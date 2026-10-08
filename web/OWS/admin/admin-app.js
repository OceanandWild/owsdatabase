// OWS Admin Panel — Client Logic
// Acceso restringido al equipo de administración (3 pasos). Gestiona Noticias,
// Eventos, Proyectos y Usuarios directamente en owsdatabase.onrender.com.

// Mismo API_BASE que el dashboard web/OWS (Render en produccion)
function resolveAdminApiBase() {
  try {
    const params = new URLSearchParams(window.location.search || '');
    const override = (params.get('api') || localStorage.getItem('ows_api_base') || '').trim();
    if (override && /^https?:\/\//i.test(override)) return override.replace(/\/+$/, '');
  } catch (_) {}
  return 'https://owsdatabase.onrender.com';
}

const API_BASE = resolveAdminApiBase();

const ADMIN_TOKEN_KEY = 'ows_admin_panel_token';
// Identificador funcional exigido por el backend (guards de cuenta principal).
// No es texto visible: nunca se muestra en la interfaz.
const ADMIN_NAME = 'OceanandWild';

let adminToken = localStorage.getItem(ADMIN_TOKEN_KEY) || '';
let adminSessionId = '';
let adminChallengeMsg = '';
let editingNewsId = null;
let editingEventId = null;
let editingProjectId = null;
let eventImageFile = null;
let projIconFile = null;
let projBannerFile = null;
let projectsCache = [];
// Cuántos proyectos solo-admin hay (solo para el aviso de la lista pública).
let hiddenAdminOnlyCount = 0;
// ══ Gestión (proyectos solo-admin) ══
// manageProjectsCache: copia completa (admin_only + públicos) con
// ?include_hidden=1. Por defecto se muestran SOLO los admin_only;
// con el filtro se agregan los públicos en modo solo-lectura.
let manageProjectsCache = [];
let manageShowPublic = false;
let editingManageId = null;
let manageIconFile = null;
let manageBannerFile = null;

// Cloudinary unsigned preset para subir iconos/banners de proyectos directo
// desde el navegador (sin pasar por el servidor). La carpeta y los formatos
// permitidos estan fijados en el preset.
const CLOUDINARY_CLOUD = 'dwoxdneqa';
const CLOUDINARY_UPLOAD_PRESET = 'ows-launch-projects-preset';

// =======================================================
// TRUSTED DEVICE — no pedir credenciales por 30 dias
// =======================================================

const TRUST_TOKEN_KEY = 'ows_admin_trust_token';
const TRUST_DEVICE_KEY = 'ows_admin_device_id';

function getDeviceId() {
  let id = localStorage.getItem(TRUST_DEVICE_KEY);
  if (!id) {
    const buf = new Uint8Array(16);
    crypto.getRandomValues(buf);
    id = Array.from(buf, (b) => b.toString(16).padStart(2, '0')).join('');
    localStorage.setItem(TRUST_DEVICE_KEY, id);
  }
  return id;
}

function getTrustToken() {
  return localStorage.getItem(TRUST_TOKEN_KEY) || '';
}

async function tryLoginWithDevice() {
  const trustToken = getTrustToken();
  if (!trustToken) return false;
  try {
    const res = await fetch(API_BASE + '/ows-admin-panel/login-with-device', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_id: getDeviceId(), trust_token: trustToken })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.token) {
      // Token invalido/vencido: limpiar para no reintentar en vano
      localStorage.removeItem(TRUST_TOKEN_KEY);
      return false;
    }
    adminToken = data.token;
    localStorage.setItem(ADMIN_TOKEN_KEY, adminToken);
    return true;
  } catch (_) {
    return false;
  }
}

async function registerTrustedDevice() {
  try {
    const res = await fetch(API_BASE + '/ows-admin-panel/trust-device', {
      method: 'POST',
      headers: adminHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ device_id: getDeviceId() })
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok && data.trust_token) {
      localStorage.setItem(TRUST_TOKEN_KEY, data.trust_token);
      showToast(`🤝 Dispositivo de confianza registrado: no te pediremos credenciales por ${data.expires_in_days || 30} días.`);
    }
  } catch (_) { /* no bloquea el login */ }
}

async function revokeTrustedDevice() {
  const trustToken = getTrustToken();
  if (!trustToken) { showToast('Este navegador no tenía dispositivo de confianza.'); return; }
  try {
    await fetch(API_BASE + '/ows-admin-panel/revoke-trust', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_id: getDeviceId(), trust_token: trustToken })
    });
  } catch (_) {}
  localStorage.removeItem(TRUST_TOKEN_KEY);
  showToast('🔓 Dispositivo olvidado. La próxima vez se pedirá login completo de 3 pasos.');
}

// =======================================================
// STARS
// =======================================================

(function initAdminStars() {
  const canvas = document.getElementById('admin-stars');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  let W = canvas.width = window.innerWidth;
  let H = canvas.height = window.innerHeight;
  const stars = Array.from({ length: 160 }, () => ({
    x: Math.random() * W, y: Math.random() * H,
    r: Math.random() * 1.3 + 0.3,
    base: Math.random() * 0.5 + 0.3,
    spd: Math.random() * 0.01 + 0.003,
    t: Math.random() * Math.PI * 2
  }));
  function frame() {
    ctx.clearRect(0, 0, W, H);
    stars.forEach(s => {
      s.t += s.spd;
      ctx.beginPath();
      ctx.arc(s.x, s.y, s.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(245, 240, 255, ${s.base + Math.sin(s.t) * 0.3})`;
      ctx.fill();
    });
    requestAnimationFrame(frame);
  }
  frame();
  window.addEventListener('resize', () => {
    W = canvas.width = window.innerWidth;
    H = canvas.height = window.innerHeight;
  });
})();

// =======================================================
// UTILITIES
// =======================================================

function escapeHtml(text) {
  return String(text || '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// ── Porcentajes: 2 decimales como máximo ──
// round2() para calcular/guardar (nunca más de 2 decimales) y fmtPct() para
// mostrar (2,5% y no 2.50% — sin ceros de relleno).
function round2(v) {
  const n = Number(v);
  if (!Number.isFinite(n)) return 0;
  return Math.round(n * 100) / 100;
}
function fmtPct(v, decimals) {
  const n = Number(v);
  if (!Number.isFinite(n)) return '0%';
  if (decimals !== undefined) {
    return `${n.toFixed(decimals)}%`;
  }
  // Sin decimales si es entero; con hasta 2 si hay decimales.
  return `${Number(n.toFixed(2))}%`;
}
function fmtDelta(v) {
  const n = round2(v);
  if (n > 0) return `+${fmtPct(n)}`;
  return fmtPct(n);
}

// ═══════════════════════════════════════════════
// CAMPOS DECIMALES
// Los <input type="number"> estorban para escribir decimales: el navegador
// impone su propio separador, los spinners saltan de 1 en 1 y el campo se
// reformatea mientras escribís. En su lugar usamos type="text" con
// inputmode="decimal" y normalizamos a mano: se acepta "2.5" o "2,5", se
// completan los ceros ("." → "0."), se corta a 2 decimales y se acota al
// máximo permitido sin frenar el cursor.
// ═══════════════════════════════════════════════

// Deja el texto listo para mostrar: solo dígitos + un punto, 2 decimales,
// y nunca un número que ya exceda el máximo (105 con tope 100 se recorta a
// 100 mientras se teclea, en vez de dejar el valor inválido en el campo).
function normalizeDecText(raw, decimals = 2, max = null) {
  // El guion se descarta ANTES de convertir la coma: si no, "-3" se
  // convertiría en "0.3". Un % negativo no existe, así que se ignora el
  // signo y queda el número tal cual ("-3" → "3").
  let s = String(raw ?? '').replace(/[-\s]/g, '').replace(/[^\d.,]/g, '').replace(/,/g, '.');
  const dot = s.indexOf('.');
  if (dot >= 0) s = s.slice(0, dot + 1) + s.slice(dot + 1).replace(/\./g, '');
  if (s === '') return '0';
  if (s === '.') s = '0.';
  if (s.charAt(0) === '.') s = '0' + s;
  if (decimals === 0) s = s.split('.')[0];
  else if (s.indexOf('.') >= 0) {
    const [i, d = ''] = s.split('.');
    s = i + '.' + d.slice(0, decimals);
  }
  // Zeros a la izquierda que no aportan: "007" → "7", "03" → "3". El "0"
  // de "0.5" se conserva porque va justo antes del punto. El lookahead
  // exige un dígito detrás, así que un "0" solo nunca se recorta.
  s = s.replace(/^0+(?=[0-9])/, '');
  // Acota el texto (no sólo el valor): evita ver "105" cuando el tope es 100.
  if (max != null && Number.isFinite(Number(s)) && Number(s) > max) {
    s = String(round2(max));
  }
  return s;
}

// Texto normalizado + valor acotado a [0, max]. max === null = sin tope.
function readDecField(raw, max) {
  const hasMax = max != null && Number.isFinite(Number(max));
  const text = normalizeDecText(raw, 2, hasMax ? Number(max) : null);
  let n = Number(text);
  if (!Number.isFinite(n)) n = 0;
  if (hasMax) n = Math.min(Number(max), Math.max(0, n));
  return { text, value: round2(n) };
}

// Al salir del campo se muestra limpio: sin "0." ni ceros de relleno.
function bindDecBlur(id, max) {
  const el = document.getElementById(id);
  if (!el || el.dataset.decBound === '1') return;
  el.dataset.decBound = '1';
  el.addEventListener('blur', () => {
    el.value = String(readDecField(el.value, max).value);
  });
  el.addEventListener('keydown', (e) => { if (e.key === 'Enter') el.blur(); });
}

let _toastTimer = null;
function showToast(msg) {
  const el = document.getElementById('toast');
  if (!el) return;
  el.textContent = msg;
  el.classList.remove('hidden');
  if (_toastTimer) clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => el.classList.add('hidden'), 4000);
}

function showAlert(id, msg, type) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = msg;
  el.className = `alert-box ${type}`;
  el.classList.remove('hidden');
}

function hideAlert(id) {
  const el = document.getElementById(id);
  if (el) el.classList.add('hidden');
}

// Puerta del panel: se exige una sesión de administración válida guardada
// del dashboard (ocean_pay_user) antes de mostrar el panel.
function isAdminPanelSession() {
  try {
    const raw = localStorage.getItem('ocean_pay_user');
    if (!raw) return false;
    const u = JSON.parse(raw);
    return String(u?.username || '').trim().toLowerCase() === 'oceanandwild';
  } catch (_) {
    return false;
  }
}

function adminHeaders(extra = {}) {
  return {
    'x-ows-admin-token': adminToken,
    'x-ows-admin-name': ADMIN_NAME,
    ...extra
  };
}

// ── Sesión persistente: el JWT dura 2h, pero NO se pide login en cada
// recarga. Mientras el token siga vigente se entra directo; si venció,
// se restaura en silencio con el dispositivo de confianza (30 días).
// Solo se muestra el login de 3 pasos cuando no hay nada válido.
function isAdminJwtValid(token) {
  if (!token || typeof token !== 'string') return false;
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return false;
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    if (!payload.exp) return true; // sin exp: asumir válido, el backend decide
    // Margen de 60s para no usar un token a punto de vencer
    return (payload.exp * 1000) > (Date.now() + 60000);
  } catch (_) {
    return false;
  }
}

function showLoginView() {
  document.getElementById('admin-login').classList.remove('hidden');
  document.getElementById('admin-panel').classList.add('hidden');
}

// ── Renovación silenciosa de sesión ──
// El JWT dura 2h. Cuando se vencía a mitad de sesión, requireAuth() saltaba
// directo al login de 3 pasos y tiraba el panel abajo, aunque el navegador
// tuviera el dispositivo de confianza (30 días). Ahora, antes de pedir
// credenciales, se intenta renovar en silencio; sólo si no hay confianza
// disponible se muestra el login.
let sessionRefreshPromise = null;

function refreshSessionSilently() {
  if (sessionRefreshPromise) return sessionRefreshPromise;
  if (!getTrustToken()) return Promise.resolve(false);
  sessionRefreshPromise = tryLoginWithDevice()
    .catch(() => false)
    .finally(() => { sessionRefreshPromise = null; });
  return sessionRefreshPromise;
}

async function requireAuth() {
  if (adminToken && isAdminJwtValid(adminToken)) return true;
  // El token venció pero el navegador es de confianza: se renueva solo y la
  // sección sigue funcionando. Antes esto saltaba al login de 3 pasos.
  if (await refreshSessionSilently()) {
    showToast('♻️ Sesión renovada automáticamente (dispositivo de confianza).');
    return true;
  }
  showLoginView();
  return false;
}

// fetch con headers de admin: si el server responde 401 (token vencido,
// clave rotada, etc.) se renueva la sesión en silencio y se reintenta una
// sola vez, en vez de dejar un error o pedir el login.
async function adminFetch(url, options = {}) {
  const opts = { ...options, headers: adminHeaders(options.headers || {}) };
  let res = await fetch(url, opts);
  if (res.status === 401 && await refreshSessionSilently()) {
    res = await fetch(url, { ...options, headers: adminHeaders(options.headers || {}) });
  }
  return res;
}

// Renovación proactiva: el JWT dura 2h y el panel puede quedar abierto
// mucho rato. En vez de esperar a que alguna sección tropiece con un 401,
// se programa un aviso unos minutos antes de que el token muera para
// renovarlo en silencio. Así ninguna pestaña ve el error ni el login.
let sessionRenewTimer = null;

function adminTokenExpiresAt() {
  try {
    const parts = String(adminToken || '').split('.');
    if (parts.length !== 3) return null;
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    return payload.exp ? Number(payload.exp) * 1000 : null;
  } catch (_) {
    return null;
  }
}

function scheduleSessionRenew() {
  if (sessionRenewTimer) { clearTimeout(sessionRenewTimer); sessionRenewTimer = null; }
  const exp = adminTokenExpiresAt();
  if (!exp) return;
  const delay = Math.max(5000, exp - Date.now() - (2 * 60 * 1000)); // 2 min antes
  sessionRenewTimer = setTimeout(async () => {
    sessionRenewTimer = null;
    if (await refreshSessionSilently()) {
      scheduleSessionRenew(); // el token nuevo dura otras 2h: se reprograma
    }
  }, delay);
}

// =======================================================
// LOGIN (3 pasos estrictos)
// =======================================================

async function adminLogin(e) {
  if (e && e.preventDefault) e.preventDefault();
  hideAlert('admin-login-alert');
  const username = document.getElementById('adm-user').value.trim();
  const password = document.getElementById('adm-pass').value;
  const btn = document.getElementById('btn-admin-login');
  btn.disabled = true;
  btn.textContent = 'Verificando…';
  try {
    const res = await fetch(API_BASE + '/ows-admin-panel/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    adminSessionId = data.sessionId;
    document.getElementById('login-step1').classList.add('hidden');
    document.getElementById('login-step2').classList.remove('hidden');
    showToast('Credenciales válidas. Paso 2: secreto administrativo.');
  } catch (err) {
    showAlert('admin-login-alert', err.message || 'Error de conexión.', 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = '🔐 Iniciar sesión';
  }
}

async function adminVerifyStep1(e) {
  if (e && e.preventDefault) e.preventDefault();
  hideAlert('admin-login-alert');
  const adminSecret = document.getElementById('adm-secret').value;
  try {
    const res = await fetch(API_BASE + '/ows-admin-panel/verify-step1', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sessionId: adminSessionId, adminSecret })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    adminChallengeMsg = data.challengeMessage || 'Completa el desafío de seguridad.';
    document.getElementById('adm-challenge-label').textContent = adminChallengeMsg;
    document.getElementById('login-step2').classList.add('hidden');
    document.getElementById('login-step3').classList.remove('hidden');
    showToast('Secreto verificado. Paso 3: desafío.');
  } catch (err) {
    showAlert('admin-login-alert', err.message || 'Error de conexión.', 'error');
  }
}

async function adminVerifyStep2(e) {
  if (e && e.preventDefault) e.preventDefault();
  hideAlert('admin-login-alert');
  const answer = document.getElementById('adm-answer').value;
  try {
    const res = await fetch(API_BASE + '/ows-admin-panel/verify-step2', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sessionId: adminSessionId, answer })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.token) throw new Error(data.error || `Error (${res.status})`);
    adminToken = data.token;
    localStorage.setItem(ADMIN_TOKEN_KEY, adminToken);
    showToast('¡Acceso autorizado! Bienvenido al panel ✔');
    // Recordar este dispositivo 30 dias (falla silenciosamente si no se logra)
    await registerTrustedDevice();
    openPanel();
  } catch (err) {
    showAlert('admin-login-alert', err.message || 'Error de conexión.', 'error');
  }
}

async function adminLogout() {
  // Salir revoca tambien la confianza del dispositivo: la proxima entrada
  // pedira el login completo de 3 pasos (los cierres normales de pestaña
  // NO revocan nada: al volver, la sesion se restaura sola).
  await revokeTrustedDevice();
  adminToken = '';
  if (sessionRenewTimer) { clearTimeout(sessionRenewTimer); sessionRenewTimer = null; }
  localStorage.removeItem(ADMIN_TOKEN_KEY);
  showToast('Sesión cerrada. Volviendo al ecosistema…');
  setTimeout(() => { window.location.href = '../index.html'; }, 900);
}

function openPanel() {
  document.getElementById('admin-login').classList.add('hidden');
  document.getElementById('admin-panel').classList.remove('hidden');
  const nameEl = document.getElementById('sidebar-admin-name');
  if (nameEl) nameEl.textContent = getCurrentAdminName();
  // El panel puede quedar abierto horas: se renueva la sesión antes de que
  // el token venza, para que ninguna sección pida credenciales de nuevo.
  scheduleSessionRenew();
  loadAdminNews();
  loadAdminEvents();
  loadAdminProjects();
  loadAdminManage();
  loadProjectDevelopment();
  loadCelebrations();
  loadAdminUsers();
  loadDevlogs();
  loadProjectActivity();
  loadWorkSessions();
  loadWsDaily();
  loadIncidents();
  loadReports();
}

// =======================================================
// TABS
// =======================================================

// En móvil las pestañas son tiras con scroll horizontal: al cambiar de
// sección (o de sub-sección) la pastilla activa se trae a la vista si quedó
// fuera de pantalla. Solo se mueve la tira, nunca la página.
function revealAdminTab(el) {
  if (!el) return;
  const strip = el.parentElement;
  if (!strip || strip.scrollWidth <= strip.clientWidth + 1) return;
  const r = el.getBoundingClientRect();
  const s = strip.getBoundingClientRect();
  if (r.left < s.left + 4) strip.scrollLeft += r.left - s.left - 8;
  else if (r.right > s.right - 4) strip.scrollLeft += r.right - s.right + 8;
}

function switchAdminTab(tab) {
  try { closeFormModal(); } catch (_) {}
  ['news', 'events', 'projects', 'manage', 'incidents', 'reports', 'users'].forEach((t) => {
    const pane = document.getElementById(`tab-${t}`);
    const btn = document.getElementById(`ptab-${t}`);
    if (pane) pane.classList.toggle('hidden', t !== tab);
    if (btn) btn.classList.toggle('active', t === tab);
  });
  revealAdminTab(document.getElementById(`ptab-${tab}`));
  // Recargar la lista correspondiente al entrar a cada pestaña para que
  // Proyectos y Gestión siempre estén sincronizados (admin_only, etc.)
  if (tab === 'manage') { loadAdminManage(); loadDevlogs(); loadProjectActivity(); loadWorkSessions(); loadWsDaily(); loadCelebrations(); }
  if (tab === 'projects') { loadAdminProjects(); loadProjectDevelopment(); }
  if (tab === 'events') {
    loadAdminEvents();
    if (adminSubState.events === 'popups') loadEventPopups();
    else if (adminSubState.events === 'presets') loadPopupPresets();
  }
  if (tab === 'users') loadAdminUsers();
  // Incidentes: la status page refleja el estado actual, así que se recarga
  // al entrar (por si otro admin acaba de abrir o cerrar algo).
  if (tab === 'incidents') loadIncidents();
  // Informes: igual que incidentes, se recarga al entrar.
  if (tab === 'reports') loadReports();
  // Barra de sub-secciones: solo visible si la sección tiene sub-secciones
  renderSubTabs(tab);
}

// =======================================================
// SUB-SECCIONES — barra secundaria bajo los tabs
// Solo aparece cuando la sección activa tiene sub-secciones. La primera
// sub-sección es siempre la PRINCIPAL: copia literalmente la misma sección
// (mismo icono + nombre del tab) para poder volver a ella en todo momento.
// Para agregar sub-secciones a otra sección en el futuro, basta con añadir
// una entrada en ADMIN_EXTRA_SUBS y sus paneles `.admin-subpane[data-sub]`
// dentro del `tab-<seccion>` correspondiente.
// =======================================================

const ADMIN_EXTRA_SUBS = {
  news: [
    { id: 'quick', label: '⚡ Rápidas' }
  ],
  events: [
    { id: 'popups', label: '💬 Modales' },
    { id: 'presets', label: '🎨 Presets' }
  ],
  manage: [
    { id: 'devlog', label: '📝 Devlog' },
    { id: 'activity', label: '📅 14 días' },
    { id: 'analytics', label: '📊 Analytics' },
    { id: 'celebs', label: '🎉 Celebraciones' },
    { id: 'welcome', label: '🌱 Bienvenidas' }
  ],
  incidents: [
    { id: 'live', label: '🔴 En curso' },
    { id: 'log', label: '📜 Registro' }
  ],
  reports: [
    { id: 'live', label: '📋 Activos' },
    { id: 'log', label: '📜 Historial' }
  ]
};

// Recuerda la sub-sección activa de cada sección (por defecto: 'main')
const adminSubState = {};

function getAdminSubs(tab) {
  const extras = ADMIN_EXTRA_SUBS[tab] || [];
  if (!extras.length) return [];
  // La principal copia literalmente la misma sección (texto del tab)
  const mainBtn = document.getElementById(`ptab-${tab}`);
  const mainLabel = mainBtn ? mainBtn.textContent.trim() : tab;
  return [{ id: 'main', label: mainLabel }, ...extras];
}

function renderSubTabs(tab) {
  const bar = document.getElementById('sub-tabs');
  const box = document.getElementById('sub-tabs-buttons');
  if (!bar || !box) return;
  const subs = getAdminSubs(tab);
  if (!subs.length) {
    bar.classList.add('hidden');
    box.innerHTML = '';
    return;
  }
  if (!adminSubState[tab]) adminSubState[tab] = 'main';
  const active = adminSubState[tab];
  box.innerHTML = subs.map((s) =>
    `<button class="subtab${s.id === active ? ' active' : ''}" data-sub="${escapeHtml(s.id)}" data-adm-ev="click" data-adm="switchAdminSub" data-adm-a0="s:${escapeHtml(tab)}" data-adm-a1="s:${escapeHtml(s.id)}">${escapeHtml(s.label)}</button>`
  ).join('');
  bar.classList.remove('hidden');
  applyAdminSub(tab, active);
  revealAdminTab(box.querySelector('.subtab.active'));
}

function switchAdminSub(tab, sub) {
  adminSubState[tab] = sub;
  document.querySelectorAll('#sub-tabs-buttons .subtab').forEach((b) =>
    b.classList.toggle('active', b.dataset.sub === sub)
  );
  revealAdminTab(document.querySelector('#sub-tabs-buttons .subtab.active'));
  applyAdminSub(tab, sub);
  // La bitácora de 14 días necesita su propio refresco: al entrar se
  // regenera la ventana de días para que no muestre datos viejos.
  if (tab === 'manage' && sub === 'activity') loadProjectActivity();
  // Analytics se arma con lo que ya hay cargado (sesiones): se repinta al entrar.
  // El histórico de subidas necesita además el historial de %: si aún no se
  // pidió, se trae en segundo plano y se repinta el apartado de esfuerzo.
  if (tab === 'manage' && sub === 'analytics') {
    loadWorkSessions(); renderWsAnalytics();
    if (!paxHistoryCache.length) {
      loadProjectActivity(false).then(() => { try { renderAnalyticsEffort(); } catch (_) {} });
    } else { try { renderAnalyticsEffort(); } catch (_) {} }
  }
  // El Devlog y sus sesiones se piden al abrir la sub-sección: son lo que
  // más cambia durante el día.
  if (tab === 'manage' && sub === 'devlog') { loadDevlogs(); loadWorkSessions(); loadWsDaily(); }
  // Celebraciones y Bienvenidas: muro interno con registro en backend.
  if (tab === 'manage' && (sub === 'celebs' || sub === 'welcome')) loadCelebrations();
  // Los modales y presets se piden al abrir su sub-sección: es lo que
  // más cambia cuando se envía o re-muestra un anuncio.
  if (tab === 'events' && sub === 'popups') loadEventPopups();
  if (tab === 'events' && sub === 'presets') loadPopupPresets();
  // Los incidentes abiertos y el registro se piden al abrir la sub-sección:
  // son los que cambian cuando se reporta o se finaliza algo.
  if (tab === 'incidents' && (sub === 'live' || sub === 'log')) loadIncidents();
  // Lo mismo para informes: activos e historial se piden al abrir.
  if (tab === 'reports' && (sub === 'live' || sub === 'log')) loadReports();
  // Las noticias rápidas se piden al abrir su sub-sección: es donde más
  // seguido se publica (texto corto, al instante).
  if (tab === 'news' && sub === 'quick') loadQuickNews();
  // Salto instantáneo: el smooth + sticky con blur dejaba una banda negra
  // repintada a mitad de Incidentes en Chrome.
  window.scrollTo({ top: 0, behavior: 'auto' });
}

function applyAdminSub(tab, sub) {
  const pane = document.getElementById(`tab-${tab}`);
  if (!pane) return;
  pane.querySelectorAll('.admin-subpane').forEach((p) =>
    p.classList.toggle('hidden', p.dataset.sub !== sub)
  );
}

// =======================================================
// GESTIÓN — proyectos que SOLO los admins ven (admin_only = true)
// + filtro para ver también los disponibles de Proyectos (solo lectura,
// con etiqueta, sin edición desde aquí).
// Reutiliza /ows-launch-projects?include_hidden=1 y el flag admin_only.
// =======================================================

function isAdminOnlyProject(p) {
  return !!(p && (p.admin_only === true || p.adminOnly === true));
}

function readManagePlatformChecks() {
  return PLATFORM_KEYS.filter((k) => {
    const el = document.getElementById(`mplat-${k}`);
    return el && el.checked;
  });
}

function writeManagePlatformChecks(platforms) {
  const list = Array.isArray(platforms) ? platforms.map((p) => String(p).toLowerCase()) : [];
  PLATFORM_KEYS.forEach((k) => {
    const el = document.getElementById(`mplat-${k}`);
    if (el) el.checked = list.includes(k);
  });
}

function clearManageImageFiles() {
  manageIconFile = null;
  manageBannerFile = null;
  ['mproj-icon-file', 'mproj-banner-file'].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  ['mproj-icon-preview', 'mproj-banner-preview'].forEach((id) => {
    const el = document.getElementById(id);
    if (el) { el.innerHTML = ''; el.classList.add('hidden'); }
  });
}

function toggleManageShowPublic() {
  const el = document.getElementById('manage-show-public');
  manageShowPublic = !!(el && el.checked);
  renderManageList();
  renderDevList();
}

function manageProjectIconHtml(p) {
  return `<div class="admin-item-thumb project-icon-wrap" style="width:50px;height:50px">🔒${p.icon_url ? `<img src="${escapeHtml(p.icon_url)}" alt="" data-adm-err="rm" />` : ''}</div>`;
}

function publicProjectIconHtml(p) {
  return `<div class="admin-item-thumb project-icon-wrap" style="width:50px;height:50px">📁${p.icon_url ? `<img src="${escapeHtml(p.icon_url)}" alt="" data-adm-err="rm" />` : ''}</div>`;
}

async function loadAdminManage() {
  const list = document.getElementById('manage-list');
  const badge = document.getElementById('manage-session-badge');
  if (badge) {
    badge.textContent = adminToken && isAdminJwtValid(adminToken)
      ? '🔒 Sesión admin activa'
      : '🔒 Solo admins';
    badge.className = 'status-pill ' + (adminToken && isAdminJwtValid(adminToken) ? 'status-on' : 'status-off');
  }
  if (!list) return;
  try {
    const res = await fetch(API_BASE + '/ows-launch-projects?include_hidden=1');
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    manageProjectsCache = data.projects || [];
    const box = document.getElementById('manage-show-public');
    if (box) box.checked = manageShowPublic;
    renderManageList();
    // El catálogo cambió: el dropdown de proyecto de Eventos se rearma.
    populateEventProjectOptions();
  } catch (err) {
    list.innerHTML = `<p class="loading-note">⚠️ ${escapeHtml(err.message)}</p>`;
  }
}

// Día de creación del proyecto como DD/MM/AAAA, desde el ISO (parte de
// fecha, sin corrimiento de huso horario).
function fmtProjectCreatedDay(iso) {
  const m = String(iso || '').slice(0, 10).match(/^(\d{4})-(\d{2})-(\d{2})$/);
  return m ? `${m[3]}/${m[2]}/${m[1]}` : '';
}
function renderManageList() {
  const list = document.getElementById('manage-list');
  if (!list) return;  const adminOnly = manageProjectsCache.filter(isAdminOnlyProject);
  const pub = manageProjectsCache.filter((p) => !isAdminOnlyProject(p));

  const countBadge = document.getElementById('manage-count-badge');
  if (countBadge) {
    countBadge.textContent = `🔒 ${adminOnly.length} solo-admin · 📁 ${pub.length} disponibles`;
  }

  let html = '';

  if (!adminOnly.length) {
    html += '<p class="loading-note">🔒 Todavía no hay proyectos solo-admin. Creá el primero con el formulario ←</p>';
  } else {
    html += adminOnly.map((p) => {
      const meta = launchStatusMeta(p.status);
      const latestVer = (p.latest_release && p.latest_release.version) || (p.latestRelease && p.latestRelease.version) || p.itch_version || p.itchVersion || '';
      const chips = [
        '<span class="status-pill status-admin-only">🔒 Solo-admin</span>',
        `<span class="status-pill ${meta.cls}">${meta.label}</span>`,
        (p.has_release || p.hasRelease || latestVer) ? `<span class="status-pill status-on">📦 v${escapeHtml(latestVer || '?')}</span>` : '<span class="status-pill">📦 sin versión</span>',
        managePermanenceChip(p),
        p.is_active ? '' : '<span class="status-pill status-off">Oculto</span>'
      ].filter(Boolean).join(' ');
      const platforms = (p.platforms || []).map((x) => escapeHtml(x)).join(', ') || '—';
      const dates = [p.expected_date, p.confirmed_date].filter(Boolean).map((d) => String(d).slice(0, 10)).join(' / ');
      const createdDay = fmtProjectCreatedDay(p.created_at);
      const feedback = String(p.status_feedback || p.statusFeedback || '').trim();
      const desc = String(p.description || '').trim();
      return `
      <div class="admin-item manage-admin-item">
        ${manageProjectIconHtml(p)}
        <div class="admin-item-info">
          <span class="admin-item-title">${escapeHtml(p.name)} ${chips}</span>
          <span class="admin-item-sub">${escapeHtml(p.slug)} · ${platforms}${p.genre ? ' · ' + escapeHtml(p.genre) : ''}${dates ? ' · ' + dates : ''}${createdDay ? ` · 🗓️ creado ${createdDay}` : ''}</span>
          ${desc
            ? `<span class="admin-item-desc" title="${escapeHtml(desc)}">📝 ${escapeHtml(desc)}</span>`
            : '<span class="admin-item-desc is-empty">Sin info del proyecto: editá y contá de qué trata.</span>'}
          ${feedback ? `<span class="manage-feedback">💬 <b>${escapeHtml(meta.label)}:</b> ${escapeHtml(feedback)}</span>` : ''}
        </div>
        <div class="admin-item-actions">
          <button class="btn btn-ghost btn-mini" title="Versiones descargables del Hub" data-adm-ev="click" data-adm="openReleasesModal" data-adm-a0="r:${p.id}">📦</button>
          <button class="btn btn-ghost btn-mini" data-adm-ev="click" data-adm="editManageProject" data-adm-a0="r:${p.id}">✏️</button>
          <button class="btn btn-ghost btn-mini" data-adm-ev="click" data-adm="toggleManageProject" data-adm-a0="r:${p.id}" data-adm-a1="r:${p.is_active ? 'false' : 'true'}">${p.is_active ? '👁️' : '🚫'}</button>
          <button class="btn btn-danger btn-mini" data-adm-ev="click" data-adm="deleteManageProject" data-adm-a0="r:${p.id}">🗑️</button>
        </div>
      </div>`;
    }).join('');
  }

  // Filtro: mostrar también los disponibles (vienen de Proyectos).
  // Se indican con etiqueta y SIN edición desde Gestión.
  if (manageShowPublic) {
    html += '<div class="manage-section-divider">📁 Disponibles (vienen de Proyectos · solo lectura)</div>';
    if (!pub.length) {
      html += '<p class="loading-note">No hay proyectos disponibles en Proyectos por ahora.</p>';
    } else {
      html += pub.map((p) => {
        const meta = launchStatusMeta(p.status);
        const platforms = (p.platforms || []).map((x) => escapeHtml(x)).join(', ') || '—';
        const createdDay = fmtProjectCreatedDay(p.created_at);
        const desc = String(p.description || '').trim();
        return `
        <div class="admin-item manage-readonly-item">
          ${publicProjectIconHtml(p)}
          <div class="admin-item-info">
            <span class="admin-item-title">${escapeHtml(p.name)}
              <span class="status-pill status-from-projects">📁 Viene de Proyectos</span>
              <span class="status-pill ${meta.cls}">${meta.label}</span>
            </span>
            <span class="admin-item-sub">${escapeHtml(p.slug)} · ${platforms}${createdDay ? ` · 🗓️ creado ${createdDay}` : ''} · 🔒 Solo lectura aquí — se edita en Proyectos</span>
            ${desc
              ? `<span class="admin-item-desc" title="${escapeHtml(desc)}">📝 ${escapeHtml(desc)}</span>`
              : '<span class="admin-item-desc is-empty">Sin info del proyecto.</span>'}
          </div>
          <div class="admin-item-actions">
            <button class="btn btn-ghost btn-mini" title="Ir a editar en Proyectos" data-adm-ev="click" data-adm="switchAdminTab" data-adm-a0="s:projects">➡️ Proyectos</button>
          </div>
        </div>`;
      }).join('');
    }
  }

  list.innerHTML = html;
}

async function saveManageProject(e) {
  if (e && e.preventDefault) e.preventDefault();
  const slug = document.getElementById('mproj-slug').value.trim().toLowerCase();
  const name = document.getElementById('mproj-name').value.trim();
  if (!slug || !name) return showToast('⚠️ Slug y nombre son obligatorios');
  const statusFeedback = document.getElementById('mproj-feedback').value.trim();
  if (!statusFeedback) {
    showAlert('manage-alert', 'El feedback del estado es obligatorio: explicá por qué elegiste ese estado.', 'error');
    showToast('⚠️ Falta el feedback del estado');
    document.getElementById('mproj-feedback').focus();
    return;
  }
  const status = document.getElementById('mproj-status').value;
  let statusPermanent = null;
  if (manageNeedsPermanence(status)) {
    statusPermanent = getManagePermanence();
    if (statusPermanent === null) {
      showAlert('manage-alert', 'Indicá si el estado es permanente o temporal.', 'error');
      showToast('⚠️ Falta elegir permanente o temporal');
      document.getElementById('mproj-permanence-wrap').scrollIntoView({ behavior: 'smooth', block: 'center' });
      return;
    }
  }

  const btn = document.getElementById('btn-save-manage');
  const fail = (msg) => {
    showAlert('manage-alert', msg, 'error');
    showToast('⚠️ ' + msg);
  };
  btn.disabled = true;

  try {
    if (manageIconFile) {
      btn.textContent = '⏳ Subiendo icono…';
      document.getElementById('mproj-icon').value = await uploadProjectImage(manageIconFile, 'icono');
      manageIconFile = null;
      document.getElementById('mproj-icon-file').value = '';
    }
    if (manageBannerFile) {
      btn.textContent = '⏳ Subiendo banner…';
      document.getElementById('mproj-banner').value = await uploadProjectImage(manageBannerFile, 'banner');
      manageBannerFile = null;
      document.getElementById('mproj-banner-file').value = '';
    }

    const payload = {
      slug,
      name,
      description: document.getElementById('mproj-desc').value.trim(),
      status,
      genre: document.getElementById('mproj-genre').value.trim(),
      platforms: readManagePlatformChecks(),
      icon_url: document.getElementById('mproj-icon').value.trim(),
      link_url: document.getElementById('mproj-link').value.trim(),
      expected_date: document.getElementById('mproj-expected').value || null,
      confirmed_date: document.getElementById('mproj-confirmed').value || null,
      status_feedback: statusFeedback,
      status_permanent: statusPermanent,
      admin_only: true
    };
    // Fecha real de creación: al crear se manda si se puso; al editar solo
    // si cambió el día (así no se reescribe la hora original sin querer).
    const createdVal = (document.getElementById('mproj-created') || {}).value || '';
    if (createdVal) {
      const orig = editingManageId
        ? manageProjectsCache.find((x) => Number(x.id) === Number(editingManageId))
        : null;
      const origDay = orig && orig.created_at ? String(orig.created_at).slice(0, 10) : '';
      if (!editingManageId || createdVal !== origDay) payload.created_at = createdVal;
    }
    const bannerUrl = document.getElementById('mproj-banner').value.trim();
    if (bannerUrl) payload.metadata = { banner_url: bannerUrl };

    btn.textContent = '💾 Guardando…';
    let res;
    if (editingManageId) {
      res = await fetch(API_BASE + `/ows-launch-projects/${editingManageId}`, {
        method: 'PATCH',
        headers: adminHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(payload)
      });
    } else {
      res = await fetch(API_BASE + '/ows-launch-projects', {
        method: 'POST',
        headers: adminHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(payload)
      });
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(res.status === 409
        ? `Ya existe un proyecto con el slug "${slug}".`
        : (data.error || `Error (${res.status})`));
    }
    hideAlert('manage-alert');
    showToast(editingManageId ? 'Proyecto solo-admin actualizado ✔' : '🌱 Proyecto creado + bienvenida lista en Bienvenidas');
    resetManageProjectForm();
    await loadAdminManage();
    // La bienvenida nace en el backend al crear: se refresca el muro.
    try { loadCelebrations(); } catch (_) {}
    // Refrescar Proyectos en segundo plano por si cambió el conteo
    loadAdminProjects();
  } catch (err) {
    fail(err.message || 'Error al guardar el proyecto solo-admin');
  } finally {
    btn.disabled = false;
    btn.textContent = editingManageId ? '💾 Guardar cambios' : '🔒 Crear proyecto solo-admin';
  }
}

function editManageProject(id) {
  const p = manageProjectsCache.find((x) => Number(x.id) === Number(id));
  if (!p) return showToast('⚠️ Proyecto no encontrado en caché');
  if (!isAdminOnlyProject(p)) {
    showToast('🔒 Ese proyecto vive en Proyectos: edítalo en la sección Proyectos.');
    switchAdminTab('projects');
    return;
  }
  editingManageId = id;
  hideAlert('manage-alert');
  document.getElementById('mproj-slug').value = p.slug || '';
  document.getElementById('mproj-slug').disabled = true;
  document.getElementById('mproj-name').value = p.name || '';
  document.getElementById('mproj-desc').value = p.description || '';
  document.getElementById('mproj-status').value = p.status || 'development';
  document.getElementById('mproj-genre').value = p.genre || '';
  document.getElementById('mproj-feedback').value = p.status_feedback || p.statusFeedback || '';
  updateManageFeedbackField(false);
  setManagePermanence((p.status_permanent !== undefined) ? p.status_permanent : p.statusPermanent);
  updateManagePermanenceField(false);
  writeManagePlatformChecks(p.platforms);
  document.getElementById('mproj-icon').value = p.icon_url || '';
  document.getElementById('mproj-banner').value = (p.metadata && p.metadata.banner_url) || p.banner_url || '';
  document.getElementById('mproj-link').value = p.link_url || '';
  document.getElementById('mproj-expected').value = p.expected_date ? String(p.expected_date).slice(0, 10) : '';
  document.getElementById('mproj-confirmed').value = p.confirmed_date ? String(p.confirmed_date).slice(0, 10) : '';
  document.getElementById('mproj-created').value = p.created_at ? String(p.created_at).slice(0, 10) : '';
  clearManageImageFiles();
  document.getElementById('manage-form-title').textContent = `Editando solo-admin: ${p.name}`;
  document.getElementById('btn-cancel-manage').classList.remove('hidden');
  document.getElementById('btn-save-manage').textContent = '💾 Guardar cambios';
  openFormModal('manage');
}

function resetManageProjectForm() {
  editingManageId = null;
  hideAlert('manage-alert');
  const slugEl = document.getElementById('mproj-slug');
  if (slugEl) { slugEl.disabled = false; slugEl.value = ''; }
  ['mproj-name', 'mproj-desc', 'mproj-genre', 'mproj-icon', 'mproj-banner', 'mproj-link', 'mproj-expected', 'mproj-confirmed', 'mproj-created'].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  const st = document.getElementById('mproj-status');
  if (st) st.value = 'development';
  const fb = document.getElementById('mproj-feedback');
  if (fb) fb.value = '';
  updateManageFeedbackField(false);
  setManagePermanence(null);
  updateManagePermanenceField(false);
  writeManagePlatformChecks(['windows']);
  clearManageImageFiles();
  const title = document.getElementById('manage-form-title');
  if (title) title.textContent = 'Nuevo proyecto solo-admin';
  const cancel = document.getElementById('btn-cancel-manage');
  if (cancel) cancel.classList.add('hidden');
  const save = document.getElementById('btn-save-manage');
  if (save) save.textContent = '🔒 Crear proyecto solo-admin';
  try { closeFormModal(); } catch (_) {}
}

async function toggleManageProject(id, newState) {
  const p = manageProjectsCache.find((x) => Number(x.id) === Number(id));
  if (p && !isAdminOnlyProject(p)) return showToast('🔒 Solo lectura: ese proyecto se edita en Proyectos.');
  try {
    const res = await fetch(API_BASE + `/ows-launch-projects/${id}`, {
      method: 'PATCH',
      headers: adminHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ is_active: newState })
    });
    if (!res.ok) throw new Error(`Error (${res.status})`);
    loadAdminManage();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

async function deleteManageProject(id) {
  const p = manageProjectsCache.find((x) => Number(x.id) === Number(id));
  if (p && !isAdminOnlyProject(p)) return showToast('🔒 Solo lectura: ese proyecto se elimina en Proyectos.');
  if (!confirm('¿Eliminar este proyecto solo-admin permanentemente?')) return;
  try {
    const res = await fetch(API_BASE + `/ows-launch-projects/${id}`, {
      method: 'DELETE',
      headers: adminHeaders()
    });
    if (!res.ok) throw new Error(`Error (${res.status})`);
    showToast('Proyecto solo-admin eliminado');
    if (editingManageId === id) resetManageProjectForm();
    loadAdminManage();
    loadAdminProjects();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

// =======================================================
// DESARROLLO (debajo de Gestión) — % completado por proyecto
// Muestra cuánto lleva cada proyecto de Gestión, quién lo actualizó
// (updated_by, multi-admin ready) y cuándo (hace cuánto / fecha).
// Endpoints: GET+PUT /ows-project-development (solo-admin).
// =======================================================

let devProgressCache = [];

function getCurrentAdminName() {
  // Multi-admin ready: usa la sesión actual del dashboard si existe,
  // si no el nombre admin por defecto. El backend guarda este valor
  // en updated_by en cada cambio de porcentaje.
  try {
    const raw = localStorage.getItem('ocean_pay_user');
    if (raw) {
      const u = JSON.parse(raw);
      const n = String(u?.username || '').trim();
      if (n) return n;
    }
  } catch (_) {}
  return ADMIN_NAME;
}

function formatDevAgo(iso) {
  if (!iso) return 'sin actualizar todavía';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return 'fecha desconocida';
  const diff = Date.now() - t;
  if (diff < 0) return 'justo ahora';
  const s = Math.floor(diff / 1000);
  if (s < 10) return 'hace unos segundos';
  if (s < 60) return `hace ${s} segundos`;
  const m = Math.floor(s / 60);
  if (m < 60) return m === 1 ? 'hace 1 minuto' : `hace ${m} minutos`;
  const h = Math.floor(m / 60);
  if (h < 24) return h === 1 ? 'hace 1 hora' : `hace ${h} horas`;
  const d = Math.floor(h / 24);
  if (d <= 7) return d === 1 ? 'hace 1 día' : `hace ${d} días`;
  // Más de una semana: fecha en vez de "hace X días"
  return new Date(iso).toLocaleDateString('es-ES', { day: 'numeric', month: 'short', year: 'numeric' });
}

// Refresca solo las etiquetas de tiempo cada 60s (sin pedir nada al servidor)
if (!window._devAgoTimer) {
  window._devAgoTimer = setInterval(() => {
    document.querySelectorAll('[data-dev-time]').forEach((el) => {
      el.textContent = formatDevAgo(el.getAttribute('data-dev-time'));
    });
  }, 60000);
}

// Fecha corta para el historial de avances: "28 sep" / "28 sep 2025" si es otro año.
function formatShortDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  const sameYear = d.getFullYear() === new Date().getFullYear();
  return d.toLocaleDateString('es-ES', sameYear
    ? { day: 'numeric', month: 'short' }
    : { day: 'numeric', month: 'short', year: 'numeric' });
}

function visibleDevList() {
  // Mismo criterio que Gestión: solo-admin siempre + disponibles si el filtro está activo
  return devProgressCache.filter((d) => (d.admin_only ? true : manageShowPublic));
}

async function loadProjectDevelopment(manual) {
  const list = document.getElementById('dev-list');
  if (!list) return;
  try {
    const res = await fetch(API_BASE + '/ows-project-development', { headers: adminHeaders() });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    devProgressCache = Array.isArray(data.development) ? data.development : [];
    renderDevList();
    if (manual) showToast('✔ Desarrollo actualizado');
  } catch (err) {
    list.innerHTML = `<p class="loading-note">⚠️ ${escapeHtml(err.message)}</p>`;
  }
}

function renderDevList() {
  const list = document.getElementById('dev-list');
  if (!list) return;
  const items = visibleDevList();
  if (!items.length) {
    list.innerHTML = manageShowPublic
      ? '<p class="loading-note">🚧 No hay proyectos todavía. Creá el primero en Gestión ←</p>'
      : '<p class="loading-note">🚧 No hay proyectos solo-admin todavía. Creá el primero en Gestión ←<br><small>Activá “Mostrar también proyectos disponibles” para ver el desarrollo de los públicos.</small></p>';
    return;
  }
  list.innerHTML = `
  <div class="dev-table-wrap">
    <table class="dev-table">
      <thead>
        <tr>
          <th>Proyecto</th>
          <th>Progreso</th>
          <th>Actualizado por</th>
          <th>Cuándo</th>
          <th class="dev-th-actions"><span class="hidden">Acciones</span></th>
        </tr>
      </thead>
      <tbody>
        ${items.map((d) => {
          const pid = Number(d.project_id || 0);
          const pct = round2(d.percent);
          const badge = d.admin_only
            ? '<span class="status-pill status-admin-only">🔒 Solo-admin</span>'
            : '<span class="status-pill status-from-projects">📁 De Proyectos</span>';
          const by = d.updated_by ? escapeHtml(d.updated_by) : '<i>nadie todavía</i>';
          const stamp = d.updated_at ? escapeHtml(d.updated_at) : '';
          // Euforia: nivel visual según cercanía al 100% (90/95/99/100).
          const euph = euphoriaLevel(pct);
          const done = pct >= 100 ? '<span class="dev-done">🎉 listo</span>' : '';
          const hypeBadge = euphoriaBadgeHtml(pct);
          const rowCls = euph.rowCls ? ` class="${euph.rowCls}"` : '';
          return `
          <tr${rowCls}>
            <td data-label="Proyecto">
              <div class="dev-cell-proj">
                <div class="admin-item-thumb project-icon-wrap dev-thumb">🚧${d.icon_url ? `<img src="${escapeHtml(d.icon_url)}" alt="" data-adm-err="rm" />` : ''}</div>
                <div class="dev-cell-proj-info">
                  <strong>${escapeHtml(d.name || d.slug || ('#' + pid))}</strong>
                  ${badge} ${done} ${hypeBadge}
                </div>
              </div>
            </td>
            <td data-label="Progreso">
              <div class="dev-cell-prog">
                <div class="dev-bar" title="${fmtPct(pct)} completado"><div class="dev-fill" style="width:${pct}%"></div></div>
                <span class="dev-pct">${fmtPct(pct)}</span>
              </div>
            </td>
            <td data-label="Actualizado por"><span class="dev-by">👤 ${by}</span></td>
            <td data-label="Cuándo"><span class="dev-when">🕓 <span data-dev-time="${stamp}">${escapeHtml(formatDevAgo(d.updated_at))}</span></span></td>
            <td class="dev-actions"><button class="btn btn-primary btn-mini" data-adm-ev="click" data-adm="openDevModal" data-adm-a0="r:${pid}">✏️ Modificar</button></td>
          </tr>`;
        }).join('')}
      </tbody>
    </table>
  </div>`;
  // La bitácora de 14 días se repinta junto con esta lista: el % que se ve
  // acá es el mismo que aparece en la columna de avance del día.
  renderProjectActivity();
}

// ── Modal de edición de progreso ──
// Dos modos, porque no es lo mismo "hoy trabajamos 10% más" que "el proyecto
// realmente va por 45%":
//   'day'   — AVANCE DE HOY: se indica cuánto subió HOY. El total se acumula
//             día a día hasta llegar al 100% (y ahí se elige fecha de lanzamiento).
//   'total' — AJUSTE TOTAL: se fija el % global de una sola vez.
// Ambos quedan registrados en el historial; el predeterminado es 'day'.
let devModalProjectId = null;
let devModalOriginal = 0;
let devModalMode = 'day';

function devModalProject() {
  return devProgressCache.find((x) => Number(x.project_id) === Number(devModalProjectId)) || null;
}

function openDevModal(pid) {
  const d = devProgressCache.find((x) => Number(x.project_id) === Number(pid));
  if (!d) return showToast('⚠️ Proyecto no encontrado');
  devModalProjectId = Number(pid);
  devModalOriginal = round2(d.percent);
  devModalMode = 'day';
  const pct = devModalOriginal;
  const badge = d.admin_only
    ? '<span class="status-pill status-admin-only">🔒 Solo-admin</span>'
    : '<span class="status-pill status-from-projects">📁 De Proyectos</span>';
  const lastBy = d.updated_by ? escapeHtml(d.updated_by) : 'nadie todavía';
  const lastWhen = escapeHtml(formatDevAgo(d.updated_at));
  const body = document.getElementById('dev-modal-body');
  const name = d.name || d.slug || ('#' + pid);
  body.innerHTML = `
    <div class="devmodal-head">
      <div class="admin-item-thumb project-icon-wrap devmodal-icon">🚧${d.icon_url ? `<img src="${escapeHtml(d.icon_url)}" alt="" data-adm-err="rm" />` : ''}</div>
      <div class="devmodal-head-info">
        <h3 class="devmodal-title">${escapeHtml(name)}</h3>
        <div class="devmodal-tags">${badge}<span class="devmodal-slug">${escapeHtml(d.slug || '')}</span></div>
      </div>
    </div>

    <p class="form-hint">Modificá el progreso de <b>${escapeHtml(name)}</b>.</p>

    <!-- 1 · Modo: ¿avance del día o ajuste total? -->
    <div class="devmode" role="tablist" aria-label="Tipo de cambio de progreso">
      <button type="button" class="devmode-opt is-active" data-mode="day" data-adm-ev="click" data-adm="setDevModalMode" data-adm-a0="s:day">
        <b>📅 Avance de hoy</b>
        <small>Suma lo trabajado hoy. Se acumula día a día hasta el 100%.</small>
      </button>
      <button type="button" class="devmode-opt" data-mode="total" data-adm-ev="click" data-adm="setDevModalMode" data-adm-a0="s:total">
        <b>🎯 Ajuste total</b>
        <small>Fijá el % real de golpe, sin sumarlo al avance del día.</small>
      </button>
    </div>

    <!-- 2 · Vista según el modo -->
    <div class="devmode-view" id="devmode-view-day">
      <p class="devmode-help">Hoy <b>${escapeHtml(name)}</b> subió <b id="devbump-label">+0%</b> · ${fmtPct(pct)} → <b id="devbump-final">${fmtPct(pct)}</b></p>
      <div class="devmodal-presets">
        ${[0.5, 1, 2, 5, 10, 20].map((v) => `<button type="button" class="devmodal-preset" data-adm-ev="click" data-adm="setDevDayBump" data-adm-a0="r:${v}">+${fmtPct(v)}</button>`).join('')}
        <button type="button" class="devmodal-preset" data-adm-ev="click" data-adm="setDevDayBump" data-adm-a0="r:${Math.max(0, round2(100 - pct))}" data-adm-a1="b:1" ${pct >= 100 ? 'disabled' : ''}>🚀 Completar</button>
      </div>
      <div class="devmodal-controls">
        <input type="range" id="devbump-range" min="0" max="${Math.max(0, round2(100 - pct))}" step="0.5" value="0" class="dev-range" data-adm-ev="input" data-adm="syncDevDayBump" data-adm-a0="thp:value" />
        <input type="text" inputmode="decimal" id="devbump-num" class="dev-dec" maxlength="6" placeholder="0" autocomplete="off" data-adm-ev="input" data-adm="syncDevDayBump" data-adm-a0="thp:value" />
        <span class="dev-pct-sign">% hoy</span>
      </div>
    </div>
    <div class="devmode-view hidden" id="devmode-view-total">
      <div class="devmodal-controls">
        <input type="range" id="devmodal-range" min="0" max="100" step="0.5" value="${pct}" class="dev-range" data-adm-ev="input" data-adm="syncDevModal" data-adm-a0="thp:value" />
        <input type="text" inputmode="decimal" id="devmodal-num" class="dev-dec" maxlength="6" placeholder="0" autocomplete="off" data-adm-ev="input" data-adm="syncDevModal" data-adm-a0="thp:value" />
        <span class="dev-pct-sign">% total</span>
      </div>
      <div class="devmodal-presets">
        ${[0, 25, 50, 75, 100].map((v) => `<button type="button" class="devmodal-preset" data-adm-ev="click" data-adm="syncDevModal" data-adm-a0="r:${v}">${v}%</button>`).join('')}
      </div>
    </div>

    <!-- 3 · Resumen antes → después + barra -->
    <div class="dev-confirm" id="devmodal-confirm">
      <div class="dev-confirm-head">Se va a guardar así</div>
      <div class="dev-confirm-flow">
        <div class="dev-confirm-box is-before"><small>Anterior</small><strong id="devmodal-before">${fmtPct(pct)}</strong></div>
        <span class="dev-confirm-arrow">→</span>
        <div class="dev-confirm-box is-after"><small>Final</small><strong id="devmodal-final">${fmtPct(pct)}</strong></div>
        <span class="dev-confirm-delta is-none" id="devmodal-modebadge">avance de hoy</span>
      </div>
      <div class="dev-confirm-bar"><div class="dev-confirm-fill" id="devmodal-fill" style="width:${pct}%"></div></div>
      <p class="dev-confirm-note" id="devmodal-note">Queda registrado como avance de <b>${escapeHtml(formatShortDate(new Date().toISOString()))}</b> en el historial.</p>
    </div>

    <div class="field-group" id="devmodal-note-group">
      <label for="devmodal-note-input">Nota del avance <span class="opt-tag">opcional</span></label>
      <input type="text" id="devmodal-note-input" maxlength="500" placeholder="Ej: se terminó el sistema de networking" />
    </div>

    <div class="devmode-hype hidden" id="devmodal-hype"></div>

    <p class="devmode-launch hidden" id="devmodal-launch">🎉 Con <b>100%</b> ya podés elegir la <b>fecha de lanzamiento</b> del proyecto (sección Proyectos → Fecha confirmada).</p>

    <div class="devmodal-last">Último avance: <b>${lastBy}</b> · <span>${lastWhen}</span></div>
    <p class="dev-meta">👤 Se registrará como <b>${escapeHtml(getCurrentAdminName())}</b></p>
    <div id="devmodal-alert" class="alert-box hidden"></div>
    <button class="btn btn-primary btn-block" id="devmodal-save" data-adm-ev="click" data-adm="saveDevModal">💾 Guardar progreso</button>`;
  document.getElementById('dev-modal').classList.remove('hidden');
  document.body.style.overflow = 'hidden';
  const room = Math.max(0, round2(100 - pct));
  bindDecBlur('devbump-num', room);
  bindDecBlur('devmodal-num', 100);
  syncDevDayBump(0);
}

function setDevModalMode(mode) {
  devModalMode = mode === 'total' ? 'total' : 'day';
  document.querySelectorAll('.devmode-opt').forEach((b) => {
    b.classList.toggle('is-active', b.dataset.mode === devModalMode);
  });
  const day = document.getElementById('devmode-view-day');
  const total = document.getElementById('devmode-view-total');
  if (day) day.classList.toggle('hidden', devModalMode !== 'day');
  if (total) total.classList.toggle('hidden', devModalMode !== 'total');
  const badge = document.getElementById('devmodal-modebadge');
  if (badge) {
    badge.textContent = devModalMode === 'day' ? 'avance de hoy' : 'ajuste total';
    badge.className = 'dev-confirm-delta is-none';
  }
  // Al cambiar de modo se recalcula el resumen con el valor del modo destino.
  if (devModalMode === 'day') syncDevDayBump(0);
  else syncDevModal(readDevTotalValue());
}

function readDevTotalValue() {
  const num = document.getElementById('devmodal-num');
  return readDecField(num ? num.value : devModalOriginal, 100).value;
}

function readDevDayBump() {
  const num = document.getElementById('devbump-num');
  const room = Math.max(0, round2(100 - devModalOriginal));
  return readDecField(num ? num.value : 0, room).value;
}

function setDevDayBump(value, exact) {
  let n = readDecField(value, 100).value;
  if (exact && n > 0) n = Math.max(0, round2(100 - devModalOriginal));
  syncDevDayBump(n);
}

function syncDevDayBump(value) {
  const room = Math.max(0, round2(100 - devModalOriginal));
  const { text, value: n } = readDecField(value, room);
  const num = document.getElementById('devbump-num');
  if (num && num.value !== text) num.value = text;
  const range = document.getElementById('devbump-range');
  if (range) range.value = n;
  const lbl = document.getElementById('devbump-label');
  if (lbl) lbl.textContent = n > 0 ? fmtDelta(n) : '+0%';
  const fin = document.getElementById('devbump-final');
  if (fin) fin.textContent = fmtPct(round2(devModalOriginal + n));
  updateDevModalSummary(round2(devModalOriginal + n), n, 'day');
}

function syncDevModal(value) {
  const { text, value: n } = readDecField(value, 100);
  const num = document.getElementById('devmodal-num');
  if (num && num.value !== text) num.value = text;
  const range = document.getElementById('devmodal-range');
  if (range) range.value = n;
  updateDevModalSummary(n, round2(n - devModalOriginal), 'total');
}

// Resumen común: barra + antes/final + nota + aviso de 100%.
function updateDevModalSummary(finalPercent, diff, mode) {
  const fill = document.getElementById('devmodal-fill');
  if (fill) fill.style.width = finalPercent + '%';
  const before = document.getElementById('devmodal-before');
  if (before) before.textContent = fmtPct(devModalOriginal);
  const final = document.getElementById('devmodal-final');
  if (final) final.textContent = fmtPct(finalPercent);
  const badge = document.getElementById('devmodal-modebadge');
  if (badge && mode === 'day') {
    if (diff > 0) { badge.textContent = `${fmtDelta(diff)} hoy`; badge.className = 'dev-confirm-delta is-up'; }
    else { badge.textContent = 'sin cambios hoy'; badge.className = 'dev-confirm-delta is-none'; }
  }
  const note = document.getElementById('devmodal-note');
  if (note) {
    note.innerHTML = mode === 'day'
      ? `Queda registrado como <b>avance del ${escapeHtml(formatShortDate(new Date().toISOString()))}</b> y suma al total (${fmtPct(devModalOriginal)} → ${fmtPct(finalPercent)}).`
      : `Ajuste total del proyecto: el % queda en <b>${fmtPct(finalPercent)}</b> (no cuenta como avance del día).`;
  }
  const launch = document.getElementById('devmodal-launch');
  if (launch) launch.classList.toggle('hidden', finalPercent < 100);
  // Pre-aviso de euforia: si el final cae en zona hype se muestra el banner.
  const hype = document.getElementById('devmodal-hype');
  if (hype) {
    const lvl = euphoriaLevel(finalPercent);
    if (!lvl.hype) { hype.classList.add('hidden'); hype.innerHTML = ''; }
    else {
      hype.classList.remove('hidden');
      hype.className = 'devmode-hype' + (lvl.clsSuffix ? ' ' + lvl.clsSuffix : '');
      hype.innerHTML = lvl.banner(devModalOriginal, finalPercent);
    }
  }
}

function closeDevModal() {
  const modal = document.getElementById('dev-modal');
  if (modal) modal.classList.add('hidden');
  document.body.style.overflow = '';
  devModalProjectId = null;
  devModalMode = 'day';
}

async function saveDevModal() {
  const pid = devModalProjectId;
  if (!Number.isFinite(pid) || pid <= 0) return;
  const isDay = devModalMode !== 'total';
  const raw = isDay ? readDevDayBump() : readDevTotalValue();
  const finalPercent = isDay ? round2(Math.min(100, devModalOriginal + raw)) : raw;
  const noteEl = document.getElementById('devmodal-note-input');
  const note = noteEl ? noteEl.value.trim() : '';
  const adminName = getCurrentAdminName();
  const btn = document.getElementById('devmodal-save');
  const before = devModalOriginal;
  if (btn) { btn.disabled = true; btn.textContent = '⏳ Guardando…'; }
  try {
    const res = await fetch(API_BASE + `/ows-project-development/${pid}`, {
      method: 'PUT',
      headers: adminHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        percent: finalPercent,
        updated_by: adminName,
        mode: isDay ? 'day' : 'total',
        note
      })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    const saved = data.development || { project_id: pid, percent: finalPercent, updated_by: adminName, updated_at: new Date().toISOString() };
    const i = devProgressCache.findIndex((d) => Number(d.project_id) === pid);
    if (i >= 0) devProgressCache[i] = { ...devProgressCache[i], ...saved };
    else devProgressCache.push({ project_id: pid, percent: finalPercent, updated_by: adminName, updated_at: saved.updated_at });
    renderDevList();
    // El % es el mismo en Proyectos y en Gestión: se repintan las dos listas.
    renderAdminProjectsList();
    // El avance recién guardado es un movimiento más del historial: la
    // bitácora de 14 días lo tiene que mostrar de inmediato.
    loadProjectActivity();
    // Las celebraciones también cambian con cada hito: se refresca el muro.
    try { loadCelebrations(); } catch (_) {}
    const savedPid = pid;
    const savedBefore = before;
    const savedFinal = finalPercent;
    closeDevModal();
    const delta = round2(finalPercent - before);
    const proj = devProgressCache.find((x) => Number(x.project_id) === Number(savedPid)) || null;
    const pname = proj ? (proj.name || proj.slug) : 'el proyecto';
    if (delta > 0) {
      // Euforia: overlay de despegue al cruzar 100% (con registro en backend),
      // toast de hype al cruzar 90/95/99.
      try { maybeTriggerEuphoria({ projectId: savedPid, before: savedBefore, after: savedFinal, name: pname, by: adminName, celebrations: data.celebrations }); } catch (_) {}
      showToast(finalPercent >= 100
        ? `🎉 ${pname} llegó al 100% — ya podés elegir la fecha de lanzamiento`
        : `${isDay ? '📅 Avance de hoy' : '🎯 Ajuste total'}: ${pname} ${fmtPct(before)} → ${fmtPct(finalPercent)} (${fmtDelta(delta)})`);
    } else {
      showToast(`Progreso de ${pname} sin cambios (${fmtPct(finalPercent)})`);
    }
  } catch (err) {
    showAlert('devmodal-alert', err.message || 'Error al guardar.', 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '💾 Guardar progreso'; }
  }
}

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') { closeDevModal(); try { closeEuphoriaOverlay(); } catch (_) {} }
});

// =======================================================
// EUFORIA OWS — cuenta atrás 90 → 100 + overlay Despegue
// Nivel visual por % + fanfarria WebAudio + confetti en canvas propio
// (sin dependencias externas) + registro en backend /ows-celebrations.
// =======================================================

function euphoriaLevel(pct) {
  const n = Number(pct) || 0;
  if (n >= 100) {
    return {
      hype: true, rowCls: 'euph-row-100', clsSuffix: 'is-100',
      badge: '<span class="euph-badge euph-100">🚀 100% despegue</span>',
      banner: (b, f) => `🚀 <b>DESPEGUE:</b> llega a <b>${fmtPct(f)}</b>. Se abre la celebración y queda registrada.`
    };
  }
  if (n >= 99) {
    return {
      hype: true, rowCls: 'euph-row-99', clsSuffix: 'is-99',
      badge: '<span class="euph-badge euph-99">🚨 99%+ punto crítico</span>',
      banner: (b, f) => `🚨 <b>Punto crítico:</b> ${fmtPct(b)} → <b>${fmtPct(f)}</b>. Falta ${fmtPct(round2(100 - f))} para el despegue.`
    };
  }
  if (n >= 95) {
    return {
      hype: true, rowCls: 'euph-row-95', clsSuffix: 'is-95',
      badge: '<span class="euph-badge euph-95">⚡ 95% casi listo</span>',
      banner: (b, f) => `⚡ <b>Zona hype:</b> ${fmtPct(b)} → <b>${fmtPct(f)}</b>. Recta final, a preparar el anuncio.`
    };
  }
  if (n >= 90) {
    return {
      hype: true, rowCls: 'euph-row-90', clsSuffix: '',
      badge: '<span class="euph-badge euph-90">🔥 90% en hype</span>',
      banner: (b, f) => `🔥 <b>Calentando:</b> ${fmtPct(b)} → <b>${fmtPct(f)}</b>. Entró en zona de euforia.`
    };
  }
  return { hype: false, rowCls: '', clsSuffix: '', badge: '', banner: () => '' };
}

function euphoriaBadgeHtml(pct) {
  try { return euphoriaLevel(pct).badge || ''; } catch (_) { return ''; }
}

function isEuphoriaMuted() {
  try { return localStorage.getItem('ows_euphoria_muted') === '1'; } catch (_) { return false; }
}

function toggleEuphoriaMute() {
  try {
    const muted = !isEuphoriaMuted();
    localStorage.setItem('ows_euphoria_muted', muted ? '1' : '0');
    showToast(muted ? '🔇 Fanfarria silenciada' : '🔊 Fanfarria activada');
    const btn = document.getElementById('euphoria-mute-btn');
    if (btn) btn.textContent = muted ? '🔇 Silenciada' : '🔊 Sonido ON';
  } catch (_) {}
}

// Fanfarria sintetizada (3 notas ascendentes). Sin archivos, respeta mute y
// movimiento reducido (en ese caso no suena).
function playEuphoriaFanfare() {
  if (isEuphoriaMuted()) return;
  try {
    if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  } catch (_) {}
  try {
    const AC = window.AudioContext || window.webkitAudioContext;
    if (!AC) return;
    const ctx = new AC();
    const notes = [523.25, 659.25, 783.99, 1046.5];
    notes.forEach((freq, i) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'triangle';
      osc.frequency.value = freq;
      const t0 = ctx.currentTime + i * 0.13;
      gain.gain.setValueAtTime(0.0001, t0);
      gain.gain.exponentialRampToValueAtTime(0.25, t0 + 0.03);
      gain.gain.exponentialRampToValueAtTime(0.0001, t0 + 0.34);
      osc.connect(gain).connect(ctx.destination);
      osc.start(t0);
      osc.stop(t0 + 0.4);
    });
    setTimeout(() => { try { ctx.close(); } catch (_) {} }, 1200);
  } catch (_) {}
}

// Confetti dorado/violeta/verde sobre el canvas del overlay. Puro JS.
let euphoriaConfettiRAF = null;
function startEuphoriaConfetti() {
  const canvas = document.getElementById('euphoria-confetti');
  if (!canvas) return;
  try {
    if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  } catch (_) {}
  const card = canvas.parentElement;
  const w = canvas.width = (card ? card.clientWidth : 500) || 500;
  const h = canvas.height = 320;
  const ctx = canvas.getContext('2d');
  const colors = ['#f59e0b', '#fbbf24', '#f97316', '#a855f7', '#34d399', '#38bdf8', '#fef3c7'];
  const parts = Array.from({ length: 140 }, () => ({
    x: Math.random() * w,
    y: -20 - Math.random() * h * 0.5,
    vx: (Math.random() - 0.5) * 2.2,
    vy: 2 + Math.random() * 3.2,
    s: 4 + Math.random() * 6,
    r: Math.random() * Math.PI * 2,
    vr: (Math.random() - 0.5) * 0.25,
    c: colors[Math.floor(Math.random() * colors.length)]
  }));
  if (euphoriaConfettiRAF) cancelAnimationFrame(euphoriaConfettiRAF);
  const tick = () => {
    ctx.clearRect(0, 0, w, h);
    let alive = false;
    parts.forEach((p) => {
      p.x += p.vx; p.y += p.vy; p.r += p.vr;
      if (p.y < h + 20) alive = true;
      ctx.save();
      ctx.translate(p.x, p.y);
      ctx.rotate(p.r);
      ctx.fillStyle = p.c;
      ctx.fillRect(-p.s / 2, -p.s / 2, p.s, p.s * 0.6);
      ctx.restore();
    });
    if (alive) euphoriaConfettiRAF = requestAnimationFrame(tick);
    else ctx.clearRect(0, 0, w, h);
  };
  tick();
}
function stopEuphoriaConfetti() {
  if (euphoriaConfettiRAF) { try { cancelAnimationFrame(euphoriaConfettiRAF); } catch (_) {} }
  euphoriaConfettiRAF = null;
  const canvas = document.getElementById('euphoria-confetti');
  if (canvas) { try { canvas.getContext('2d').clearRect(0, 0, canvas.width, canvas.height); } catch (_) {} }
}

// Decide si hay euforia al guardar: hype por toast + overlay solo al 100.
// El overlay se muestra una sola vez por proyecto (localStorage) salvo que
// se fuerce con el botón "Ver de nuevo" del muro.
function maybeTriggerEuphoria({ projectId, before = 0, after = 0, name = '', by = '', celebrations = null } = {}) {
  const b = Number(before) || 0;
  const a = Number(after) || 0;
  if (!(a > b)) return;
  const crossed = (t) => b < t && a >= t;
  if (crossed(100)) {
    let alreadySeen = false;
    try { alreadySeen = localStorage.getItem(`ows_euphoria_seen_${projectId}_100`) === '1'; } catch (_) {}
    openEuphoriaOverlay({ projectId, name, by, before: b, after: a });
    try { localStorage.setItem(`ows_euphoria_seen_${projectId}_100`, '1'); } catch (_) {}
    if (!alreadySeen) playEuphoriaFanfare();
    return;
  }
  if (crossed(99)) { playEuphoriaFanfare(); showToast(`🚨 ${name} en 99%+ — punto crítico, falta ${fmtPct(round2(100 - a))}`); return; }
  if (crossed(95)) { playEuphoriaFanfare(); showToast(`⚡ ${name} al 95% — recta final`); return; }
  if (crossed(90)) { playEuphoriaFanfare(); showToast(`🔥 ${name} entró en hype (90%)`); return; }
}

function openEuphoriaOverlay({ projectId, name = '', by = '', before = 0, after = 0 } = {}) {
  const overlay = document.getElementById('euphoria-overlay');
  const body = document.getElementById('euphoria-body');
  if (!overlay || !body) return;
  const safeName = escapeHtml(name || 'el proyecto');
  const safeBy = escapeHtml(by || getCurrentAdminName());
  body.innerHTML = `
    <div class="euphoria-icon">🚀</div>
    <span class="euphoria-kicker">OWS · Despegue · 100%</span>
    <h3 class="euphoria-title" id="euphoria-title"><b>${safeName}</b> listo para despegar</h3>
    <p class="euphoria-sub">De <b>${fmtPct(before)}</b> a <b>${fmtPct(after)}</b> · cerrado por <b>${safeBy}</b> · quedó registrado en <b>Celebraciones</b>. Ahora: fijá fecha, anuncialo y llevalo al catálogo global.</p>
    <div class="euphoria-actions">
      <button class="btn btn-primary btn-sm" data-adm-ev="click" data-adm="euphoriaGotoDate" data-adm-a0="r:${Number(projectId) || 0}">📅 Fijar fecha</button>
      <button class="btn btn-ghost btn-sm" data-adm-ev="click" data-adm="euphoriaGotoEvent" data-adm-a0="s:${escapeHtml(name || '')}">🚀 Crear evento</button>
      <button class="btn btn-ghost btn-sm" data-adm-ev="click" data-adm="euphoriaGotoNews" data-adm-a0="s:${escapeHtml(name || '')}">📰 Crear noticia</button>
      <button class="btn btn-ghost btn-sm" data-adm-ev="click" data-adm="euphoriaGotoCelebs">🎉 Ver muro</button>
    </div>
    <div class="euphoria-foot">
      <button class="euphoria-mute" data-adm-ev="click" data-adm="toggleEuphoriaMute" id="euphoria-mute-btn">${isEuphoriaMuted() ? '🔇 Silenciada' : '🔊 Sonido ON'}</button>
      <span style="font-size:0.75rem;color:var(--text-muted)">·</span>
      <button class="euphoria-mute" data-adm-ev="click" data-adm="closeEuphoriaOverlay">Seguir trabajando →</button>
    </div>`;
  overlay.classList.remove('hidden');
  document.body.style.overflow = 'hidden';
  playEuphoriaFanfare();
  setTimeout(() => { try { startEuphoriaConfetti(); } catch (_) {} }, 60);
}

function closeEuphoriaOverlay() {
  const overlay = document.getElementById('euphoria-overlay');
  if (overlay) overlay.classList.add('hidden');
  stopEuphoriaConfetti();
  if (document.getElementById('dev-modal').classList.contains('hidden')) {
    document.body.style.overflow = '';
  }
}

// Atajos del overlay: cierran la fiesta y dejan todo precargado.
function euphoriaGotoDate(projectId) {
  closeEuphoriaOverlay();
  switchAdminTab('projects');
  try {
    const p = (projectsCache || []).find((x) => Number(x.id) === Number(projectId))
      || (manageProjectsCache || []).find((x) => Number(x.id) === Number(projectId));
    if (p) showToast(`📅 ${p.name}: editá y poné la Fecha confirmada`);
  } catch (_) {}
}
function euphoriaGotoEvent(projectName) {
  closeEuphoriaOverlay();
  switchAdminTab('events');
  try {
    const t = document.getElementById('event-title');
    if (t && projectName) { t.value = `¡${projectName} llegó al 100%!`; updateEventLivePreview(); }
    focusEventForm();
  } catch (_) { try { focusEventForm(); } catch (_) {} }
}
function euphoriaGotoNews(projectName) {
  closeEuphoriaOverlay();
  switchAdminTab('news');
  try {
    const t = document.getElementById('news-title');
    if (t && projectName) { t.value = `${projectName} completó su desarrollo 🚀`; admUpdateNewsCountersAndPreview(); }
    openNewsForm();
  } catch (_) { try { openNewsForm(); } catch (_) {} }
}
function euphoriaGotoCelebs() {
  closeEuphoriaOverlay();
  switchAdminTab('manage');
  switchAdminSub('manage', 'celebs');
}

// =======================================================
// CELEBRACIONES + BIENVENIDAS — muro interno con backend
// GET/POST/DELETE /ows-celebrations (solo-admin).
//  - Celebraciones 🎉: catalog_entry + hypes + liftoff (llegada al catálogo global)
//  - Bienvenidas 🌱: kind welcome (nace un solo-admin, pronto será grande)
// =======================================================

let celebrationsCache = [];

function celebKindMeta(kind) {
  switch (String(kind || '')) {
    case 'welcome': return { icon: '🌱', label: 'Bienvenida' };
    case 'hype_90': return { icon: '🔥', label: 'Hype 90%' };
    case 'hype_95': return { icon: '⚡', label: 'Hype 95%' };
    case 'hype_99': return { icon: '🚨', label: 'Punto crítico 99%' };
    case 'liftoff_100': return { icon: '🚀', label: 'Despegue 100%' };
    case 'catalog_entry': return { icon: '🎉', label: 'Catálogo global' };
    default: return { icon: '🎉', label: String(kind || 'Festejo') };
  }
}

async function loadCelebrations(manual) {
  const celebsList = document.getElementById('celebs-list');
  const welcomeList = document.getElementById('welcome-list');
  if (!celebsList && !welcomeList) return;
  try {
    const res = await fetch(API_BASE + '/ows-celebrations?limit=200', { headers: adminHeaders() });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    celebrationsCache = Array.isArray(data.celebrations) ? data.celebrations : [];
    renderCelebrations();
    renderWelcomes();
    if (manual) showToast('✔ Celebraciones actualizadas');
  } catch (err) {
    const msg = `<p class="loading-note">⚠️ ${escapeHtml(err.message || 'Error')}</p>`;
    if (celebsList) celebsList.innerHTML = msg;
    if (welcomeList) welcomeList.innerHTML = msg;
  }
}

function celebItemHtml(c) {
  const meta = celebKindMeta(c.kind);
  const when = c.created_at ? formatDevAgo(c.created_at) : 'recién';
  const icon = c.project_icon_url
    ? `<div class="admin-item-thumb project-icon-wrap" style="width:50px;height:50px">${meta.icon}<img src="${escapeHtml(c.project_icon_url)}" alt="" data-adm-err="rm" /></div>`
    : `<div class="admin-item-thumb project-icon-wrap" style="width:50px;height:50px">${meta.icon}</div>`;
  const pctLine = (c.percent_before != null && c.percent_after != null)
    ? ` · ${fmtPct(c.percent_before)} → ${fmtPct(c.percent_after)}` : '';
  return `
  <div class="admin-item celeb-item is-${escapeHtml(c.kind)}">
    ${icon}
    <div class="admin-item-info">
      <span class="admin-item-title">${escapeHtml(c.title || meta.label)} <span class="celeb-kind">${meta.icon} ${escapeHtml(meta.label)}</span></span>
      <span class="admin-item-sub">🎯 ${escapeHtml(c.project_name || c.project_slug || ('#' + (c.project_id || '')))}${pctLine} · 👤 ${escapeHtml(c.created_by || '—')} · 🕓 ${escapeHtml(when)}</span>
      ${c.message ? `<span class="admin-item-desc">💬 ${escapeHtml(c.message)}</span>` : ''}
    </div>
    <div class="admin-item-actions">
      ${c.kind === 'liftoff_100' ? `<button class="btn btn-ghost btn-mini" title="Ver despegue de nuevo" data-adm-ev="click" data-adm="replayLiftoff" data-adm-a0="r:${Number(c.project_id) || 0}">🚀</button>` : ''}
      ${c.kind === 'liftoff_100' ? `<button class="btn btn-ghost btn-mini" title="Festejar entrada al catálogo" data-adm-ev="click" data-adm="celebrateCatalogEntry" data-adm-a0="r:${Number(c.project_id) || 0}">🎉</button>` : ''}
      <button class="btn btn-danger btn-mini" title="Borrar festejo" data-adm-ev="click" data-adm="deleteCelebration" data-adm-a0="r:${Number(c.id) || 0}">🗑️</button>
    </div>
  </div>`;
}

function renderCelebrations() {
  const list = document.getElementById('celebs-list');
  if (!list) return;
  const items = celebrationsCache.filter((c) => String(c.kind) !== 'welcome');
  const catalogCount = celebrationsCache.filter((c) => String(c.kind) === 'catalog_entry').length;
  const hypeCount = celebrationsCache.filter((c) => ['hype_90', 'hype_95', 'hype_99', 'liftoff_100'].includes(String(c.kind))).length;
  const set = (id, txt) => { const el = document.getElementById(id); if (el) el.textContent = txt; };
  set('celeb-total-badge', `🎉 ${items.length} ${items.length === 1 ? 'festejo' : 'festejos'}`);
  set('celeb-catalog-badge', `🌍 ${catalogCount} en catálogo`);
  set('celeb-hype-badge', `🔥 ${hypeCount} hitos`);
  if (!items.length) {
    list.innerHTML = '<p class="loading-note">🎉 Todavía no hay festejos. Al cruzar 90/95/99/100 o entrar al catálogo global, aparecen acá solos.</p>';
    return;
  }
  list.innerHTML = items.map(celebItemHtml).join('');
}

function renderWelcomes() {
  const list = document.getElementById('welcome-list');
  if (!list) return;
  const items = celebrationsCache.filter((c) => String(c.kind) === 'welcome');
  const set = (id, txt) => { const el = document.getElementById(id); if (el) el.textContent = txt; };
  set('welcome-total-badge', `🌱 ${items.length} ${items.length === 1 ? 'bienvenida' : 'bienvenidas'}`);
  if (!items.length) {
    list.innerHTML = '<p class="loading-note">🌱 Todavía no hay bienvenidas. Creá un proyecto solo-admin en Gestión y nace acá su bienvenida: pronto será grande.</p>';
    return;
  }
  list.innerHTML = items.map(celebItemHtml).join('');
}

async function deleteCelebration(id) {
  if (!confirm('¿Borrar este festejo del muro? (el hito se puede volver a generar)')) return;
  try {
    const res = await fetch(API_BASE + `/ows-celebrations/${Number(id)}`, {
      method: 'DELETE', headers: adminHeaders()
    });
    if (!res.ok) throw new Error(`Error (${res.status})`);
    showToast('Festejo borrado');
    loadCelebrations();
  } catch (err) {
    showToast(`⚠️ ${err.message || 'No se pudo borrar'}`);
  }
}

// Festeja a mano la entrada al catálogo de un proyecto (ej: ya está al 100%
// y se volvió público). Dedupeado en backend: si ya existe, no duplica.
async function celebrateCatalogEntry(projectId) {
  const pid = Number(projectId);
  if (!Number.isFinite(pid) || pid <= 0) return;
  try {
    const res = await fetch(API_BASE + '/ows-celebrations', {
      method: 'POST',
      headers: adminHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ project_id: pid, kind: 'catalog_entry', created_by: getCurrentAdminName() })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    showToast(`🎉 ¡Entrada al catálogo festejada!`);
    loadCelebrations();
    switchAdminSub('manage', 'celebs');
  } catch (err) {
    showToast(`⚠️ ${err.message || 'No se pudo festejar'}`);
  }
}

// Reabre el overlay de despegue de un proyecto (para revivir la euforia).
function replayLiftoff(projectId) {
  const pid = Number(projectId);
  const dev = devProgressCache.find((x) => Number(x.project_id) === pid);
  const celeb = celebrationsCache.find((c) => Number(c.project_id) === pid && String(c.kind) === 'liftoff_100');
  const name = (dev && (dev.name || dev.slug)) || (celeb && celeb.project_name) || ('#' + pid);
  const pct = dev ? round2(dev.percent) : 100;
  openEuphoriaOverlay({ projectId: pid, name, by: (dev && dev.updated_by) || getCurrentAdminName(), before: pct >= 100 ? 99 : pct, after: 100 });
}

// =======================================================
// USUARIOS — administración
// Muestra la cantidad total de usuarios y permite modificar datos sensibles
// (usuario, contraseña, rol admin, saldos) + agregar usuarios nuevos
// (opcionalmente como admin). Todo pasa por endpoints /ows-admin-panel/users*
// que exigen JWT de superadmin.
// =======================================================

let adminUsersCache = [];
let adminUsersTotal = 0;
let editingAdminUserId = null;
let adminUsersSearch = '';
let adminUsersSearchTimer = null;
// Filtro por rol: 'all' | 'admins' (principal + admins) | 'members'
let adminUsersRoleFilter = 'all';

function setAdminUsersFilter(f) {
  adminUsersRoleFilter = (f === 'admins' || f === 'members') ? f : 'all';
  document.querySelectorAll('[data-usersfilter]').forEach((b) => {
    b.classList.toggle('active', b.dataset.usersfilter === adminUsersRoleFilter);
  });
  renderAdminUsers();
}

function clearAdminUsersFilter() {
  adminUsersSearch = '';
  const si = document.getElementById('users-search');
  if (si) si.value = '';
  setAdminUsersFilter('all');
}

function onAdminUsersSearch(value) {
  adminUsersSearch = String(value || '').trim();
  if (adminUsersSearchTimer) clearTimeout(adminUsersSearchTimer);
  adminUsersSearchTimer = setTimeout(() => loadAdminUsers(), 350);
}

function updateUsersBadges(stats) {
  const total = Number(stats?.total ?? adminUsersTotal ?? 0);
  const admins = Number(stats?.admins ?? adminUsersCache.filter((u) => u.is_admin).length ?? 0);
  const regular = Math.max(0, total - admins);
  const week = Number(stats?.last_week ?? 0);
  const set = (id, txt) => { const el = document.getElementById(id); if (el) el.textContent = txt; };
  set('users-total-badge', `👥 ${total} ${total === 1 ? 'usuario' : 'usuarios'}`);
  set('users-admins-badge', `🛡️ ${admins} ${admins === 1 ? 'admin' : 'admins'}`);
  set('users-regular-badge', `🧑 ${regular} ${regular === 1 ? 'miembro' : 'miembros'}`);
  set('users-week-badge', `🆕 ${week} esta semana`);
  const setChip = (f, txt) => { const b = document.querySelector(`[data-usersfilter="${f}"]`); if (b) b.textContent = txt; };
  setChip('all', `Todos (${total})`);
  setChip('admins', `🛡️ Admins (${admins})`);
  setChip('members', `🧑 Miembros (${regular})`);
}

async function loadAdminUsers(manual) {
  const list = document.getElementById('users-list');
  if (!list) return;
  if (!(await requireAuth())) return;
  try {
    const [statsRes, listRes] = await Promise.all([
      adminFetch(API_BASE + '/ows-admin-panel/users/stats'),
      adminFetch(API_BASE + '/ows-admin-panel/users?limit=200' + (adminUsersSearch ? `&search=${encodeURIComponent(adminUsersSearch)}` : ''))
    ]);
    const stats = await statsRes.json().catch(() => ({}));
    const data = await listRes.json().catch(() => ({}));
    if (!statsRes.ok) throw new Error(stats.error || `Error stats (${statsRes.status})`);
    if (!listRes.ok) throw new Error(data.error || `Error lista (${listRes.status})`);
    adminUsersCache = Array.isArray(data.users) ? data.users : [];
    adminUsersTotal = Number(data.total ?? stats.total ?? adminUsersCache.length);
    updateUsersBadges(stats);
    renderAdminUsers();
    if (manual) showToast(`✔ Usuarios actualizados: ${adminUsersTotal}`);
  } catch (err) {
    list.innerHTML = `<p class="loading-note">⚠️ ${escapeHtml(err.message || 'No se pudieron cargar los usuarios.')}</p>`;
  }
}

// Lista categorizada por rol: principal → administradores → miembros.
// Con filtro 'admins'/'members' se muestra plano; en 'Todos' (sin búsqueda)
// se agrupa con encabezados por categoría para reconocer cada rol al instante.
function userRoleRank(u) {
  if (u.is_owner) return 0;
  if (u.is_admin) return 1;
  return 2;
}

function userRowHtml(u) {
  const roleChip = u.is_owner
    ? '<span class="status-pill status-owner">⭐ Cuenta principal</span>'
    : u.is_admin
      ? '<span class="status-pill status-admin">🛡️ Admin</span>'
      : '<span class="status-pill status-off">🧑 Miembro</span>';
  const rowCls = u.is_owner ? 'is-owner-row' : (u.is_admin ? 'is-admin-row' : 'is-member-row');
  const avatarCls = u.is_owner ? 'user-avatar-owner' : (u.is_admin ? 'user-avatar-admin' : '');
  const avatarIcon = u.is_owner ? '⭐' : (u.is_admin ? '🛡️' : '👤');
  const date = u.created_at ? new Date(u.created_at).toLocaleDateString('es-ES', { day: 'numeric', month: 'short', year: 'numeric' }) : '—';
  const balances = `💰 ${u.aquabux ?? 0} AquaBux · ${u.ecoxionums ?? 0} Ecoxionums`;
  const ownerLock = u.is_owner ? 'disabled title="La cuenta principal está protegida: no se puede degradar ni eliminar"' : '';
  return `
  <div class="admin-item user-item${u.is_admin ? ' user-is-admin' : ''} ${rowCls}">
    <div class="admin-item-thumb user-avatar ${avatarCls}">${avatarIcon}</div>
    <div class="admin-item-info">
      <span class="admin-item-title">${escapeHtml(u.username)} ${roleChip}</span>
      <span class="admin-item-sub">#${u.id} · 📅 ${escapeHtml(date)} · ${escapeHtml(balances)}</span>
    </div>
    <div class="admin-item-actions user-actions">
      <button class="btn btn-ghost btn-mini" title="Editar datos sensibles" data-adm-ev="click" data-adm="editAdminUser" data-adm-a0="r:${u.id}">✏️</button>
      <button class="btn btn-ghost btn-mini" title="Nueva contraseña" data-adm-ev="click" data-adm="resetAdminUserPassword" data-adm-a0="r:${u.id}">🔑</button>
      <button class="btn btn-ghost btn-mini" title="${u.is_admin ? 'Quitar admin' : 'Hacer admin'}" ${ownerLock} data-adm-ev="click" data-adm="toggleAdminUserRole" data-adm-a0="r:${u.id}" data-adm-a1="r:${u.is_admin ? 'false' : 'true'}">${u.is_admin ? '⬇️' : '🛡️'}</button>
      <button class="btn btn-danger btn-mini" title="Eliminar" ${ownerLock} data-adm-ev="click" data-adm="deleteAdminUser" data-adm-a0="r:${u.id}">🗑️</button>
    </div>
  </div>`;
}

function renderAdminUsers() {
  const list = document.getElementById('users-list');
  if (!list) return;
  if (!adminUsersCache.length) {
    list.innerHTML = adminUsersSearch
      ? `<p class="loading-note">Sin resultados para “${escapeHtml(adminUsersSearch)}”.</p>`
      : '<p class="loading-note">👥 Todavía no hay usuarios registrados.</p>';
    return;
  }
  let arr = [...adminUsersCache];
  if (adminUsersRoleFilter === 'admins') arr = arr.filter((u) => u.is_admin || u.is_owner);
  else if (adminUsersRoleFilter === 'members') arr = arr.filter((u) => !u.is_admin && !u.is_owner);
  if (!arr.length) {
    const what = adminUsersRoleFilter === 'admins' ? '🛡️ administradores' : '🧑 miembros';
    list.innerHTML = `<div class="newsadm-empty"><span class="newsadm-empty-icon">🔎</span>`
      + `<p><b>Sin resultados.</b><br />No hay ${what} que coincidan con el filtro${adminUsersSearch ? ` ni con “${escapeHtml(adminUsersSearch)}”` : ''}.</p>`
      + `<button class="btn btn-ghost btn-sm" data-adm-ev="click" data-adm="clearAdminUsersFilter">↺ Ver todos</button></div>`;
    return;
  }
  // Orden fijo por categoría y luego por id: el rol se reconoce de un vistazo.
  arr.sort((a, b) => userRoleRank(a) - userRoleRank(b) || Number(a.id) - Number(b.id));

  // Vista agrupada por categorías (solo en 'Todos' sin búsqueda).
  if (adminUsersRoleFilter === 'all' && !adminUsersSearch) {
    const groups = [
      { title: '⭐ Cuenta principal', items: arr.filter((u) => u.is_owner) },
      { title: '🛡️ Administradores', items: arr.filter((u) => !u.is_owner && u.is_admin) },
      { title: '🧑 Miembros', items: arr.filter((u) => !u.is_owner && !u.is_admin) }
    ].filter((g) => g.items.length);
    list.innerHTML = groups.map((g) => `
      <div class="users-group-title">${escapeHtml(g.title)} <span class="users-group-count">${g.items.length}</span></div>
      ${g.items.map(userRowHtml).join('')}`).join('');
    return;
  }
  list.innerHTML = arr.map(userRowHtml).join('');
}

async function saveAdminUser(e) {
  if (e && e.preventDefault) e.preventDefault();
  if (!(await requireAuth())) return;
  hideAlert('users-form-alert');
  const usernameEl = document.getElementById('new-username');
  const passEl = document.getElementById('new-password');
  const adminEl = document.getElementById('new-is-admin');
  const username = usernameEl.value.trim();
  const password = passEl.value;
  const isAdmin = !!(adminEl && adminEl.checked);
  const btn = document.getElementById('btn-save-user');

  if (!username || (!editingAdminUserId && !password)) {
    showAlert('users-form-alert', 'Usuario y contraseña son obligatorios.', 'error');
    return;
  }
  if (!editingAdminUserId && password.length < 6) {
    showAlert('users-form-alert', 'La contraseña debe tener al menos 6 caracteres.', 'error');
    return;
  }

  btn.disabled = true;
  try {
    let res;
    if (editingAdminUserId) {
      // Edición de datos sensibles: usuario + rol admin + saldos.
      // La contraseña solo se cambia si se escribió una nueva.
      const payload = { username, is_admin: isAdmin };
      if (password) {
        if (password.length < 6) throw new Error('La nueva contraseña debe tener al menos 6 caracteres.');
        payload.password = password;
      }
      const aq = document.getElementById('edit-aquabux');
      const eco = document.getElementById('edit-ecoxionums');
      if (aq) payload.aquabux = Number(aq.value || 0);
      if (eco) payload.ecoxionums = Number(eco.value || 0);
      btn.textContent = '💾 Guardando…';
      res = await adminFetch(API_BASE + `/ows-admin-panel/users/${editingAdminUserId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
    } else {
      btn.textContent = '⏳ Creando…';
      res = await adminFetch(API_BASE + '/ows-admin-panel/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, is_admin: isAdmin })
      });
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    showToast(editingAdminUserId
      ? `✔ Usuario "${data.user?.username || username}" actualizado`
      : isAdmin
        ? `🛡️ Admin "${username}" creado ✔`
        : `✔ Usuario "${username}" creado`);
    resetAdminUserForm();
    await loadAdminUsers();
  } catch (err) {
    showAlert('users-form-alert', err.message || 'Error al guardar.', 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = editingAdminUserId ? '💾 Guardar cambios' : '➕ Crear usuario';
  }
}

function editAdminUser(id) {
  const u = adminUsersCache.find((x) => Number(x.id) === Number(id));
  if (!u) return showToast('⚠️ Usuario no encontrado en caché');
  editingAdminUserId = id;
  hideAlert('users-form-alert');
  document.getElementById('new-username').value = u.username || '';
  document.getElementById('new-password').value = '';
  document.getElementById('new-password').placeholder = '(vacío = no cambiar)';
  document.getElementById('new-password').required = false;
  document.getElementById('new-password-label').textContent = 'Nueva contraseña (vacío = no cambiar)';
  const adminEl = document.getElementById('new-is-admin');
  if (adminEl) {
    adminEl.checked = !!u.is_admin;
    if (u.is_owner) adminEl.disabled = true;
    else adminEl.disabled = false;
  }
  const aq = document.getElementById('edit-aquabux');
  const eco = document.getElementById('edit-ecoxionums');
  const balRow = document.getElementById('user-balances-row');
  if (aq) aq.value = Number(u.aquabux ?? 0);
  if (eco) eco.value = Number(u.ecoxionums ?? 0);
  if (balRow) balRow.classList.remove('hidden');
  document.getElementById('user-form-title').textContent = `✏️ Editando: ${u.username} (datos sensibles)`;
  document.getElementById('btn-cancel-user').classList.remove('hidden');
  document.getElementById('btn-save-user').textContent = '💾 Guardar cambios';
  openFormModal('user');
}

function resetAdminUserForm() {
  editingAdminUserId = null;
  hideAlert('users-form-alert');
  document.getElementById('new-username').value = '';
  const passEl = document.getElementById('new-password');
  passEl.value = '';
  passEl.placeholder = 'Mínimo 6 caracteres';
  passEl.required = true;
  document.getElementById('new-password-label').textContent = 'Contraseña *';
  const adminEl = document.getElementById('new-is-admin');
  if (adminEl) { adminEl.checked = false; adminEl.disabled = false; }
  const aq = document.getElementById('edit-aquabux');
  const eco = document.getElementById('edit-ecoxionums');
  if (aq) aq.value = 0;
  if (eco) eco.value = 0;
  const balRow = document.getElementById('user-balances-row');
  if (balRow) balRow.classList.add('hidden');
  document.getElementById('user-form-title').textContent = '➕ Agregar usuario';
  document.getElementById('btn-cancel-user').classList.add('hidden');
  document.getElementById('btn-save-user').textContent = '➕ Crear usuario';
  try { closeFormModal(); } catch (_) {}
}

async function toggleAdminUserRole(id, makeAdmin) {
  const u = adminUsersCache.find((x) => Number(x.id) === Number(id));
  if (u?.is_owner) return showToast('🔒 No se puede cambiar el rol de la cuenta principal.');
  if (!confirm(makeAdmin ? `¿Dar rol de ADMIN a "${u?.username || '#' + id}"?` : `¿Quitar rol de admin a "${u?.username || '#' + id}"?`)) return;
  if (!(await requireAuth())) return;
  try {
    const res = await adminFetch(API_BASE + `/ows-admin-panel/users/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ is_admin: !!makeAdmin })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    showToast(makeAdmin ? `🛡️ "${u?.username}" ahora es admin` : `"${u?.username}" volvió a miembro`);
    if (editingAdminUserId === id) resetAdminUserForm();
    loadAdminUsers();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

async function resetAdminUserPassword(id) {
  const u = adminUsersCache.find((x) => Number(x.id) === Number(id));
  const np = prompt(`🔑 Nueva contraseña para "${u?.username || '#' + id}" (mínimo 6 caracteres):`, '');
  if (np === null) return;
  if (String(np).length < 6) return showToast('⚠️ La contraseña debe tener al menos 6 caracteres.');
  if (!(await requireAuth())) return;
  try {
    const res = await adminFetch(API_BASE + `/ows-admin-panel/users/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: String(np) })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    showToast(`🔑 Contraseña de "${u?.username}" actualizada`);
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

async function deleteAdminUser(id) {
  const u = adminUsersCache.find((x) => Number(x.id) === Number(id));
  if (u?.is_owner) return showToast('🔒 No se puede eliminar la cuenta principal.');
  if (!confirm(`¿Eliminar al usuario "${u?.username || '#' + id}" permanentemente?`)) return;
  if (!(await requireAuth())) return;
  try {
    const res = await adminFetch(API_BASE + `/ows-admin-panel/users/${id}`, {
      method: 'DELETE'
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    showToast(`Usuario "${u?.username}" eliminado`);
    if (editingAdminUserId === id) resetAdminUserForm();
    loadAdminUsers();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

// =======================================================
// DEVLOG — sub-sección de Gestión
// Tabla con todos los devlogs (por quién, cuándo, highlight de nuevos)
// + modal "Crear Devlog": por qué, si afecta a un proyecto y a cuál, etc.
// Endpoints: GET/POST/PATCH/DELETE /ows-devlogs (solo-admin).
// =======================================================

let devlogsCache = [];
let editingDevlogId = null;

// Frescura para highlight: entradas de los últimos 7 días
const DEVLOG_FRESH_MS = 7 * 24 * 60 * 60 * 1000;

function isDevlogFresh(d) {
  const t = d?.created_at ? new Date(d.created_at).getTime() : NaN;
  return Number.isFinite(t) && (Date.now() - t) <= DEVLOG_FRESH_MS;
}

function formatDevlogDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleDateString('es-ES', { day: 'numeric', month: 'short', year: 'numeric' });
}

async function loadDevlogs(manual) {
  const tbody = document.getElementById('devlog-table-body');
  const empty = document.getElementById('devlog-empty');
  if (!tbody) return;
  if (!(await requireAuth())) return;
  try {
    const res = await adminFetch(API_BASE + '/ows-devlogs?limit=200');
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    devlogsCache = Array.isArray(data.devlogs) ? data.devlogs : [];
    renderDevlogs();
    if (manual) showToast(`✔ Devlog actualizado: ${devlogsCache.length} ${devlogsCache.length === 1 ? 'entrada' : 'entradas'}`);
  } catch (err) {
    tbody.innerHTML = '';
    if (empty) {
      empty.classList.remove('hidden');
      empty.querySelector('.news-empty-title').textContent = 'No se pudo cargar el devlog';
      empty.querySelector('.news-empty-sub').textContent = err.message || 'Revisá tu conexión.';
    }
  }
}

// Mini-gráfica del avance registrado: base gris (el % anterior) + tramo
// verde (lo que sumó este devlog). Es el registro visual de "esto dejó el
// proyecto en X%".
function devlogProgressCell(d) {
  if (!d || d.progress_after == null) {
    // Sin antes/después pero con avance registrado: se muestra el delta del día.
    const only = d && d.progress_delta != null ? round2(d.progress_delta) : null;
    if (only) {
      return `<span class="devlog-spark-label" title="Avance del día (sin antes/después registrados)"><em>${fmtDelta(only)}</em></span>`;
    }
    return '<span class="devlog-no-progress">sin %</span>';
  }
  const after = round2(d.progress_after);
  const before = round2(Math.max(0, Math.min(after, d.progress_before ?? after)));
  const delta = round2(Math.max(0, after - before));
  const grew = delta > 0;
  return `
    <div class="devlog-spark${grew ? ' is-up' : ''}" title="Antes ${fmtPct(before)} → Final ${fmtPct(after)}${grew ? ` (${fmtDelta(delta)})` : ''}">
      <div class="devlog-spark-bar">
        <span class="devlog-spark-base" style="width:${before}%"></span>
        ${grew ? `<span class="devlog-spark-gain" style="left:${before}%;width:${delta}%"></span>` : ''}
      </div>
      <span class="devlog-spark-label">
        <span class="devlog-spark-from">${fmtPct(before)}</span>
        <span class="devlog-spark-arrow">→</span>
        <b>${fmtPct(after)}</b>
        ${grew ? `<em>${fmtDelta(delta)}</em>` : ''}
      </span>
    </div>`;
}

function renderDevlogs() {
  const tbody = document.getElementById('devlog-table-body');
  const empty = document.getElementById('devlog-empty');
  if (!tbody) return;
  const totalBadge = document.getElementById('devlog-total-badge');
  const freshBadge = document.getElementById('devlog-fresh-badge');
  const dailyBadge = document.getElementById('devlog-daily-badge');
  const freshCount = devlogsCache.filter(isDevlogFresh).length;
  const dailyCount = devlogsCache.filter((d) => d.entry_type === 'daily').length;
  if (totalBadge) totalBadge.textContent = `📝 ${devlogsCache.length} ${devlogsCache.length === 1 ? 'entrada' : 'entradas'}`;
  if (freshBadge) freshBadge.textContent = `🆕 ${freshCount} ${freshCount === 1 ? 'nueva' : 'nuevas'}`;
  if (dailyBadge) dailyBadge.textContent = `🗓️ ${dailyCount} ${dailyCount === 1 ? 'del día' : 'del día'}`;

  if (!devlogsCache.length) {
    tbody.innerHTML = '';
    if (empty) {
      empty.classList.remove('hidden');
      empty.querySelector('.news-empty-title').textContent = 'Sin entradas todavía';
      empty.querySelector('.news-empty-sub').textContent = 'Creá la primera con “Crear Devlog”.';
    }
    return;
  }
  if (empty) empty.classList.add('hidden');

  const newestId = devlogsCache.length ? Number(devlogsCache[0].id) : -1;
  tbody.innerHTML = devlogsCache.map((d) => {    const fresh = isDevlogFresh(d);
    const isNewest = Number(d.id) === newestId && fresh;
    // Un devlog del día se arma combinando sesiones de trabajo: se marca
    // para que se distinga de una entrada escrita a mano.
    const dailyTag = d.entry_type === 'daily'
      ? ` <span class="devlog-daily-badge" title="Se generó combinando ${(d.session_ids || []).length} sesión(es) de trabajo">🗓️ del día${Array.isArray(d.session_ids) && d.session_ids.length ? ` · ${d.session_ids.length} sesiones` : ''}${d.day_minutes ? ` · ${wsMinutes(d.day_minutes)}` : ''}</span>`
      : '';
    const proj = d.affects_project
      ? `<span class="news-item-project">🎯 ${escapeHtml(d.project_name || 'Proyecto')}</span>`
      : '<span class="devlog-no-proj">—</span>';
    return `
    <tr class="${fresh ? 'devlog-fresh' : ''}" data-adm-ev="click" data-adm="viewDevlog" data-adm-a0="r:${d.id}" role="button" tabindex="0" title="Ver detalle">
      <td>
        <span class="news-item-title">${escapeHtml(d.title)}${dailyTag}${isNewest ? ' <span class="devlog-new-badge">🆕 Nuevo</span>' : ''}</span>
        ${d.reason ? `<span class="news-item-desc">${escapeHtml(d.reason.length > 90 ? d.reason.slice(0, 90) + '…' : d.reason)}</span>` : ''}
      </td>
      <td data-label="Proyecto">${proj}</td>
      <td data-label="Progreso">${devlogProgressCell(d)}</td>
      <td data-label="Por quién"><span class="devlog-by">👤 ${escapeHtml(d.created_by || '—')}</span></td>
      <td class="news-item-date" data-label="Cuándo">${escapeHtml(formatDevlogDate(d.created_at))}</td>
      <td class="devlog-td-actions" data-adm-stop="1">
        <button class="btn btn-ghost btn-mini" title="Ver" data-adm-ev="click" data-adm="viewDevlog" data-adm-a0="r:${d.id}">👁️</button>
        <button class="btn btn-ghost btn-mini" title="Editar" data-adm-ev="click" data-adm="openDevlogForm" data-adm-a0="r:${d.id}">✏️</button>
        <button class="btn btn-danger btn-mini" title="Eliminar" data-adm-ev="click" data-adm="deleteDevlog" data-adm-a0="r:${d.id}">🗑️</button>
      </td>
    </tr>`;
  }).join('');
  // Un devlog nuevo es un evento más en la bitácora diaria: se repinta.
  renderProjectActivity();
}

// Opciones de proyecto para el modal (solo-admin + disponibles)
function devlogProjectOptions(selectedId) {
  const seen = new Set();
  const all = [...(manageProjectsCache || []), ...(projectsCache || [])];
  const opts = ['<option value="">— Elegí un proyecto —</option>'];
  all.forEach((p) => {
    const id = Number(p?.id || 0);
    if (!Number.isFinite(id) || id <= 0 || seen.has(id)) return;
    seen.add(id);
    const tag = (p.admin_only === true || p.adminOnly === true) ? '🔒' : '📁';
    const sel = Number(selectedId) === id ? ' selected' : '';
    opts.push(`<option value="${id}"${sel}>${tag} ${escapeHtml(p.name || p.slug || ('#' + id))}</option>`);
  });
  return opts.join('');
}

function onDevlogAffectsChange() {
  const sel = document.getElementById('devlog-project');
  const chk = document.getElementById('devlog-affects');
  const on = !!(chk && chk.checked);
  if (sel) sel.disabled = !on;
  const group = document.getElementById('devlog-project-group');
  if (group) {
    group.style.display = on ? '' : 'none';
    if (!on) group.removeAttribute('style');
  }
  if (on && sel && !sel.options.length) {
    sel.innerHTML = devlogProjectOptions(editingDevlogId
      ? (devlogsCache.find((x) => Number(x.id) === Number(editingDevlogId)) || {}).project_id
      : null);
  }
  updateDevlogNextHint();
}

// =======================================================
// DEVLOG — modal en 2 pasos
// Paso 1: qué se hizo y a qué proyecto afecta.
// Paso 2 (solo si afecta a un proyecto): cuánto aumentó el %.
//   Antes de confirmar se muestra explícitamente el % ANTERIOR,
//   el incremento y el % FINAL que quedará en Gestión.
// Al confirmar se guarda el devlog Y se aplica el % al proyecto,
// de modo que Devlog y Gestión quedan siempre sincronizados.
// =======================================================

// Estado del wizard (se re-arma en cada openDevlogForm)
let devlogStep = 1;
let devlogProjectPercent = 0;
let devlogProjectName = '';
// Copia de los campos del paso 1: al pasar al paso 2 ese DOM se reemplaza,
// así que hay que guardar los valores antes de avanzar (si no, null.value).
let devlogDraft = null;

function devlogCurrentPercent(projectId) {
  const pid = Number(projectId || 0);
  const d = devProgressCache.find((x) => Number(x.project_id) === pid);
  return d ? round2(d.percent) : 0;
}

function devlogProjectLabel(projectId) {
  const pid = Number(projectId || 0);
  const all = [...(manageProjectsCache || []), ...(projectsCache || [])];
  const p = all.find((x) => Number(x?.id) === pid);
  return String(p?.name || p?.slug || (pid > 0 ? '#' + pid : 'el proyecto'));
}

// ¿El paso 1 tiene los datos mínimos para avanzar?
function validateDevlogStep1() {
  const title = document.getElementById('devlog-title').value.trim();
  const reason = document.getElementById('devlog-reason').value.trim();
  if (!title) {
    showAlert('devlog-form-alert', 'El título es obligatorio.', 'error');
    document.getElementById('devlog-title').focus();
    return false;
  }
  if (!reason) {
    showAlert('devlog-form-alert', 'Indicá por qué este devlog.', 'error');
    document.getElementById('devlog-reason').focus();
    return false;
  }
  const affects = !!(document.getElementById('devlog-affects') && document.getElementById('devlog-affects').checked);
  if (affects) {
    const sel = document.getElementById('devlog-project');
    const pid = Number(sel ? sel.value : 0);
    if (!Number.isFinite(pid) || pid <= 0) {
      showAlert('devlog-form-alert', 'Si afecta a un proyecto, elegí cuál.', 'error');
      if (sel) sel.focus();
      return false;
    }
  }
  hideAlert('devlog-form-alert');
  return true;
}

// Lee el paso 1 a memoria. Se llama ANTES de renderizar el paso 2, porque
// ese render borra los inputs del paso 1 del DOM (por eso, al confirmar
// desde el paso 2 no existe `devlog-title` y leerlo daba null).
function readDevlogDraft() {
  const t = document.getElementById('devlog-title');
  const r = document.getElementById('devlog-reason');
  const d = document.getElementById('devlog-details');
  const a = document.getElementById('devlog-affects');
  const s = document.getElementById('devlog-project');
  const affects = !!(a && a.checked);
  return {
    title: t ? t.value.trim() : '',
    reason: r ? r.value.trim() : '',
    details: d ? d.value.trim() : '',
    affects_project: affects,
    project_id: affects && s ? Number(s.value || 0) : 0
  };
}

// Avanza del paso 1 al 2. Si el devlog NO afecta a un proyecto no hay
// nada más que preguntar, así que se guarda directamente.
function devlogNextStep() {
  if (!validateDevlogStep1()) return;
  devlogDraft = readDevlogDraft();
  if (!devlogDraft.affects_project) {
    // Sin proyecto — no hay % que ajustar: se confirma de una.
    commitDevlog(null);
    return;
  }
  devlogProjectPercent = devlogCurrentPercent(devlogDraft.project_id);
  devlogProjectName = devlogProjectLabel(devlogDraft.project_id);
  const room = Math.max(0, round2(100 - devlogProjectPercent));
  devlogStep = 2;
  renderDevlogStep2(room);
}

// ── Paso 2: impacto en el progreso ──
function renderDevlogStep2(room) {
  const body = document.getElementById('devlog-modal-body');
  if (!body) return;
  const presets = [0.5, 1, 2, 5, 10].filter((v) => v <= Math.max(room, 1));
  body.innerHTML = `
    <div class="devmodal-head">
      <div class="devmodal-icon">📈</div>
      <div class="devmodal-head-info">
        <h3 class="devmodal-title">Impacto en el progreso</h3>
        <p class="modal-tagline">¿Este devlog aumentó el porcentaje de <b>${escapeHtml(devlogProjectName)}</b>?</p>
      </div>
    </div>
    <div class="devstep-tag">Paso 2 de 2 · Confirmación</div>

    <div class="dev-impact">
      <div class="dev-impact-row">
        <span class="dev-impact-key">Progreso actual</span>
        <span class="dev-impact-val" id="devimp-before">${fmtPct(devlogProjectPercent)}</span>
      </div>
      <div class="dev-impact-row">
        <span class="dev-impact-key">¿Aumentó?</span>
        <div class="dev-impact-opts">
          <button type="button" class="dev-impact-opt is-active" data-bump="0" data-adm-ev="click" data-adm="devlogSetBump" data-adm-a0="n:0" data-adm-a1="r:${room}">No cambió</button>
          ${presets.map((v) => `<button type="button" class="dev-impact-opt" data-bump="${v}" data-adm-ev="click" data-adm="devlogSetBump" data-adm-a0="r:${v}" data-adm-a1="r:${room}">+${fmtPct(v)}</button>`).join('')}
          <button type="button" class="dev-impact-opt" data-bump="custom" data-adm-ev="click" data-adm="devlogFocusCustom" data-adm-a0="r:${room}">Otro…</button>
        </div>
      </div>
      <div class="dev-impact-row dev-impact-custom">
        <span class="dev-impact-key">Subir manualmente</span>
        <div class="dev-impact-custom-ctl">
          <input type="range" id="dev-bump-range" min="0" max="${room}" step="0.5" value="0" data-adm-ev="input" data-adm="syncDevlogBump" data-adm-a0="thp:value" data-adm-a1="r:${room}" />
          <input type="text" inputmode="decimal" id="dev-bump-num" class="dev-dec" maxlength="6" placeholder="0" autocomplete="off" data-adm-ev="input" data-adm="syncDevlogBump" data-adm-a0="thp:value" data-adm-a1="r:${room}" />
          <span class="dev-pct-sign">%</span>
        </div>
      </div>
    </div>

    <!-- Resumen ANTES → DESPUÉS (lo que el usuario pidió ver antes de confirmar) -->
    <div class="dev-confirm" id="dev-confirm">
      <div class="dev-confirm-head">Se va a guardar así</div>
      <div class="dev-confirm-flow">
        <div class="dev-confirm-box is-before">
          <small>Anterior</small>
          <strong id="devc-before">${fmtPct(devlogProjectPercent)}</strong>
        </div>
        <span class="dev-confirm-arrow">→</span>
        <div class="dev-confirm-box is-after">
          <small>Final</small>
          <strong id="devc-after">${fmtPct(devlogProjectPercent)}</strong>
        </div>
        <span class="dev-confirm-delta" id="devc-delta">sin cambios</span>
      </div>
      <div class="dev-confirm-bar"><div class="dev-confirm-fill" id="devc-fill" style="width:${devlogProjectPercent}%"></div></div>
      <p class="dev-confirm-note" id="devc-note">
        El porcentaje de <b>${escapeHtml(devlogProjectName)}</b> en Gestión quedará en <b>${fmtPct(devlogProjectPercent)}</b>. El devlog registra el avance sin tocar el %.
      </p>
    </div>

    <p class="dev-confirm-warn" id="devc-warn" hidden>⚠️ El proyecto ya está en 100%: el incremento se ignorará.</p>

    <div id="devlog-form-alert" class="alert-box hidden"></div>
    <div class="dev-step-actions">
      <button type="button" class="btn btn-ghost" data-adm-ev="click" data-adm="devlogBackToStep1">← Volver</button>
      <button type="button" class="btn btn-primary" id="btn-save-devlog" data-adm-ev="click" data-adm="devlogConfirmStep2">✔ Confirmar y guardar</button>
    </div>
  `;
  syncDevlogBump(0, room);
  bindDecBlur('dev-bump-num', room);
  const first = document.getElementById('devlog-title');
  setTimeout(() => { if (first) first.focus(); }, 40);
}

function devlogSetBump(value, room) {
  if (value === 'custom') return devlogFocusCustom(room);
  syncDevlogBump(value, room);
  document.querySelectorAll('.dev-impact-opt').forEach((b) => {
    b.classList.toggle('is-active', Number(b.dataset.bump) === Number(value));
  });
}

function devlogFocusCustom(room) {
  const num = document.getElementById('dev-bump-num');
  if (num) { num.focus(); num.select(); }
  document.querySelectorAll('.dev-impact-opt').forEach((b) => b.classList.remove('is-active'));
}

function syncDevlogBump(value, room) {
  const max = Number(room || 0);
  const { text, value: n } = readDecField(value, max);
  const num = document.getElementById('dev-bump-num');
  if (num && num.value !== text) num.value = text;
  const range = document.getElementById('dev-bump-range');
  if (range) range.value = n;

  const before = devlogProjectPercent;
  const after = round2(Math.min(100, before + n));
  const setText = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  setText('devimp-before', fmtPct(before));
  setText('devc-before', fmtPct(before));
  setText('devc-after', fmtPct(after));

  const delta = document.getElementById('devc-delta');
  if (delta) {
    if (n > 0) { delta.textContent = fmtDelta(n); delta.className = 'dev-confirm-delta is-up'; }
    else { delta.textContent = 'sin cambios'; delta.className = 'dev-confirm-delta is-none'; }
  }
  const fill = document.getElementById('devc-fill');
  if (fill) fill.style.width = `${after}%`;
  const note = document.getElementById('devc-note');
  if (note) {
    note.innerHTML = n > 0
      ? `El devlog queda como registro de este avance y el porcentaje de <b>${escapeHtml(devlogProjectName)}</b> en Gestión pasa de <b>${fmtPct(before)}</b> a <b>${fmtPct(after)}</b>.`
      : `El porcentaje de <b>${escapeHtml(devlogProjectName)}</b> en Gestión queda en <b>${fmtPct(after)}</b>. El devlog registra el cambio sin tocar el %.`;
  }
  const warn = document.getElementById('devc-warn');
  if (warn) warn.hidden = !(max === 0 && before >= 100);
}

function devlogBackToStep1() {
  devlogStep = 1;
  renderDevlogForm();
  // El DOM del paso 1 se recreó vacío: se repuebla desde la copia.
  if (devlogDraft) {
    const set = (id, v) => { const el = document.getElementById(id); if (el && v != null) el.value = v; };
    set('devlog-title', devlogDraft.title);
    set('devlog-reason', devlogDraft.reason);
    set('devlog-details', devlogDraft.details);
  }
  updateDevlogNextHint();
  setTimeout(() => { const t = document.getElementById('devlog-title'); if (t) t.focus(); }, 40);
}

function devlogConfirmStep2() {
  const numEl = document.getElementById('dev-bump-num');
  const bump = round2(Number(numEl ? numEl.value : 0));
  const before = devlogProjectPercent;
  const n = Number.isFinite(bump) ? bump : 0;
  const after = round2(Math.min(100, before + n));
  commitDevlog({
    before,
    after,
    delta: round2(after - before)
  });
}

// Guarda el devlog y, si trae impacto, aplica el % final al proyecto.
// El servidor devuelve el `development` ya aplicado: se usa para refrescar
// el % de Gestión sin una segunda ida.
// Los datos del paso 1 se leen de `devlogDraft` cuando se llega desde el
// paso 2 (donde esos inputs ya no existen en el DOM).
async function commitDevlog(progress) {
  if (!(await requireAuth())) return;
  const alertId = 'devlog-form-alert';
  hideAlert(alertId);
  const live = devlogStep === 1 ? readDevlogDraft() : (devlogDraft || readDevlogDraft());
  const title = String(live.title || '');
  const reason = String(live.reason || '');
  const affects = !!live.affects_project;
  const details = String(live.details || '');
  if (!title) return showAlert(alertId, 'El título es obligatorio.', 'error');
  if (!reason) return showAlert(alertId, 'Indicá por qué este devlog.', 'error');
  const payload = { title, reason, details, affects_project: affects, created_by: getCurrentAdminName() };
  if (affects) {
    const pid = Number(live.project_id || 0);
    if (!Number.isFinite(pid) || pid <= 0) return showAlert(alertId, 'Si afecta a un proyecto, elegí cuál.', 'error');
    payload.project_id = pid;
    // Compartir el avance con Gestión: antes / después / incremento.
    if (progress) {
      payload.progress_before = progress.before;
      payload.progress_after = progress.after;
      payload.progress_delta = progress.delta;
    }
  }
  const btn = document.getElementById('btn-save-devlog');
  if (btn) { btn.disabled = true; btn.textContent = 'Guardando…'; }
  try {
    let res;
    if (editingDevlogId) {
      res = await fetch(API_BASE + `/ows-devlogs/${editingDevlogId}`, {
        method: 'PATCH',
        headers: adminHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(payload)
      });
    } else {
      res = await fetch(API_BASE + '/ows-devlogs', {
        method: 'POST',
        headers: adminHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(payload)
      });
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);

    // Sincronizar el % de Gestión con lo que el devlog acaba de aplicar.
    if (data.development && data.development.project_id) {
      const i = devProgressCache.findIndex((d) => Number(d.project_id) === Number(data.development.project_id));
      if (i >= 0) devProgressCache[i] = { ...devProgressCache[i], ...data.development };
      else devProgressCache.push({ project_id: data.development.project_id, percent: data.development.percent, updated_by: data.development.updated_by, updated_at: data.development.updated_at });
      renderDevList();
    } else if (progress && payload.project_id) {
      // El servidor no devolvió development: se sincroniza igual en local.
      const i = devProgressCache.findIndex((d) => Number(d.project_id) === Number(payload.project_id));
      if (i >= 0) devProgressCache[i] = { ...devProgressCache[i], percent: progress.after, updated_by: getCurrentAdminName(), updated_at: new Date().toISOString() };
      renderDevList();
    }

    closeDevlogModal();
    const bumped = progress && progress.delta > 0;
    showToast(bumped
      ? `Devlog guardado ✔ · ${devlogProjectName || 'El proyecto'}: ${fmtPct(progress.before)} → ${fmtPct(progress.after)} (${fmtDelta(progress.delta)})`
      : (editingDevlogId ? 'Devlog actualizado ✔' : 'Devlog creado ✔'));
    loadDevlogs();
    // El devlog puede haber aplicado %: se recarga el historial de avances
    // para que la bitácora de 14 días registre el movimiento de hoy.
    loadProjectActivity();
  } catch (err) {
    showAlert(alertId, err.message || 'Error al guardar.', 'error');
    if (btn) btn.disabled = false;
  }
}

// Modal crear/editar devlog — render del paso 1
function renderDevlogForm() {
  const body = document.getElementById('devlog-modal-body');
  if (!body) return;
  const d = editingDevlogId ? devlogsCache.find((x) => Number(x.id) === Number(editingDevlogId)) : null;
  const affects = d ? !!d.affects_project : false;
  body.innerHTML = `
    <div class="devmodal-head">
      <div class="devmodal-icon">📝</div>
      <div class="devmodal-head-info">
        <h3 class="devmodal-title">${d ? 'Editar devlog' : 'Crear Devlog'}</h3>
        <p class="modal-tagline">${d ? escapeHtml(d.title) : 'Nueva entrada del registro de desarrollo'}</p>
      </div>
    </div>
    <div class="devstep-tag">Paso 1 de 2 · ¿Qué se hizo?</div>
    <div class="field-group">
      <label for="devlog-title">Título *</label>
      <input type="text" id="devlog-title" placeholder="Ej: Avance del prototipo secreto" maxlength="160" required value="${escapeHtml(d?.title || '')}" autocomplete="off" />
    </div>
    <div class="field-group">
      <label for="devlog-reason">¿Por qué este devlog? *</label>
      <textarea id="devlog-reason" rows="3" maxlength="2000" placeholder="Motivo del cambio, qué se hizo y por qué…" required>${escapeHtml(d?.reason || '')}</textarea>
    </div>
    <div class="field-group">
      <label>¿Afecta a un proyecto?</label>
      <div class="check-row">
        <label class="check-item"><input type="checkbox" id="devlog-affects" ${affects ? 'checked' : ''} data-adm-ev="change" data-adm="onDevlogAffectsChange" /> Sí, afecta a un proyecto</label>
      </div>
    </div>
    <div class="field-group" id="devlog-project-group" ${affects ? '' : 'style="display:none"'}>
      <label for="devlog-project">¿A cuál proyecto?</label>
      <select id="devlog-project" ${affects ? '' : 'disabled'}>
        ${devlogProjectOptions(d?.project_id)}
      </select>
    </div>
    <div class="field-group">
      <label for="devlog-details">Detalles / etc. (opcional)</label>
      <textarea id="devlog-details" rows="3" maxlength="5000" placeholder="Versiones, notas internas, próximos pasos…">${escapeHtml(d?.details || '')}</textarea>
    </div>
    <p class="dev-next-hint" id="dev-next-hint"></p>
    <div id="devlog-form-alert" class="alert-box hidden"></div>
    <button type="button" class="btn btn-primary btn-block" id="btn-save-devlog" data-adm-ev="click" data-adm="devlogNextStep">Continuar →</button>
  `;
  updateDevlogNextHint();
}

function updateDevlogNextHint() {
  const hint = document.getElementById('dev-next-hint');
  if (!hint) return;
  const affects = !!(document.getElementById('devlog-affects') && document.getElementById('devlog-affects').checked);
  const sel = document.getElementById('devlog-project');
  const pid = Number(sel ? sel.value : 0);
  const btn = document.getElementById('btn-save-devlog');
  if (btn) {
    btn.textContent = affects ? 'Continuar →' : (editingDevlogId ? '💾 Guardar cambios' : '📝 Crear Devlog');
  }
  if (!affects) {
    hint.innerHTML = 'No afecta a ningún proyecto: se guarda directo, sin tocar porcentajes.';
    return;
  }
  const name = pid > 0 ? devlogProjectLabel(pid) : '—';
  const cur = pid > 0 ? devlogCurrentPercent(pid) : 0;
  hint.innerHTML = `En el paso 2 te preguntamos cuánto aumentó <b>${escapeHtml(name)}</b> (hoy está en <b>${fmtPct(cur)}</b>) y te mostramos el % final antes de confirmar.`;
}

function openDevlogForm(editId) {
  const modal = document.getElementById('devlog-modal');
  if (!modal) return;
  const d = editId != null ? devlogsCache.find((x) => Number(x.id) === Number(editId)) : null;
  editingDevlogId = d ? Number(d.id) : null;
  devlogStep = 1;
  devlogProjectPercent = 0;
  devlogProjectName = '';
  renderDevlogForm();
  modal.classList.remove('hidden');
  document.body.style.overflow = 'hidden';
  setTimeout(() => { const t = document.getElementById('devlog-title'); if (t) t.focus(); }, 50);
}

// Modal ver detalle del devlog
function viewDevlog(id) {
  const modal = document.getElementById('devlog-modal');
  const body = document.getElementById('devlog-modal-body');
  if (!modal || !body) return;
  const d = devlogsCache.find((x) => Number(x.id) === Number(id));
  if (!d) return showToast('⚠️ Devlog no encontrado');
  const fresh = isDevlogFresh(d);
  body.innerHTML = `
    <div class="devmodal-head">
      <div class="devmodal-icon">📝</div>
      <div class="devmodal-head-info">
        <h3 class="devmodal-title">${escapeHtml(d.title)}</h3>
        <p class="modal-tagline">👤 ${escapeHtml(d.created_by || '—')} · 📅 ${escapeHtml(d.created_at ? new Date(d.created_at).toLocaleString('es-ES') : '—')}</p>
        <div class="devmodal-tags">
          ${fresh ? '<span class="devlog-new-badge">🆕 Nuevo</span>' : ''}
          ${d.affects_project ? `<span class="status-pill status-admin-only">🎯 ${escapeHtml(d.project_name || 'Proyecto')}</span>` : '<span class="status-pill status-off">Sin proyecto asociado</span>'}
        </div>
      </div>
    </div>
    <div class="modal-about">
      <h4 class="modal-about-title">¿Por qué este devlog?</h4>
      <p class="modal-about-text">${escapeHtml(d.reason || '—')}</p>
    </div>
    ${d.details ? `<div class="modal-about"><h4 class="modal-about-title">Detalles</h4><p class="modal-about-text">${escapeHtml(d.details)}</p></div>` : ''}
    ${d.progress_after != null ? (() => {
      const after = round2(d.progress_after);
      const before = round2(Math.max(0, Math.min(after, d.progress_before ?? after)));
      const delta = round2(after - before);
      return `
      <div class="modal-about dev-log-progress">
        <h4 class="modal-about-title">📈 Impacto en el progreso</h4>
        <div class="dev-confirm-flow is-detail">
          <div class="dev-confirm-box is-before"><small>Anterior</small><strong>${fmtPct(before)}</strong></div>
          <span class="dev-confirm-arrow">→</span>
          <div class="dev-confirm-box is-after"><small>Final</small><strong>${fmtPct(after)}</strong></div>
          <span class="dev-confirm-delta ${delta > 0 ? 'is-up' : 'is-none'}">${delta > 0 ? fmtDelta(delta) : 'sin cambios'}</span>
        </div>
        <div class="dev-confirm-bar"><div class="dev-confirm-fill" style="width:${after}%"></div></div>
        <p class="dev-confirm-note">Este avance quedó aplicado en el porcentaje de <b>${escapeHtml(d.project_name || 'el proyecto')}</b> dentro de Gestión.</p>
      </div>`;
    })() : (d.progress_delta ? `
      <div class="modal-about dev-log-progress">
        <h4 class="modal-about-title">📈 Impacto en el progreso</h4>
        <p class="modal-about-text" title="Avance del día (sin antes/después registrados)">${fmtDelta(round2(d.progress_delta))} en el día.</p>
      </div>` : '')}
    <div class="dev-step-actions">
      <button class="btn btn-ghost" data-adm-ev="click" data-adm="openDevlogForm" data-adm-a0="r:${d.id}">✏️ Editar</button>
      <button class="btn btn-danger" data-adm-ev="click" data-adm="admCloseDevlogAndDelete" data-adm-a0="r:${d.id}">🗑️ Eliminar</button>
    </div>
  `;
  modal.classList.remove('hidden');
  document.body.style.overflow = 'hidden';
}

function closeDevlogModal() {
  const modal = document.getElementById('devlog-modal');
  if (modal) modal.classList.add('hidden');
  document.body.style.overflow = '';
  editingDevlogId = null;
  devlogStep = 1;
  devlogProjectPercent = 0;
  devlogProjectName = '';
}

async function deleteDevlog(id) {
  const d = devlogsCache.find((x) => Number(x.id) === Number(id));
  if (!confirm(`¿Eliminar el devlog "${d?.title || '#' + id}" permanentemente?`)) return;
  try {
    const res = await fetch(API_BASE + `/ows-devlogs/${id}`, {
      method: 'DELETE',
      headers: adminHeaders()
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    showToast('Devlog eliminado');
    loadDevlogs();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

// =======================================================
// INCIDENTES — status page + registro de incidentes
// Un "incidente" es un problema del estudio que un admin reporta: el
// desarrollo se trabó, el desarrollo está demasiado lento, se cayó el
// server, hay problemas de red, etc.
// El ciclo de vida es: se reporta → queda ACTIVO en la status page → el
// admin lo va actualizando (investigando → identificado → en observación)
// → lo finaliza → pasa al REGISTRO con su hora de inicio y de fin.
// Endpoints (solo-admin): GET/POST /ows-incidents, PATCH/DELETE
// /ows-incidents/:id, POST /ows-incidents/:id/updates | /resolve | /reopen.
// =======================================================

let incidentsCache = [];
let incidentsSummary = null;
let editingIncidentId = null;
let incidentLogFilter = 'all';
let incidentLogSearch = '';
let incidentTickTimer = null;
// Modal: 'view' (detalle + línea de tiempo), 'resolve' (finalizar) o
// 'reopen' (reabrir). El detalle vive en el modal; el alta/edición de
// campos largos, en el formulario de la sub-sección principal.
let incidentModalMode = 'view';
let incidentModalId = null;

// Metadatos de los tres ejes del incidente. Cada tipo de problema tiene su
// icono para reconocerlo de un vistazo en la status page y el registro.
const INC_CATEGORY_META = {
  development: { icon: '🧑‍💻', label: 'Desarrollo' },
  performance: { icon: '🐌', label: 'Velocidad' },
  server: { icon: '🖥️', label: 'Servidor / API' },
  network: { icon: '🌐', label: 'Red' },
  build: { icon: '📦', label: 'Builds' },
  other: { icon: '🧩', label: 'Otro' }
};

// Gravedad: define el color del incidente y el de la banner general.
const INC_SEVERITY_META = {
  minor: { icon: '🟢', label: 'Menor', rank: 1 },
  major: { icon: '🟠', label: 'Mayor', rank: 2 },
  critical: { icon: '🔴', label: 'Crítico', rank: 3 }
};

// Estado global del status page. El título de la banner sale de acá.
const INC_STATE_META = {
  operational: { icon: '🟢', title: 'Todo operativo', sub: 'No hay ningún incidente abierto. Si algo falla, reportalo y la luz baja en el momento.' },
  minor: { icon: '🟡', title: 'Incidencias menores', sub: 'Hay problemas abiertos de gravedad menor. Se puede seguir usando, pero algo anda lento o molesto.' },
  major: { icon: '🟠', title: 'Servicio degradado', sub: 'Hay un problema mayor abierto: parte del ecosistema no funciona o tarda demasiado.' },
  critical: { icon: '🔴', title: 'Incidente crítico en curso', sub: 'Hay un problema crítico abierto: algo está caído o inutilizable.' }
};

// Estados por los que pasa un incidente antes de finalizarse.
const INC_STATUS_META = {
  investigating: { icon: '🔎', label: 'Investigando' },
  identified: { icon: '🎯', label: 'Causa identificada' },
  monitoring: { icon: '👀', label: 'En observación' },
  resolved: { icon: '✅', label: 'Resuelto' }
};

function incCat(key) {
  return INC_CATEGORY_META[key] || { icon: '🧩', label: 'Otro' };
}
function incSev(key) {
  return INC_SEVERITY_META[key] || { icon: '🟠', label: 'Mayor', rank: 2 };
}
function incStatus(key) {
  return INC_STATUS_META[key] || { icon: '🔎', label: 'Investigando' };
}

// ── Fechas y duraciones ──
function fmtIncidentDateTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString('es-ES', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit'
  });
}

function fmtIncidentClock(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

// Duración legible: "45s" · "12m 30s" · "3h 07m" · "2d 4h".
function fmtIncidentDuration(ms) {
  // Number(null) y Number('') son 0, no NaN: sin este chequeo una duración
  // ausente se mostraría como "0s" en vez de "—".
  if (ms === null || ms === undefined || ms === '') return '—';
  const n = Number(ms);
  if (!Number.isFinite(n) || n < 0) return '—';
  const s = Math.floor(n / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ${String(m % 60).padStart(2, '0')}m`;
  const d = Math.floor(h / 24);
  return `${d}d ${h % 24}h`;
}

function fmtIncidentAgo(iso) {
  const t = iso ? new Date(iso).getTime() : NaN;
  if (!Number.isFinite(t)) return '—';
  const diff = Math.max(0, Date.now() - t);
  if (diff < 45000) return 'recién';
  if (diff < 3600000) return `hace ${Math.max(1, Math.round(diff / 60000))} min`;
  if (diff < 86400000) {
    const h = Math.max(1, Math.round(diff / 3600000));
    return `hace ${h} ${h === 1 ? 'hora' : 'horas'}`;
  }
  const d = Math.max(1, Math.round(diff / 86400000));
  return `hace ${d} ${d === 1 ? 'día' : 'días'}`;
}

// <input type="datetime-local"> habla en hora local sin zona; estas dos
// funciones hacen la traducción en los dos sentidos sin desfases.
function toLocalInputValue(iso) {
  const d = iso ? new Date(iso) : new Date();
  if (Number.isNaN(d.getTime())) return '';
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}
function fromLocalInputValue(value) {
  const s = String(value || '').trim();
  if (!s) return '';
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? '' : d.toISOString();
}

function getIncident(id) {
  return incidentsCache.find((x) => Number(x.id) === Number(id)) || null;
}
function openIncidents() {
  return incidentsCache.filter((i) => i && i.is_open);
}
function resolvedIncidents() {
  return incidentsCache.filter((i) => i && !i.is_open);
}
// Abiertos primero y, entre ellos, el peor primero (crítico > mayor > menor);
// a igual gravedad, el más nuevo arriba.
function openIncidentsSorted() {
  return openIncidents().slice().sort((a, b) => {
    const r = incSev(b.severity).rank - incSev(a.severity).rank;
    if (r) return r;
    return new Date(b.started_at || 0) - new Date(a.started_at || 0);
  });
}

// ═══════════════════════════════════════════════
// CARGA
// ═══════════════════════════════════════════════

async function loadIncidents(manual) {
  if (!(await requireAuth())) return;
  try {
    const res = await adminFetch(API_BASE + '/ows-incidents?limit=200');
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    incidentsCache = Array.isArray(data.incidents) ? data.incidents : [];
    incidentsSummary = data.summary && typeof data.summary === 'object' ? data.summary : null;
    syncIncidentProjectOptions();
    renderIncidents();
    startIncidentClock();
    if (manual) {
      showToast(`✔ Estado actualizado: ${openIncidents().length} en curso · ${resolvedIncidents().length} en el registro`);
    }
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

// El cronómetro de los incidentes abiertos corre solo: en vez de repintar la
// lista cada segundo (que rompería el foco de los textarea), solo se refresca
// el texto de los .inc-elapsed que ya están en pantalla.
function startIncidentClock() {
  if (incidentTickTimer) return;
  incidentTickTimer = setInterval(() => {
    if (!document.querySelector('.inc-elapsed[data-since]')) return;
    document.querySelectorAll('.inc-elapsed[data-since]').forEach((el) => {
      const since = Number(el.dataset.since || 0);
      if (!Number.isFinite(since)) return;
      el.textContent = fmtIncidentDuration(Date.now() - since);
    });
  }, 1000);
}

function renderIncidents() {
  renderIncidentBanner();
  renderIncidentComponents();
  renderIncidentLive();
  renderIncidentLog();
  updateIncidentFormMode();
}

// ── Banner: la luz general del ecosistema ──
function renderIncidentBanner() {
  const banner = document.getElementById('inc-banner');
  const title = document.getElementById('inc-banner-title');
  const sub = document.getElementById('inc-banner-sub');
  if (!banner || !title || !sub) return;
  const s = incidentsSummary;
  const open = openIncidents();
  const state = (s && INC_STATE_META[s.state]) ? s.state : (open.length ? 'major' : 'operational');
  const meta = INC_STATE_META[state] || INC_STATE_META.operational;
  banner.dataset.state = state;
  title.textContent = `${meta.icon} ${meta.title}`;

  // Debajo del estado va lo que conviene mirar de entrada: qué está caído y
  // hace cuánto.
  const worst = openIncidentsSorted()[0];
  let detail = meta.sub;
  if (worst) {
    const c = incCat(worst.category);
    detail = `${worst.severity === 'critical' ? 'Crítico' : worst.severity === 'major' ? 'Mayor' : 'Menor'} en ${c.label.toLowerCase()}: “${worst.title}” · ${fmtIncidentAgo(worst.started_at)}.`;
    if (open.length > 1) detail += ` Y ${open.length - 1} ${open.length - 1 === 1 ? 'incidente más' : 'incidentes más'} abierto(s).`;
  }
  sub.textContent = detail;

  const openBadge = document.getElementById('inc-open-badge');
  if (openBadge) {
    openBadge.textContent = open.length
      ? `🔴 ${open.length} en curso`
      : '✅ 0 en curso';
    openBadge.className = `status-pill ${open.length ? 'status-admin-only' : 'status-on'}`;
  }
  const sevBadge = document.getElementById('inc-sev-badge');
  if (sevBadge) {
    const crit = open.filter((i) => i.severity === 'critical').length;
    const maj = open.filter((i) => i.severity === 'major').length;
    const min = open.filter((i) => i.severity === 'minor').length;
    sevBadge.textContent = crit || maj || min ? `⚠️ ${crit}🔴 ${maj}🟠 ${min}🟢` : '⚠️ sin gravedad activa';
  }
  const mttrBadge = document.getElementById('inc-mttr-badge');
  if (mttrBadge) {
    // El incidente abierto más viejo es el que más duele: ese es el número
    // que hay que mirar de entrada.
    const longest = open.reduce((acc, i) => Math.max(acc, Number(i.duration_ms || 0)), 0);
    mttrBadge.textContent = open.length ? `⏱ más viejo: ${fmtIncidentDuration(longest)}` : '⏱ —';
  }
  const updatedBadge = document.getElementById('inc-updated-badge');
  if (updatedBadge) {
    const last = s?.last_update_at || incidentsCache[0]?.last_update_at || null;
    updatedBadge.textContent = last ? `↻ actualizado ${fmtIncidentAgo(last)}` : '↻ sin movimientos';
  }
}

// ── Luces por componente (una por tipo de problema) ──
function renderIncidentComponents() {
  const box = document.getElementById('inc-components');
  if (!box) return;
  let comps = Array.isArray(incidentsSummary?.components) ? incidentsSummary.components : [];
  if (!comps.length) {
    comps = Object.keys(INC_CATEGORY_META).map((category) => ({ category, state: 'operational', open_count: 0 }));
  }
  box.innerHTML = comps.map((c) => {
    const meta = incCat(c.category);
    const count = Number(c.open_count || 0);
    const worst = incSev(c.worst_severity);
    const state = count ? (c.worst_severity || 'major') : 'operational';
    const line = count
      ? `${count} ${count === 1 ? 'incidente abierto' : 'incidentes abiertos'} · ${worst.label}`
      : 'Sin incidentes abiertos';
    return `
      <div class="inc-comp" data-state="${escapeHtml(state)}">
        <span class="inc-comp-dot" aria-hidden="true"></span>
        <div class="inc-comp-body">
          <span class="inc-comp-name">${meta.icon} ${escapeHtml(meta.label)}</span>
          <span class="inc-comp-line">${escapeHtml(line)}</span>
        </div>
        <span class="inc-comp-pill">${count ? `${count} 🔴` : '🟢'}</span>
      </div>`;
  }).join('');
}

// ═══════════════════════════════════════════════
// INCIDENTES EN CURSO
// ═══════════════════════════════════════════════

function incidentStatusOptions(selected) {
  return ['investigating', 'identified', 'monitoring']
    .map((k) => {
      const m = incStatus(k);
      return `<option value="${k}"${k === selected ? ' selected' : ''}>${m.icon} ${escapeHtml(m.label)}</option>`;
    }).join('');
}

function incidentCardHtml(i) {
  const cat = incCat(i.category);
  const sev = incSev(i.severity);
  const st = incStatus(i.status);
  const updates = Array.isArray(i.updates) ? i.updates : [];
  const sinceMs = i.started_at ? new Date(i.started_at).getTime() : Date.now();
  const isLive = !!i.is_open;
  // Historial apilado: una tarjeta por actualización, en orden cronológico
  // (la nueva queda abajo, justo encima del formulario). Ya no se reemplaza.
  const historyHtml = updates.length ? `
    <div class="inc-card-history">
      ${updates.map((u, idx) => {
        const m = incStatus(u?.status);
        const tag = idx === 0
          ? `Reporte inicial · ${fmtIncidentAgo(u?.at)}`
          : `Actualización #${idx + 1} · ${fmtIncidentAgo(u?.at)}`;
        return `
        <div class="inc-card-last">
          <span class="inc-last-tag">${m.icon} ${escapeHtml(tag)} · ${escapeHtml(m.label)}</span>
          <p class="inc-last-text">${escapeHtml(u?.body || '')}</p>
          <span class="inc-last-by">👤 ${escapeHtml(u?.author || '—')}</span>
        </div>`;
      }).join('')}
    </div>` : '';
  return `
  <article class="inc-card" data-severity="${escapeHtml(i.severity)}" data-state="${escapeHtml(i.status)}">
    <span class="inc-card-stripe" aria-hidden="true"></span>
    <div class="inc-card-main">
      <div class="inc-card-top">
        <div class="inc-card-pills">
          <span class="inc-pill is-sev">${sev.icon} ${escapeHtml(sev.label)}</span>
          <span class="inc-pill is-cat">${cat.icon} ${escapeHtml(cat.label)}</span>
          <span class="inc-pill is-status">${st.icon} ${escapeHtml(st.label)}</span>
          ${i.project_name ? `<span class="inc-pill is-proj">🎯 ${escapeHtml(i.project_name)}</span>` : ''}
          <span class="inc-pill is-updates">💬 ${i.update_count || updates.length}</span>
        </div>
        <div class="inc-card-clock">
          <span class="inc-elapsed" data-since="${sinceMs}">${fmtIncidentDuration(Date.now() - sinceMs)}</span>
          <small>${isLive ? `en curso desde ${escapeHtml(fmtIncidentDateTime(i.started_at))}` : `terminado ${escapeHtml(fmtIncidentDateTime(i.resolved_at))}`}</small>
        </div>
      </div>

      <h3 class="inc-card-title" role="button" tabindex="0" data-adm-ev="click" data-adm="viewIncident" data-adm-a0="r:${i.id}">${escapeHtml(i.title)}</h3>
      ${i.details ? `<p class="inc-card-text">${escapeHtml(i.details)}</p>` : ''}
      ${i.impact ? `<p class="inc-card-impact"><b>Impacto:</b> ${escapeHtml(i.impact)}</p>` : ''}
      ${i.resolution ? `<p class="inc-card-resolution"><b>Cierre:</b> ${escapeHtml(i.resolution)}</p>` : ''}

      ${historyHtml}

      ${isLive ? `
        <div class="inc-quick">
          <label class="inc-quick-label" for="inc-q-note-${i.id}">➕ Actualización del reporte</label>
          <textarea id="inc-q-note-${i.id}" class="inc-quick-note" rows="2" maxlength="2000" placeholder="¿Qué cambió? Escribí acá el avance: el incidente sigue abierto, solo se le agrega esta nota a la línea de tiempo."></textarea>
          <div class="inc-quick-foot">
            <select id="inc-q-status-${i.id}" class="inc-quick-status">${incidentStatusOptions(i.status === 'resolved' ? 'investigating' : i.status)}</select>
            <button type="button" class="btn btn-primary btn-sm" data-adm-ev="click" data-adm="addIncidentUpdate" data-adm-a0="r:${i.id}">💬 Agregar actualización</button>
            <span class="inc-quick-hint">El incidente queda activo hasta que lo finalices.</span>
          </div>
        </div>` : ''}

      <div class="inc-card-actions">
        <button class="btn btn-ghost btn-sm" data-adm-ev="click" data-adm="viewIncident" data-adm-a0="r:${i.id}" title="Ver detalle y línea de tiempo">👁️ Detalle</button>
        <button class="btn btn-ghost btn-sm" data-adm-ev="click" data-adm="openIncidentForm" data-adm-a0="r:${i.id}" title="Editar título, tipo, gravedad y descripción">✏️ Editar</button>
        ${isLive
          ? `<button class="btn btn-primary btn-sm" data-adm-ev="click" data-adm="openResolveForm" data-adm-a0="r:${i.id}" title="Finalizar y mandar al registro">✅ Finalizar</button>
             <button class="btn btn-danger btn-sm" data-adm-ev="click" data-adm="deleteIncident" data-adm-a0="r:${i.id}" title="Eliminar definitivamente">🗑️</button>`
          : `<button class="btn btn-primary btn-sm" data-adm-ev="click" data-adm="reopenIncident" data-adm-a0="r:${i.id}" title="Volver a ponerlo en curso">♻️ Reabrir</button>`}
      </div>
    </div>
  </article>`;
}

function renderIncidentLive() {
  const box = document.getElementById('inc-live-list');
  if (!box) return;
  const open = openIncidentsSorted();
  const badge = document.getElementById('inc-live-badge');
  if (badge) {
    badge.textContent = open.length ? `🔴 ${open.length} abiertos` : '✅ 0 abiertos';
    badge.className = `status-pill ${open.length ? 'status-admin-only' : 'status-on'}`;
  }
  const longestBadge = document.getElementById('inc-live-longest');
  if (longestBadge) {
    const longest = open.reduce((acc, i) => Math.max(acc, Number(i.duration_ms || 0)), 0);
    longestBadge.textContent = open.length ? `⏱ el más viejo: ${fmtIncidentDuration(longest)}` : '⏱ —';
  }
  if (!open.length) {
    box.innerHTML = `
      <div class="glass-card inc-allclear">
        <span class="inc-allclear-icon">✅</span>
        <h3 class="inc-allclear-title">Nada abierto</h3>
        <p class="inc-allclear-sub">No hay ningún incidente en curso. Cuando algo falle, reportalo arriba: la luz del componente baja sola y queda activado hasta que lo finalices.</p>
        <button class="btn btn-ghost btn-sm" data-adm-ev="click" data-adm="focusIncidentForm">🚨 Reportar un problema</button>
      </div>`;
    return;
  }
  box.innerHTML = open.map(incidentCardHtml).join('');
}

// ═══════════════════════════════════════════════
// REGISTRO DE INCIDENTES (los ya finalizados)
// ═══════════════════════════════════════════════

function setIncidentFilter(f) {
  incidentLogFilter = Object.prototype.hasOwnProperty.call(INC_CATEGORY_META, f) ? f : 'all';
  document.querySelectorAll('[data-incfilter]').forEach((b) => {
    b.classList.toggle('active', b.getAttribute('data-incfilter') === incidentLogFilter);
  });
  renderIncidentLog();
}

function filterIncidentLog() {
  const el = document.getElementById('inc-log-search');
  incidentLogSearch = el ? el.value.trim().toLowerCase() : '';
  renderIncidentLog();
}

function renderIncidentLog() {
  const body = document.getElementById('inc-log-body');
  const empty = document.getElementById('inc-log-empty');
  if (!body) return;

  const all = resolvedIncidents().slice().sort(
    (a, b) => new Date(b.resolved_at || b.started_at || 0) - new Date(a.resolved_at || a.started_at || 0)
  );

  // Contadores del encabezado (sobre el registro completo, sin filtrar).
  const totalBadge = document.getElementById('inc-log-badge');
  if (totalBadge) {
    totalBadge.textContent = `📜 ${all.length} ${all.length === 1 ? 'resuelto' : 'resueltos'}`;
  }
  const totalTimeBadge = document.getElementById('inc-log-total');
  const avgBadge = document.getElementById('inc-log-avg');
  const sum = all.reduce((acc, i) => acc + (Number(i.duration_ms) || 0), 0);
  if (totalTimeBadge) totalTimeBadge.textContent = all.length ? `⏱ total: ${fmtIncidentDuration(sum)}` : '⏱ —';
  if (avgBadge) avgBadge.textContent = all.length ? `📊 promedio: ${fmtIncidentDuration(sum / all.length)}` : '📊 —';

  const q = incidentLogSearch;
  const rows = all.filter((i) => {
    if (incidentLogFilter !== 'all' && i.category !== incidentLogFilter) return false;
    if (!q) return true;
    const hay = [
      i.title, i.details, i.resolution, i.project_name,
      incCat(i.category).label, incSev(i.severity).label, i.created_by
    ].join(' ').toLowerCase();
    return hay.includes(q);
  });

  if (!rows.length) {
    body.innerHTML = '';
    if (empty) {
      empty.classList.remove('hidden');
      const t = empty.querySelector('.news-empty-title');
      const s = empty.querySelector('.news-empty-sub');
      if (!all.length) {
        if (t) t.textContent = 'Todavía no hay incidentes resueltos';
        if (s) s.textContent = 'Cuando finalices uno aparece acá con su hora de inicio y de fin.';
      } else {
        if (t) t.textContent = 'Nada coincide con el filtro';
        if (s) s.textContent = 'Probá con otro tipo de problema o limpiá la búsqueda.';
      }
    }
    return;
  }
  if (empty) empty.classList.add('hidden');

  body.innerHTML = rows.map((i) => {
    const cat = incCat(i.category);
    const sev = incSev(i.severity);
    return `
      <tr class="inc-row" data-severity="${escapeHtml(i.severity)}" data-adm-ev="click" data-adm="viewIncident" data-adm-a0="r:${i.id}" role="button" tabindex="0" title="Ver detalle">
        <td>
          <span class="inc-row-title">${escapeHtml(i.title)}</span>
          <span class="inc-row-sub">${i.project_name ? `🎯 ${escapeHtml(i.project_name)} · ` : ''}${i.update_count || 0} 💬</span>
        </td>
        <td data-label="Tipo"><span class="inc-pill is-cat">${cat.icon} ${escapeHtml(cat.label)}</span></td>
        <td data-label="Gravedad"><span class="inc-pill is-sev">${sev.icon} ${escapeHtml(sev.label)}</span></td>
        <td data-label="Inicio" class="inc-row-time">
          <strong>${escapeHtml(fmtIncidentDateTime(i.started_at))}</strong>
          <small>${escapeHtml(fmtIncidentAgo(i.started_at))}</small>
        </td>
        <td data-label="Fin" class="inc-row-time">
          <strong>${escapeHtml(fmtIncidentDateTime(i.resolved_at))}</strong>
          <small>${escapeHtml(fmtIncidentAgo(i.resolved_at))}</small>
        </td>
        <td data-label="Duración"><span class="inc-row-dur">⏱ ${escapeHtml(fmtIncidentDuration(i.duration_ms))}</span></td>
        <td class="inc-row-actions" data-adm-stop="1">
          <button class="btn btn-ghost btn-mini" title="Ver detalle" data-adm-ev="click" data-adm="viewIncident" data-adm-a0="r:${i.id}">👁️</button>
          <button class="btn btn-primary btn-mini" title="Reabrir el incidente" data-adm-ev="click" data-adm="reopenIncident" data-adm-a0="r:${i.id}">♻️</button>
        </td>
      </tr>`;
  }).join('');
}

// ═══════════════════════════════════════════════
// FORMULARIO — reportar / editar
// ═══════════════════════════════════════════════

function syncIncidentProjectOptions() {
  const sel = document.getElementById('inc-project');
  if (!sel) return;
  const keep = sel.value;
  // Se reutiliza el listado de proyectos del Devlog (solo-admin + disponibles).
  sel.innerHTML = devlogProjectOptions(keep ? Number(keep) : null);
}

function onIncidentProjectChange() {
  const chk = document.getElementById('inc-affects-project');
  const group = document.getElementById('inc-project-group');
  const sel = document.getElementById('inc-project');
  const on = !!(chk && chk.checked);
  if (group) group.classList.toggle('hidden', !on);
  if (sel) sel.disabled = !on;
  renderIncidentPreview();
}

function updateIncidentCounters() {
  const pairs = [['inc-title', 'inc-title-count', 120], ['inc-details', 'inc-details-count', 2000]];
  pairs.forEach(([fieldId, countId, max]) => {
    const f = document.getElementById(fieldId);
    const c = document.getElementById(countId);
    if (f && c) c.textContent = `${f.value.length}/${max}`;
  });
  renderIncidentPreview();
}

function readIncidentDraft() {
  const cat = document.querySelector('input[name="inc-category"]:checked');
  const sev = document.querySelector('input[name="inc-severity"]:checked');
  const aff = document.getElementById('inc-affects-project');
  const proj = document.getElementById('inc-project');
  const details = document.getElementById('inc-details');
  const impact = document.getElementById('inc-impact');
  const started = document.getElementById('inc-started-at');
  return {
    title: (document.getElementById('inc-title')?.value || '').trim(),
    category: cat ? cat.value : 'development',
    severity: sev ? sev.value : 'major',
    affects_project: !!(aff && aff.checked),
    project_id: (aff && aff.checked && proj && !proj.disabled) ? Number(proj.value || 0) : 0,
    details: details ? details.value.trim() : '',
    impact: impact ? impact.value.trim() : '',
    started_at: started ? fromLocalInputValue(started.value) : ''
  };
}

// Vista previa: el incidente tal como se vería en la status page.
function renderIncidentPreview() {
  const box = document.getElementById('inc-preview');
  if (!box) return;
  const d = readIncidentDraft();
  const cat = incCat(d.category);
  const sev = incSev(d.severity);
  const proj = d.project_id ? (() => {
    const all = [...(manageProjectsCache || []), ...(projectsCache || [])];
    const p = all.find((x) => Number(x?.id) === d.project_id);
    return p ? (p.name || p.slug || `#${d.project_id}`) : '';
  })() : '';
  box.innerHTML = `
    <div class="inc-prev" data-severity="${escapeHtml(d.severity)}">
      <span class="inc-prev-stripe" aria-hidden="true"></span>
      <div class="inc-prev-body">
        <div class="inc-card-pills">
          <span class="inc-pill is-sev">${sev.icon} ${escapeHtml(sev.label)}</span>
          <span class="inc-pill is-cat">${cat.icon} ${escapeHtml(cat.label)}</span>
          <span class="inc-pill is-status">🔎 Investigando</span>
          ${proj ? `<span class="inc-pill is-proj">🎯 ${escapeHtml(proj)}</span>` : ''}
        </div>
        <h3 class="inc-prev-title">${d.title ? escapeHtml(d.title) : '<span class="inc-prev-empty">Tu título aparecerá acá</span>'}</h3>
        <p class="inc-card-text">${d.details ? escapeHtml(d.details) : '<span class="inc-prev-empty">Contá qué está pasando y va a quedar escrito acá.</span>'}</p>
        ${d.impact ? `<p class="inc-card-impact"><b>Impacto:</b> ${escapeHtml(d.impact)}</p>` : ''}
        <div class="inc-prev-foot">
          <span class="inc-elapsed" data-since="${Date.now()}">0s</span>
          <small>${d.started_at ? `empezó ${escapeHtml(fmtIncidentDateTime(d.started_at))}` : 'empezando ahora'}</small>
        </div>
      </div>
    </div>
    <p class="form-hint inc-prev-note">Se activa apenas lo guardes. En la sub-sección <b>En curso</b> le vas agregando actualizaciones y, cuando lo resolvés, lo finalizás.</p>`;
}

function updateIncidentFormMode() {
  const title = document.getElementById('inc-form-title');
  const btn = document.getElementById('btn-save-incident');
  const cancel = document.getElementById('btn-cancel-incident');
  const editing = editingIncidentId != null;
  if (title) title.textContent = editing ? `✏️ Editando el incidente #${editingIncidentId}` : '🚨 Reportar un problema';
  if (btn) btn.textContent = editing ? '💾 Guardar cambios' : '🚨 Activar incidente';
  if (cancel) cancel.classList.toggle('hidden', !editing);
}

function resetIncidentForm() {
  editingIncidentId = null;
  ['inc-title', 'inc-details', 'inc-impact', 'inc-started-at'].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  document.querySelectorAll('input[name="inc-severity"]').forEach((r) => { r.checked = r.value === 'major'; });
  document.querySelectorAll('input[name="inc-category"]').forEach((r) => { r.checked = r.value === 'development'; });
  const aff = document.getElementById('inc-affects-project');
  if (aff) aff.checked = false;
  onIncidentProjectChange();
  hideAlert('inc-form-alert');
  updateIncidentFormMode();
  updateIncidentCounters();
  try { closeFormModal(); } catch (_) {}
}

function focusIncidentForm() {
  openIncidentForm(null);
}

// Abre el formulario de la sub-sección principal: vacío para reportar uno
// nuevo, o poblado si se pasa el id de un incidente a editar.
function openIncidentForm(editId) {
  switchAdminTab('incidents');
  switchAdminSub('incidents', 'main');
  const i = editId != null && editId !== '' ? getIncident(editId) : null;
  if (editId != null && editId !== '' && !i) {
    showToast('⚠️ Incidente no encontrado');
    return;
  }
  editingIncidentId = i ? Number(i.id) : null;

  const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
  set('inc-title', i ? i.title : '');
  set('inc-details', i ? i.details : '');
  set('inc-impact', i ? i.impact : '');
  // Al editar se propone la hora con la que se creó: si el admin la corrige
  // queda corregida, y si no, se manda tal cual (el backend la conserva).
  set('inc-started-at', toLocalInputValue(i ? i.started_at : null));
  const aff = document.getElementById('inc-affects-project');
  if (aff) aff.checked = !!(i && (i.project_id || i.project_name));
  const sel = document.getElementById('inc-project');
  if (sel && i && i.project_id) sel.value = String(i.project_id);
  document.querySelectorAll('input[name="inc-severity"]').forEach((r) => {
    r.checked = r.value === ((i && i.severity) || 'major');
  });
  document.querySelectorAll('input[name="inc-category"]').forEach((r) => {
    r.checked = r.value === ((i && i.category) || 'development');
  });
  onIncidentProjectChange();
  hideAlert('inc-form-alert');
  updateIncidentFormMode();
  updateIncidentCounters();
  openFormModal('incident');
}

async function saveIncident(e) {
  if (e) e.preventDefault();
  hideAlert('inc-form-alert');
  const d = readIncidentDraft();
  if (!d.title) {
    showAlert('inc-form-alert', 'El título es obligatorio.', 'error');
    document.getElementById('inc-title')?.focus();
    return;
  }
  if (!d.details) {
    showAlert('inc-form-alert', 'Contá qué está pasando: es lo que se lee en el reporte.', 'error');
    document.getElementById('inc-details')?.focus();
    return;
  }
  if (d.affects_project && (!Number.isFinite(d.project_id) || d.project_id <= 0)) {
    showAlert('inc-form-alert', 'Si afecta a un proyecto, elegí cuál.', 'error');
    document.getElementById('inc-project')?.focus();
    return;
  }
  const body = {
    title: d.title,
    details: d.details,
    impact: d.impact,
    category: d.category,
    severity: d.severity,
    project_id: d.affects_project ? d.project_id : null,
    started_at: d.started_at || null
  };
  const editing = editingIncidentId != null;
  const url = editing ? `${API_BASE}/ows-incidents/${editingIncidentId}` : `${API_BASE}/ows-incidents`;
  const btn = document.getElementById('btn-save-incident');
  if (btn) { btn.disabled = true; btn.textContent = editing ? '💾 Guardando…' : '🚨 Activando…'; }
  try {
    const res = await adminFetch(url, {
      method: editing ? 'PATCH' : 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    showToast(editing
      ? `✔ Incidente #${data.incident?.id || editingIncidentId} actualizado`
      : `🚨 Incidente activado: “${data.incident?.title || d.title}”`);
    resetIncidentForm();
    await loadIncidents();
  } catch (err) {
    showAlert('inc-form-alert', err.message, 'error');
  } finally {
    if (btn) { btn.disabled = false; updateIncidentFormMode(); }
  }
}

// ═══════════════════════════════════════════════
// ACCIONES SOBRE UN INCIDENTE
// ═══════════════════════════════════════════════

// Actualización rápida: solo agrega una nota a la línea de tiempo y deja el
// incidente tal cual estaba. Es el "ir actualizando poco a poco".
async function addIncidentUpdate(id, fromModal) {
  const fieldId = fromModal ? 'inc-modal-note' : `inc-q-note-${id}`;
  const statusId = fromModal ? 'inc-modal-status' : `inc-q-status-${id}`;
  const note = (document.getElementById(fieldId)?.value || '').trim();
  const status = document.getElementById(statusId)?.value || 'investigating';
  if (!note) {
    showToast('⚠️ Escribí la actualización antes de guardarla.');
    document.getElementById(fieldId)?.focus();
    return;
  }
  try {
    const res = await adminFetch(`${API_BASE}/ows-incidents/${id}/updates`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ body: note, status })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    showToast(`💬 Actualización agregada (${data.incident?.update_count || 0} en total)`);
    const box = document.getElementById(fieldId);
    if (box) box.value = '';
    await loadIncidents();
    if (incidentModalId === Number(id) && incidentModalMode === 'view') {
      viewIncident(id);
    }
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

// ═══════════════════════════════════════════════
// MODAL — detalle, línea de tiempo, finalizar y reabrir
// ═══════════════════════════════════════════════

function incidentTimelineHtml(updates) {
  const list = Array.isArray(updates) ? updates : [];
  if (!list.length) return '<p class="inc-timeline-empty">Todavía no hay actualizaciones en este incidente.</p>';
  return `<ol class="inc-timeline">${list.slice().reverse().map((u) => {
    const m = incStatus(u.status);
    return `
      <li class="inc-tl-item" data-state="${escapeHtml(u.status)}">
        <span class="inc-tl-dot" aria-hidden="true"></span>
        <div class="inc-tl-body">
          <div class="inc-tl-head">
            <span class="inc-tl-status">${m.icon} ${escapeHtml(m.label)}</span>
            <span class="inc-tl-time" title="${escapeHtml(fmtIncidentDateTime(u.at))}">${escapeHtml(fmtIncidentClock(u.at))} · ${escapeHtml(fmtIncidentAgo(u.at))}</span>
          </div>
          <p class="inc-tl-text">${escapeHtml(u.body)}</p>
          <span class="inc-tl-author">👤 ${escapeHtml(u.author || '—')}</span>
        </div>
      </li>`;
  }).join('')}</ol>`;
}

function openIncidentModal() {
  const modal = document.getElementById('inc-modal');
  if (modal) modal.classList.remove('hidden');
  document.body.style.overflow = 'hidden';
}

function closeIncidentModal() {
  const modal = document.getElementById('inc-modal');
  if (modal) modal.classList.add('hidden');
  document.body.style.overflow = '';
  incidentModalMode = 'view';
  incidentModalId = null;
}

// Detalle completo: descripción, impacto, horas, línea de tiempo, y las
// acciones para actualizar, finalizar o reabrir.
function viewIncident(id) {
  const body = document.getElementById('inc-modal-body');
  if (!body) return;
  const i = getIncident(id);
  if (!i) {
    showToast('⚠️ Incidente no encontrado');
    return;
  }
  incidentModalMode = 'view';
  incidentModalId = Number(id);
  const cat = incCat(i.category);
  const sev = incSev(i.severity);
  const st = incStatus(i.status);
  const updates = Array.isArray(i.updates) ? i.updates : [];
  const isLive = !!i.is_open;
  const sinceMs = i.started_at ? new Date(i.started_at).getTime() : Date.now();
  // La duración sale del servidor (que ya la calcula); si falta, se deriva de
  // las horas. Así el modal y la tabla del registro nunca se contradicen.
  const liveMs = isLive ? Date.now() - sinceMs : Number(i.duration_ms ?? 0);

  body.innerHTML = `
    <div class="devmodal-head">
      <div class="devmodal-icon">${cat.icon}</div>
      <div class="devmodal-head-info">
        <h3 class="devmodal-title">${escapeHtml(i.title)}</h3>
        <p class="modal-tagline">#${i.id} · ${sev.icon} ${escapeHtml(sev.label)} · ${st.icon} ${escapeHtml(st.label)} ${i.project_name ? `· 🎯 ${escapeHtml(i.project_name)}` : ''}</p>
        <div class="devmodal-tags">
          <span class="inc-pill is-cat">${cat.icon} ${escapeHtml(cat.label)}</span>
          <span class="inc-pill is-sev">${sev.icon} ${escapeHtml(sev.label)}</span>
          ${i.project_name ? `<span class="inc-pill is-proj">🎯 ${escapeHtml(i.project_name)}</span>` : ''}
          <span class="inc-pill is-updates">💬 ${i.update_count || updates.length}</span>
        </div>
      </div>
    </div>

    <div class="inc-modal-times">
      <div class="inc-time-box">
        <small>🕐 Inicio</small>
        <strong>${escapeHtml(fmtIncidentDateTime(i.started_at))}</strong>
        <span>${escapeHtml(fmtIncidentAgo(i.started_at))}</span>
      </div>
      <div class="inc-time-box ${i.resolved_at ? 'is-end' : 'is-live'}">
        <small>${i.resolved_at ? '🏁 Fin' : '⏳ En curso'}</small>
        <strong>${i.resolved_at ? escapeHtml(fmtIncidentDateTime(i.resolved_at)) : '<span class="inc-elapsed" data-since="' + sinceMs + '">' + escapeHtml(fmtIncidentDuration(Date.now() - sinceMs)) + '</span>'}</strong>
        <span>${i.resolved_at ? escapeHtml(fmtIncidentAgo(i.resolved_at)) : 'sigue abierto'}</span>
      </div>
      <div class="inc-time-box">
        <small>⏱ Duración</small>
        <strong>${escapeHtml(fmtIncidentDuration(liveMs))}</strong>
        <span>${i.resolved_at ? 'total del incidente' : 'hasta ahora'}</span>
      </div>
    </div>

    ${i.details ? `<div class="modal-about"><h4 class="modal-about-title">¿Qué está pasando?</h4><p class="modal-about-text">${escapeHtml(i.details)}</p></div>` : ''}
    ${i.impact ? `<div class="modal-about"><h4 class="modal-about-title">Impacto</h4><p class="modal-about-text">${escapeHtml(i.impact)}</p></div>` : ''}
    ${i.resolution ? `<div class="modal-about"><h4 class="modal-about-title">🔎 Cómo se resolvió</h4><p class="modal-about-text">${escapeHtml(i.resolution)}</p></div>` : ''}

    ${isLive ? `
      <div class="inc-quick is-modal">
        <label class="inc-quick-label" for="inc-modal-note">➕ Actualizar el reporte</label>
        <textarea id="inc-modal-note" class="inc-quick-note" rows="2" maxlength="2000" placeholder="¿Qué cambió? La nota se suma a la línea de tiempo y el incidente sigue activo."></textarea>
        <div class="inc-quick-foot">
          <select id="inc-modal-status" class="inc-quick-status">${incidentStatusOptions(i.status === 'resolved' ? 'investigating' : i.status)}</select>
          <button type="button" class="btn btn-primary btn-sm" data-adm-ev="click" data-adm="addIncidentUpdate" data-adm-a0="r:${i.id}" data-adm-a1="b:1">💬 Agregar actualización</button>
          <span class="inc-quick-hint">Queda activo hasta que lo finalices.</span>
        </div>
      </div>` : ''}

    <div class="modal-about inc-tl-wrap">
      <h4 class="modal-about-title">📜 Línea de tiempo <span class="inc-tl-count">${updates.length} ${updates.length === 1 ? 'entrada' : 'entradas'}</span></h4>
      ${incidentTimelineHtml(updates)}
    </div>

    <p class="inc-modal-foot">Creado por <b>${escapeHtml(i.created_by || '—')}</b> · última edición de <b>${escapeHtml(i.updated_by || i.created_by || '—')}</b> ${escapeHtml(fmtIncidentAgo(i.updated_at || i.created_at))}</p>

    <div class="dev-step-actions">
      ${isLive
        ? `<button class="btn btn-primary" data-adm-ev="click" data-adm="openResolveForm" data-adm-a0="r:${i.id}">✅ Finalizar incidente</button>
           <button class="btn btn-ghost" data-adm-ev="click" data-adm="openIncidentForm" data-adm-a0="r:${i.id}">✏️ Editar</button>`
        : `<button class="btn btn-primary" data-adm-ev="click" data-adm="admCloseIncidentAndReopen" data-adm-a0="r:${i.id}">♻️ Reabrir</button>`}
      <button class="btn btn-danger" data-adm-ev="click" data-adm="deleteIncident" data-adm-a0="r:${i.id}">🗑️ Eliminar</button>
      <button class="btn btn-ghost" data-adm-ev="click" data-adm="closeIncidentModal">Cerrar</button>
    </div>`;
  openIncidentModal();
}

// Finalizar: acá se pone la hora de fin (editable) y el texto de cierre. Al
// guardar, el incidente sale de la status page y entra al registro.
function openResolveForm(id) {
  const body = document.getElementById('inc-modal-body');
  if (!body) return;
  const i = getIncident(id);
  if (!i) {
    showToast('⚠️ Incidente no encontrado');
    return;
  }
  incidentModalMode = 'resolve';
  incidentModalId = Number(id);
  const cat = incCat(i.category);
  const sev = incSev(i.severity);
  const updates = Array.isArray(i.updates) ? i.updates : [];
  const sinceMs = i.started_at ? new Date(i.started_at).getTime() : Date.now();

  body.innerHTML = `
    <div class="devmodal-head">
      <div class="devmodal-icon">✅</div>
      <div class="devmodal-head-info">
        <h3 class="devmodal-title">Finalizar incidente</h3>
        <p class="modal-tagline">${escapeHtml(i.title)}</p>
        <div class="devmodal-tags">
          <span class="inc-pill is-cat">${cat.icon} ${escapeHtml(cat.label)}</span>
          <span class="inc-pill is-sev">${sev.icon} ${escapeHtml(sev.label)}</span>
          <span class="inc-pill is-updates">💬 ${i.update_count || updates.length}</span>
        </div>
      </div>
    </div>

    <div class="inc-modal-times">
      <div class="inc-time-box">
        <small>🕐 Inicio</small>
        <strong>${escapeHtml(fmtIncidentDateTime(i.started_at))}</strong>
        <span>${escapeHtml(fmtIncidentAgo(i.started_at))}</span>
      </div>
      <div class="inc-time-box is-live">
        <small>⏳ Lleva abierto</small>
        <strong><span class="inc-elapsed" data-since="${sinceMs}">${escapeHtml(fmtIncidentDuration(Date.now() - sinceMs))}</span></strong>
        <span>hasta ahora</span>
      </div>
    </div>

    <div class="field-group">
      <label for="inc-resolve-at">Hora de fin *</label>
      <input type="datetime-local" id="inc-resolve-at" value="${toLocalInputValue(new Date())}" />
      <p class="form-hint">Por defecto es el momento en que estás finalizando. Corregila si el problema ya se había resuelto antes.</p>
    </div>
    <div class="field-group">
      <label for="inc-resolve-note">Cómo se resolvió <span class="opt-tag">opcional</span></label>
      <textarea id="inc-resolve-note" rows="3" maxlength="2000" placeholder="Causa y arreglo: qué era, qué se hizo, y si queda algo pendiente. Queda como última entrada de la línea de tiempo."></textarea>
    </div>
    <div class="inc-resolve-warn">
      <b>⚠️ Al finalizar</b> el incidente sale de la status page, deja de contar como problema abierto y entra en el <b>registro de incidentes</b> con su hora de inicio, la de fin y la duración total. Podés reabrirlo después si vuelve a pasar.
    </div>
    <div class="dev-step-actions">
      <button class="btn btn-primary" id="btn-resolve-incident" data-adm-ev="click" data-adm="resolveIncident">✅ Confirmar y finalizar</button>
      <button class="btn btn-ghost" data-adm-ev="click" data-adm="viewIncident" data-adm-a0="r:${i.id}">Volver</button>
      <button class="btn btn-ghost" data-adm-ev="click" data-adm="closeIncidentModal">Cancelar</button>
    </div>`;
  openIncidentModal();
  startIncidentClock();
}

async function resolveIncident() {
  const id = incidentModalId;
  if (!id) return;
  const at = fromLocalInputValue(document.getElementById('inc-resolve-at')?.value || '');
  if (!at) {
    showToast('⚠️ Poné la hora de fin del incidente.');
    return;
  }
  const note = (document.getElementById('inc-resolve-note')?.value || '').trim();
  const btn = document.getElementById('btn-resolve-incident');
  if (btn) { btn.disabled = true; btn.textContent = '✅ Finalizando…'; }
  try {
    const res = await adminFetch(`${API_BASE}/ows-incidents/${id}/resolve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ resolved_at: at, resolution: note })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    const inc = data.incident;
    showToast(`✅ Incidente finalizado · duró ${fmtIncidentDuration(inc?.duration_ms)}`);
    closeIncidentModal();
    await loadIncidents();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
    if (btn) { btn.disabled = false; btn.textContent = '✅ Confirmar y finalizar'; }
  }
}

async function reopenIncident(id) {
  const i = getIncident(id);
  if (!i) return showToast('⚠️ Incidente no encontrado');
  const reason = prompt(
    `¿Por qué se reabre el incidente “${i.title}”?\n\n` +
    'Se vuelve a poner activo en la status page y queda con las actualizaciones que tenía.',
    'El problema volvió a aparecer'
  );
  if (reason === null) return; // cancelado
  try {
    const res = await adminFetch(`${API_BASE}/ows-incidents/${id}/reopen`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason: String(reason || '').trim() })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    showToast('♻️ Incidente reabierto: volvió a la status page');
    await loadIncidents();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

async function deleteIncident(id) {
  const i = getIncident(id);
  if (!i) return showToast('⚠️ Incidente no encontrado');
  if (!confirm(`¿Eliminar el incidente “${i.title}” con toda su línea de tiempo?\n\nEsta acción no se puede deshacer.`)) return;
  try {
    const res = await adminFetch(`${API_BASE}/ows-incidents/${id}`, { method: 'DELETE' });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    showToast('🗑️ Incidente eliminado');
    closeIncidentModal();
    await loadIncidents();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

// =======================================================
// INFORMES — avisos activos hasta terminar (NO incidentes)
// Un "informe" es un estado del estudio que queda ACTIVO hasta que se termina:
// el desarrollo se pausa por un rato, hay problemas internos del equipo, baja
// el ritmo, o cualquier aviso general. Se publica → sigue activo (con notas
// en la línea de tiempo) → se finaliza → pasa al HISTORIAL con inicio y fin.
// Endpoints (solo-admin): GET/POST /ows-reports, PATCH/DELETE
// /ows-reports/:id, POST /ows-reports/:id/updates | /resolve | /reopen.
// Reutiliza las clases visuales inc-* y los formateadores de incidentes.
// =======================================================

let reportsCache = [];
let reportsSummary = null;
let editingReportId = null;
let reportLogFilter = 'all';
let reportLogSearch = '';
let reportModalMode = 'view';
let reportModalId = null;

// Tipos de informe: qué situación describe. Cada uno tiene su icono.
const REP_KIND_META = {
  pause: { icon: '⏸️', label: 'Pausa' },
  internal: { icon: '🏢', label: 'Interno' },
  progress: { icon: '🐢', label: 'Ritmo' },
  info: { icon: '📢', label: 'Aviso' },
  other: { icon: '🧩', label: 'Otro' }
};

// Colores de acento: la barra, los pill y los bloques del informe.
// Mismo vocabulario que el backend (OWS_REPORT_ACCENTS). El vacío es el
// ámbar de siempre.
const REP_ACCENTS = [
  { key: '', label: 'Ámbar (por defecto)' },
  { key: 'amber', label: 'Ámbar' },
  { key: 'violet', label: 'Violeta' },
  { key: 'sky', label: 'Celeste' },
  { key: 'emerald', label: 'Verde' },
  { key: 'rose', label: 'Rojo' }
];

// Elementos de diseño: la paleta del constructor de informes.
// Cada tipo define su icono, su nombre y qué campos se editan.
const REP_BLOCK_META = {
  heading: { icon: '🔖', label: 'Subtítulo', hint: 'Un título intermedio que ordena el informe' },
  text:    { icon: '📄', label: 'Párrafo', hint: 'Texto explicativo de varias líneas' },
  list:    { icon: '•',  label: 'Lista', hint: 'Viñetas, una por línea' },
  stat:    { icon: '📊', label: 'Dato', hint: 'Un número grande con su etiqueta' },
  callout: { icon: '📣', label: 'Aviso', hint: 'Recuadro destacado para lo importante' },
  image:   { icon: '🖼️', label: 'Imagen', hint: 'Imagen por URL con su pie' },
  tags:    { icon: '🏷️', label: 'Etiquetas', hint: 'Chips cortos, uno por línea' },
  divider: { icon: '➖', label: 'Separador', hint: 'Una línea para separar bloques' }
};

function repBlockMeta(type) {
  return REP_BLOCK_META[type] || { icon: '🧩', label: 'Elemento', hint: '' };
}

// Borrador de elementos mientras se arma/edita el informe.
let repBlocksDraft = [];
let repBlockSeq = 0;
// Modal de actualización: a qué informe se le está escribiendo la nota.
let repUpdateModalId = null;

function repKind(key) {
  return REP_KIND_META[key] || { icon: '🧩', label: 'Otro' };
}

function getReport(id) {
  return reportsCache.find((x) => Number(x.id) === Number(id)) || null;
}
function openReports() {
  return reportsCache.filter((r) => r && r.is_open);
}
function resolvedReports() {
  return reportsCache.filter((r) => r && !r.is_open);
}
function openReportsSorted() {
  return openReports().slice().sort(
    (a, b) => new Date(b.started_at || 0) - new Date(a.started_at || 0)
  );
}

// ═══════════════════════════════════════════════
// CARGA
// ═══════════════════════════════════════════════

async function loadReports(manual) {
  if (!(await requireAuth())) return;
  try {
    const res = await adminFetch(API_BASE + '/ows-reports?limit=200');
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    reportsCache = Array.isArray(data.reports) ? data.reports : [];
    reportsSummary = data.summary && typeof data.summary === 'object' ? data.summary : null;
    syncReportProjectOptions();
    renderReports();
    startIncidentClock();
    if (manual) {
      showToast(`✔ Informes actualizados: ${openReports().length} activos · ${resolvedReports().length} en el historial`);
    }
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

function renderReports() {
  renderReportBlockPalette();
  renderReportAccents();
  renderReportBlocks();
  renderReportBanner();
  renderReportKinds();
  renderReportLive();
  renderReportLog();
  updateReportFormMode();
}

// ── Banner: cuántos informes siguen activos ──
function renderReportBanner() {
  const banner = document.getElementById('rep-banner');
  const title = document.getElementById('rep-banner-title');
  const sub = document.getElementById('rep-banner-sub');
  if (!banner || !title || !sub) return;
  const open = openReports();
  // Sin semáforo de gravedad (no son errores): verde si no hay nada, ámbar si hay.
  banner.dataset.state = open.length ? 'major' : 'operational';
  if (!open.length) {
    title.textContent = '📋 Sin informes activos';
    sub.textContent = 'No hay ningún aviso vigente. Cuando el desarrollo se pause o haya novedades internas, publicalo y queda activo hasta que termine.';
  } else {
    const first = openReportsSorted()[0];
    const k = repKind(first.kind);
    title.textContent = `📋 ${open.length} ${open.length === 1 ? 'informe activo' : 'informes activos'}`;
    sub.textContent = `Vigente ahora: ${k.icon} ${k.label} — “${first.title}” · ${fmtIncidentAgo(first.started_at)}.${open.length > 1 ? ` Y ${open.length - 1} más.` : ''}`;
  }

  const openBadge = document.getElementById('rep-open-badge');
  if (openBadge) {
    openBadge.textContent = open.length ? `📋 ${open.length} activos` : '📋 0 activos';
    openBadge.className = `status-pill ${open.length ? 'status-admin-only' : 'status-on'}`;
  }
  const kindBadge = document.getElementById('rep-kind-badge');
  if (kindBadge) {
    if (!open.length) {
      kindBadge.textContent = '— sin tipos activos —';
    } else {
      const counts = {};
      open.forEach((r) => { counts[r.kind] = (counts[r.kind] || 0) + 1; });
      kindBadge.textContent = Object.entries(counts)
        .map(([k, n]) => `${repKind(k).icon} ${n}`)
        .join(' · ');
    }
  }
  const timeBadge = document.getElementById('rep-time-badge');
  if (timeBadge) {
    const longest = open.reduce((acc, r) => Math.max(acc, Number(r.duration_ms || 0)), 0);
    timeBadge.textContent = open.length ? `⏱ el más viejo: ${fmtIncidentDuration(longest)}` : '⏱ —';
  }
  const updatedBadge = document.getElementById('rep-updated-badge');
  if (updatedBadge) {
    const s = reportsSummary;
    const last = s?.last_update_at || reportsCache[0]?.last_update_at || null;
    updatedBadge.textContent = last ? `↻ actualizado ${fmtIncidentAgo(last)}` : '↻ sin movimientos';
  }
}

// ── Tipos de informe (conteo por tipo) ──
function renderReportKinds() {
  const box = document.getElementById('rep-kinds');
  if (!box) return;
  const open = openReports();
  box.innerHTML = Object.keys(REP_KIND_META).map((kind) => {
    const meta = repKind(kind);
    const own = open.filter((r) => r.kind === kind);
    const count = own.length;
    const state = count ? 'major' : 'operational';
    const line = count
      ? `${count} ${count === 1 ? 'informe activo' : 'informes activos'}`
      : 'Sin informes activos';
    return `
      <div class="inc-comp" data-state="${escapeHtml(state)}">
        <span class="inc-comp-dot" aria-hidden="true"></span>
        <div class="inc-comp-body">
          <span class="inc-comp-name">${meta.icon} ${escapeHtml(meta.label)}</span>
          <span class="inc-comp-line">${escapeHtml(line)}</span>
        </div>
        <span class="inc-comp-pill">${count ? `${count} 📋` : '—'}</span>
      </div>`;
  }).join('');
}

// ═══════════════════════════════════════════════
// ELEMENTOS DE DISEÑO — constructor de bloques
// ═══════════════════════════════════════════════
// El informe se arma con elementos (bloques) que se guardan en orden.
// Uno los escribe (borrador), otro los dibuja ya guardados (preview,
// tarjetas y detalle). Mismo HTML para los dos: lo que se ve armando es
// lo que se ve publicado.

function repBlockList(value) {
  if (Array.isArray(value)) return value.map((s) => String(s || '').trim()).filter(Boolean);
  return String(value || '').split('\n').map((s) => s.trim()).filter(Boolean);
}

// El acento vacío significa "el de siempre" (ámbar): se normaliza acá para
// que el CSS tenga siempre una clase con la que pintar.
function repAccentKey(value) {
  const v = String(value || '');
  return REP_ACCENTS.some((a) => a.key === v && a.key) ? v : 'amber';
}

// Dibuja los bloques tal como se ven en el informe publicado.
function reportBlocksHtml(blocks) {
  const list = Array.isArray(blocks) ? blocks : [];
  if (!list.length) return '';
  return `<div class="rep-blocks">${list.map((b) => {
    const type = String(b?.type || '');
    const meta = repBlockMeta(type);
    if (!REP_BLOCK_META[type]) return '';
    if (type === 'divider') return '<hr class="rep-blk rep-blk-div" />';
    if (type === 'heading') return `<h4 class="rep-blk rep-blk-heading">${escapeHtml(String(b.text || ''))}</h4>`;
    if (type === 'text') return `<p class="rep-blk rep-blk-text">${escapeHtml(String(b.text || ''))}</p>`;
    if (type === 'callout') return `<div class="rep-blk rep-blk-callout"><span class="rep-blk-callout-icon">${meta.icon}</span><p>${escapeHtml(String(b.text || ''))}</p></div>`;
    if (type === 'list') {
      const items = repBlockList(b.items);
      if (!items.length) return '';
      return `<ul class="rep-blk rep-blk-list">${items.map((i) => `<li>${escapeHtml(i)}</li>`).join('')}</ul>`;
    }
    if (type === 'tags') {
      const items = repBlockList(b.items);
      if (!items.length) return '';
      return `<div class="rep-blk rep-blk-tags">${items.map((i) => `<span class="rep-tag">${escapeHtml(i)}</span>`).join('')}</div>`;
    }
    if (type === 'stat') {
      return `<div class="rep-blk rep-blk-stat"><strong>${escapeHtml(String(b.value || ''))}</strong><small>${escapeHtml(String(b.label || ''))}</small></div>`;
    }
    if (type === 'image') {
      const url = String(b.image_url || b.url || '');
      return `<figure class="rep-blk rep-blk-image">
        <img src="${escapeHtml(url)}" alt="${escapeHtml(String(b.caption || ''))}" loading="lazy" data-adm-err="rm" />
        ${b.caption ? `<figcaption>${escapeHtml(String(b.caption || ''))}</figcaption>` : ''}
      </figure>`;
    }
    return '';
  }).filter(Boolean).join('')}</div>`;
}

// ── Paleta de elementos ──
function renderReportBlockPalette() {
  const box = document.getElementById('repb-palette');
  if (!box) return;
  box.innerHTML = Object.entries(REP_BLOCK_META).map(([type, meta]) => `
    <button type="button" class="repb-pal" data-adm-ev="click" data-adm="addReportBlock" data-adm-a0="s:${type}" title="${escapeHtml(meta.hint)}">
      <span class="repb-pal-icon">${meta.icon}</span>
      <span class="repb-pal-text"><b>${escapeHtml(meta.label)}</b><small>${escapeHtml(meta.hint)}</small></span>
      <span class="repb-pal-plus">＋</span>
    </button>`).join('');
}

function renderReportAccents() {
  const box = document.getElementById('rep-accent-row');
  if (!box) return;
  const current = String(document.getElementById('rep-accent')?.value || '');
  box.innerHTML = REP_ACCENTS.map((a) => `
    <button type="button" class="rep-accent${a.key === current ? ' active' : ''}${a.key ? ` is-${a.key}` : ''}"
      data-adm-ev="click" data-adm="setReportAccent" data-adm-a0="s:${a.key}" title="${escapeHtml(a.label)}">
      <span class="rep-accent-swatch"></span><small>${escapeHtml(a.label)}</small>
    </button>`).join('');
}

function setReportAccent(key) {
  const input = document.getElementById('rep-accent');
  if (input) input.value = REP_ACCENTS.some((a) => a.key === key) ? key : '';
  renderReportAccents();
  renderReportPreview();
}

// ── Borrador: agregar / mover / duplicar / borrar ──
function addReportBlock(type) {
  if (!REP_BLOCK_META[type]) return;
  if (repBlocksDraft.length >= 40) {
    showToast('⚠️ Un informe no puede tener más de 40 elementos.');
    return;
  }
  const id = `b${++repBlockSeq}`;
  const base = { id, type };
  if (type === 'list') base.items = ['Primer punto', 'Segundo punto'];
  else if (type === 'tags') base.items = ['desarrollo', 'equipo'];
  else if (type === 'divider') { /* sin campos */ }
  else if (type === 'stat') { base.value = '0'; base.label = 'personas afectadas'; }
  else if (type === 'image') { base.url = ''; base.caption = 'Captura o gráfico del informe'; }
  else if (type === 'heading') base.text = 'Nuevo subtítulo';
  else if (type === 'text') base.text = '';
  else if (type === 'callout') base.text = 'Esto es lo más importante del informe.';
  repBlocksDraft.push(base);
  renderReportBlocks();
  renderReportPreview();
  const first = document.querySelector(`[data-repblock="${id}"] input, [data-repblock="${id}"] textarea`);
  if (first) { try { first.focus(); } catch (_) {} }
}

function repBlockField(id, field) {
  const b = repBlocksDraft.find((x) => x.id === id);
  if (!b) return;
  const raw = this.value;
  if (field === 'items') b.items = raw.split('\n');
  else b[field] = raw;
  renderReportPreview();
}

function moveReportBlock(id, dir) {
  const i = repBlocksDraft.findIndex((x) => x.id === id);
  if (i < 0) return;
  const j = i + dir;
  if (j < 0 || j >= repBlocksDraft.length) return;
  const [b] = repBlocksDraft.splice(i, 1);
  repBlocksDraft.splice(j, 0, b);
  renderReportBlocks();
  renderReportPreview();
}

function duplicateReportBlock(id) {
  const i = repBlocksDraft.findIndex((x) => x.id === id);
  if (i < 0) return;
  if (repBlocksDraft.length >= 40) {
    showToast('⚠️ Un informe no puede tener más de 40 elementos.');
    return;
  }
  const copy = JSON.parse(JSON.stringify(repBlocksDraft[i]));
  copy.id = `b${++repBlockSeq}`;
  repBlocksDraft.splice(i + 1, 0, copy);
  renderReportBlocks();
  renderReportPreview();
}

function removeReportBlock(id) {
  repBlocksDraft = repBlocksDraft.filter((x) => x.id !== id);
  renderReportBlocks();
  renderReportPreview();
}

function clearReportBlocks() {
  if (!repBlocksDraft.length) return;
  if (!confirm('¿Quitar todos los elementos del informe?')) return;
  repBlocksDraft = [];
  renderReportBlocks();
  renderReportPreview();
}

// ── Lista editable de elementos ──
// Enter dentro de un campo no debe enviar el formulario: el dispatcher hace
// preventDefault cuando data-adm-key coincide, así que el handler queda vacío.
function repBlockEnterGuard() { /* solo evita el submit del formulario */ }

function reportBlocksEditorHtml() {
  if (!repBlocksDraft.length) return '';
  const guard = ' data-adm-key="Enter"';
  return repBlocksDraft.map((b, i) => {
    const meta = repBlockMeta(b.type);
    const at = `data-adm-a0="r:${b.id}"`;
    const upd = 'data-adm-ev="input|keydown" data-adm="repBlockEnterGuard"';
    const fields = (() => {
      if (b.type === 'divider') return '<p class="repb-row-note">Separador: no tiene contenido.</p>';
      if (b.type === 'list' || b.type === 'tags') {
        return `<label class="repb-field">
          <span>${b.type === 'list' ? 'Viñetas (una por línea)' : 'Etiquetas (una por línea)'}</span>
          <textarea class="inc-quick-note" rows="4"${guard} ${upd} data-adm="repBlockField" ${at} data-adm-a1="s:items">${escapeHtml(repBlockList(b.items).join('\n'))}</textarea>
        </label>`;
      }
      if (b.type === 'stat') {
        return `<div class="repb-field-row">
          <label class="repb-field"><span>Valor</span>
            <input type="text" value="${escapeHtml(String(b.value || ''))}" maxlength="160"${guard} ${upd} data-adm="repBlockField" ${at} data-adm-a1="s:value" /></label>
          <label class="repb-field"><span>Etiqueta</span>
            <input type="text" value="${escapeHtml(String(b.label || ''))}" maxlength="160"${guard} ${upd} data-adm="repBlockField" ${at} data-adm-a1="s:label" /></label>
        </div>`;
      }
      if (b.type === 'image') {
        return `<label class="repb-field"><span>URL de la imagen</span>
          <input type="url" placeholder="https://…" value="${escapeHtml(String(b.image_url || b.url || ''))}"${guard} ${upd} data-adm="repBlockField" ${at} data-adm-a1="s:url" /></label>
        <label class="repb-field"><span>Pie de imagen <span class="opt-tag">opcional</span></span>
          <input type="text" placeholder="Qué se ve en la imagen" value="${escapeHtml(String(b.caption || ''))}" maxlength="400"${guard} ${upd} data-adm="repBlockField" ${at} data-adm-a1="s:caption" /></label>`;
      }
      if (b.type === 'heading') {
        return `<label class="repb-field"><span>Subtítulo</span>
          <input type="text" value="${escapeHtml(String(b.text || ''))}" maxlength="2000"${guard} ${upd} data-adm="repBlockField" ${at} data-adm-a1="s:text" /></label>`;
      }
      const label = b.type === 'callout' ? 'Texto del aviso' : 'Párrafo';
      const rows = b.type === 'callout' ? '3' : '4';
      return `<label class="repb-field"><span>${label}</span>
        <textarea class="inc-quick-note" rows="${rows}"${guard} ${upd} data-adm="repBlockField" ${at} data-adm-a1="s:text">${escapeHtml(String(b.text || ''))}</textarea></label>`;
    })();
    return `
    <div class="repb-row is-${escapeHtml(b.type)}" data-repblock="${escapeHtml(b.id)}">
      <div class="repb-row-head">
        <span class="repb-row-order">${i + 1}</span>
        <span class="repb-row-type">${meta.icon} ${escapeHtml(meta.label)}</span>
        <span class="repb-row-tools">
          <button type="button" class="btn btn-ghost btn-mini" title="Subir" data-adm-ev="click" data-adm="moveReportBlock" data-adm-a0="r:${b.id}" data-adm-a1="n:-1"${i === 0 ? ' disabled' : ''}>↑</button>
          <button type="button" class="btn btn-ghost btn-mini" title="Bajar" data-adm-ev="click" data-adm="moveReportBlock" data-adm-a0="r:${b.id}" data-adm-a1="n:1"${i === repBlocksDraft.length - 1 ? ' disabled' : ''}>↓</button>
          <button type="button" class="btn btn-ghost btn-mini" title="Duplicar" data-adm-ev="click" data-adm="duplicateReportBlock" data-adm-a0="r:${b.id}">⧉</button>
          <button type="button" class="btn btn-ghost btn-mini" title="Quitar" data-adm-ev="click" data-adm="removeReportBlock" data-adm-a0="r:${b.id}">✕</button>
        </span>
      </div>
      <div class="repb-row-body">${fields}</div>
    </div>`;
  }).join('');
}

function renderReportBlocks() {
  const box = document.getElementById('rep-blocks');
  const empty = document.getElementById('rep-blocks-empty');
  const count = document.getElementById('rep-blocks-count');
  if (count) count.textContent = `${repBlocksDraft.length} ${repBlocksDraft.length === 1 ? 'elemento' : 'elementos'}`;
  if (empty) empty.classList.toggle('hidden', repBlocksDraft.length > 0);
  if (!box) return;
  box.innerHTML = reportBlocksEditorHtml();
}

// ═══════════════════════════════════════════════
// INFORMES ACTIVOS
// ═══════════════════════════════════════════════

function reportStatusOptions(selected) {
  return [['active', '📋 Activo'], ['monitoring', '👀 En seguimiento']]
    .map(([k, label]) => `<option value="${k}"${k === selected ? ' selected' : ''}>${label}</option>`)
    .join('');
}

function reportCardHtml(r) {
  const kind = repKind(r.kind);
  const updates = Array.isArray(r.updates) ? r.updates : [];
  const blocks = Array.isArray(r.blocks) ? r.blocks : [];
  const sinceMs = r.started_at ? new Date(r.started_at).getTime() : Date.now();
  const isLive = !!r.is_open;
  const historyHtml = updates.length ? `
    <div class="inc-card-history">
      ${updates.map((u, idx) => {
        const tag = idx === 0
          ? `Publicación · ${fmtIncidentAgo(u?.at)}`
          : `Actualización #${idx + 1} · ${fmtIncidentAgo(u?.at)}`;
        return `
        <div class="inc-card-last">
          <span class="inc-last-tag">📋 ${escapeHtml(tag)}</span>
          <p class="inc-last-text">${escapeHtml(u?.body || '')}</p>
          <span class="inc-last-by">👤 ${escapeHtml(u?.author || '—')}</span>
        </div>`;
      }).join('')}
    </div>` : '';
  const accentCls = ` is-${escapeHtml(repAccentKey(r.accent))}`;
  return `
  <article class="inc-card${accentCls}" data-severity="major" data-state="${escapeHtml(r.status)}">
    <span class="inc-card-stripe" aria-hidden="true"></span>
    <div class="inc-card-main">
      <div class="inc-card-top">
        <div class="inc-card-pills">
          <span class="inc-pill is-cat">${kind.icon} ${escapeHtml(kind.label)}</span>
          <span class="inc-pill is-status">📋 ${isLive ? 'Activo' : 'Terminado'}</span>
          ${r.project_name ? `<span class="inc-pill is-proj">🎯 ${escapeHtml(r.project_name)}</span>` : ''}
          ${blocks.length ? `<span class="inc-pill is-updates">🧱 ${blocks.length}</span>` : ''}
          <span class="inc-pill is-updates">💬 ${r.update_count || updates.length}</span>
        </div>
        <div class="inc-card-clock">
          <span class="inc-elapsed" data-since="${sinceMs}">${fmtIncidentDuration(Date.now() - sinceMs)}</span>
          <small>${isLive ? `activo desde ${escapeHtml(fmtIncidentDateTime(r.started_at))}` : `terminado ${escapeHtml(fmtIncidentDateTime(r.resolved_at))}`}</small>
        </div>
      </div>

      <h3 class="inc-card-title" role="button" tabindex="0" data-adm-ev="click" data-adm="viewReport" data-adm-a0="r:${r.id}">${escapeHtml(r.title)}</h3>
      ${r.details ? `<p class="inc-card-text">${escapeHtml(r.details)}</p>` : ''}

      ${reportBlocksHtml(blocks)}

      ${historyHtml}

      <div class="inc-card-actions">
        <button class="btn btn-ghost btn-sm" data-adm-ev="click" data-adm="viewReport" data-adm-a0="r:${r.id}" title="Ver detalle y línea de tiempo">👁️ Detalle</button>
        <button class="btn btn-ghost btn-sm" data-adm-ev="click" data-adm="openReportForm" data-adm-a0="r:${r.id}" title="Editar título, tipo, diseño y elementos">✏️ Editar</button>
        ${isLive
          ? `<button class="btn btn-primary btn-sm" data-adm-ev="click" data-adm="openReportUpdateModal" data-adm-a0="r:${r.id}" title="Escribir una actualización del informe">💬 Actualizar</button>
             <button class="btn btn-primary btn-sm" data-adm-ev="click" data-adm="openResolveReportForm" data-adm-a0="r:${r.id}" title="Terminar y mandar al historial">✅ Terminar</button>
             <button class="btn btn-danger btn-sm" data-adm-ev="click" data-adm="deleteReport" data-adm-a0="r:${r.id}" title="Eliminar definitivamente">🗑️</button>`
          : `<button class="btn btn-primary btn-sm" data-adm-ev="click" data-adm="reopenReport" data-adm-a0="r:${r.id}" title="Volver a ponerlo activo">♻️ Reactivar</button>`}
      </div>
    </div>
  </article>`;
}

function renderReportLive() {
  const box = document.getElementById('rep-live-list');
  if (!box) return;
  const open = openReportsSorted();
  const badge = document.getElementById('rep-live-badge');
  if (badge) {
    badge.textContent = open.length ? `📋 ${open.length} activos` : '📋 0 activos';
    badge.className = `status-pill ${open.length ? 'status-admin-only' : 'status-on'}`;
  }
  const longestBadge = document.getElementById('rep-live-longest');
  if (longestBadge) {
    const longest = open.reduce((acc, r) => Math.max(acc, Number(r.duration_ms || 0)), 0);
    longestBadge.textContent = open.length ? `⏱ el más viejo: ${fmtIncidentDuration(longest)}` : '⏱ —';
  }
  if (!open.length) {
    box.innerHTML = `
      <div class="glass-card inc-allclear">
        <span class="inc-allclear-icon">📋</span>
        <h3 class="inc-allclear-title">Nada activo</h3>
        <p class="inc-allclear-sub">No hay ningún informe vigente. Cuando el desarrollo se pause o haya novedades internas, publicalo arriba y queda activo hasta que lo termines.</p>
        <button class="btn btn-ghost btn-sm" data-adm-ev="click" data-adm="focusReportForm">📋 Nuevo informe</button>
      </div>`;
    return;
  }
  box.innerHTML = open.map(reportCardHtml).join('');
}

// ═══════════════════════════════════════════════
// HISTORIAL DE INFORMES (los ya terminados)
// ═══════════════════════════════════════════════

function setReportFilter(f) {
  reportLogFilter = Object.prototype.hasOwnProperty.call(REP_KIND_META, f) ? f : 'all';
  document.querySelectorAll('[data-repfilter]').forEach((b) => {
    b.classList.toggle('active', b.getAttribute('data-repfilter') === reportLogFilter);
  });
  renderReportLog();
}

function filterReportLog() {
  const el = document.getElementById('rep-log-search');
  reportLogSearch = el ? el.value.trim().toLowerCase() : '';
  renderReportLog();
}

function renderReportLog() {
  const body = document.getElementById('rep-log-body');
  const empty = document.getElementById('rep-log-empty');
  if (!body) return;

  const all = resolvedReports().slice().sort(
    (a, b) => new Date(b.resolved_at || b.started_at || 0) - new Date(a.resolved_at || a.started_at || 0)
  );

  const totalBadge = document.getElementById('rep-log-badge');
  if (totalBadge) {
    totalBadge.textContent = `📜 ${all.length} ${all.length === 1 ? 'terminado' : 'terminados'}`;
  }
  const totalTimeBadge = document.getElementById('rep-log-total');
  const avgBadge = document.getElementById('rep-log-avg');
  const sum = all.reduce((acc, r) => acc + (Number(r.duration_ms) || 0), 0);
  if (totalTimeBadge) totalTimeBadge.textContent = all.length ? `⏱ total: ${fmtIncidentDuration(sum)}` : '⏱ —';
  if (avgBadge) avgBadge.textContent = all.length ? `📊 promedio: ${fmtIncidentDuration(sum / all.length)}` : '📊 —';

  const q = reportLogSearch;
  const rows = all.filter((r) => {
    if (reportLogFilter !== 'all' && r.kind !== reportLogFilter) return false;
    if (!q) return true;
    const hay = [r.title, r.details, r.project_name, repKind(r.kind).label, r.created_by].join(' ').toLowerCase();
    return hay.includes(q);
  });

  if (!rows.length) {
    body.innerHTML = '';
    if (empty) {
      empty.classList.remove('hidden');
      const t = empty.querySelector('.news-empty-title');
      const s = empty.querySelector('.news-empty-sub');
      if (!all.length) {
        if (t) t.textContent = 'Todavía no hay informes terminados';
        if (s) s.textContent = 'Cuando finalices uno aparece acá con su hora de inicio y de fin.';
      } else {
        if (t) t.textContent = 'Nada coincide con el filtro';
        if (s) s.textContent = 'Probá con otro tipo de informe o limpiá la búsqueda.';
      }
    }
    return;
  }
  if (empty) empty.classList.add('hidden');

  body.innerHTML = rows.map((r) => {
    const kind = repKind(r.kind);
    return `
      <tr class="inc-row" data-adm-ev="click" data-adm="viewReport" data-adm-a0="r:${r.id}" role="button" tabindex="0" title="Ver detalle">
        <td>
          <span class="inc-row-title">${escapeHtml(r.title)}</span>
          <span class="inc-row-sub">${r.project_name ? `🎯 ${escapeHtml(r.project_name)} · ` : ''}${r.update_count || 0} 💬</span>
        </td>
        <td data-label="Tipo"><span class="inc-pill is-cat">${kind.icon} ${escapeHtml(kind.label)}</span></td>
        <td data-label="Inicio" class="inc-row-time">
          <strong>${escapeHtml(fmtIncidentDateTime(r.started_at))}</strong>
          <small>${escapeHtml(fmtIncidentAgo(r.started_at))}</small>
        </td>
        <td data-label="Fin" class="inc-row-time">
          <strong>${escapeHtml(fmtIncidentDateTime(r.resolved_at))}</strong>
          <small>${escapeHtml(fmtIncidentAgo(r.resolved_at))}</small>
        </td>
        <td data-label="Duración"><span class="inc-row-dur">⏱ ${escapeHtml(fmtIncidentDuration(r.duration_ms))}</span></td>
        <td class="inc-row-actions" data-adm-stop="1">
          <button class="btn btn-ghost btn-mini" title="Ver detalle" data-adm-ev="click" data-adm="viewReport" data-adm-a0="r:${r.id}">👁️</button>
          <button class="btn btn-primary btn-mini" title="Reactivar el informe" data-adm-ev="click" data-adm="reopenReport" data-adm-a0="r:${r.id}">♻️</button>
        </td>
      </tr>`;
  }).join('');
}

// ═══════════════════════════════════════════════
// FORMULARIO — publicar / editar
// ═══════════════════════════════════════════════

function syncReportProjectOptions() {
  const sel = document.getElementById('rep-project');
  if (!sel) return;
  const keep = sel.value;
  if (typeof devlogProjectOptions === 'function') {
    sel.innerHTML = devlogProjectOptions(keep ? Number(keep) : null);
  }
}

function onReportProjectChange() {
  const chk = document.getElementById('rep-affects-project');
  const group = document.getElementById('rep-project-group');
  const sel = document.getElementById('rep-project');
  const on = !!(chk && chk.checked);
  if (group) group.classList.toggle('hidden', !on);
  if (sel) sel.disabled = !on;
  renderReportPreview();
}

function updateReportCounters() {
  const pairs = [['rep-title', 'rep-title-count', 120], ['rep-details', 'rep-details-count', 2000]];
  pairs.forEach(([fieldId, countId, max]) => {
    const f = document.getElementById(fieldId);
    const c = document.getElementById(countId);
    if (f && c) c.textContent = `${f.value.length}/${max}`;
  });
  renderReportPreview();
}

function readReportDraft() {
  const kind = document.querySelector('input[name="rep-kind"]:checked');
  const aff = document.getElementById('rep-affects-project');
  const proj = document.getElementById('rep-project');
  const details = document.getElementById('rep-details');
  const started = document.getElementById('rep-started-at');
  const accent = document.getElementById('rep-accent');
  return {
    title: (document.getElementById('rep-title')?.value || '').trim(),
    kind: kind ? kind.value : 'info',
    affects_project: !!(aff && aff.checked),
    project_id: (aff && aff.checked && proj && !proj.disabled) ? Number(proj.value || 0) : 0,
    details: details ? details.value.trim() : '',
    started_at: started ? fromLocalInputValue(started.value) : '',
    accent: accent ? accent.value : '',
    blocks: repBlocksDraft.map((b) => {
      const out = { type: b.type };
      if (b.text != null) out.text = String(b.text);
      if (Array.isArray(b.items)) out.items = repBlockList(b.items);
      if (b.value != null) out.value = String(b.value);
      if (b.label != null) out.label = String(b.label);
      if (b.url != null) out.image_url = String(b.url);
      if (b.caption != null) out.caption = String(b.caption);
      return out;
    })
  };
}

function renderReportPreview() {
  const box = document.getElementById('rep-preview');
  if (!box) return;
  const d = readReportDraft();
  const kind = repKind(d.kind);
  const proj = d.project_id ? (() => {
    const all = [...(manageProjectsCache || []), ...(projectsCache || [])];
    const p = all.find((x) => Number(x?.id) === d.project_id);
    return p ? (p.name || p.slug || `#${d.project_id}`) : '';
  })() : '';
  const blocks = reportBlocksHtml(d.blocks);
  const accent = repAccentKey(d.accent);
  box.innerHTML = `
    <div class="inc-prev is-${escapeHtml(accent)}" data-severity="major">
      <span class="inc-prev-stripe" aria-hidden="true"></span>
      <div class="inc-prev-body">
        <div class="inc-card-pills">
          <span class="inc-pill is-cat">${kind.icon} ${escapeHtml(kind.label)}</span>
          <span class="inc-pill is-status">📋 Activo</span>
          ${proj ? `<span class="inc-pill is-proj">🎯 ${escapeHtml(proj)}</span>` : ''}
          ${d.blocks.length ? `<span class="inc-pill is-updates">🧱 ${d.blocks.length}</span>` : ''}
        </div>
        <h3 class="inc-prev-title">${d.title ? escapeHtml(d.title) : '<span class="inc-prev-empty">Tu título aparecerá acá</span>'}</h3>
        <p class="inc-card-text">${d.details ? escapeHtml(d.details) : '<span class="inc-prev-empty">Explicá la situación y va a quedar escrita acá.</span>'}</p>
        ${blocks}
        <div class="inc-prev-foot">
          <span class="inc-elapsed" data-since="${Date.now()}">0s</span>
          <small>${d.started_at ? `empezó ${escapeHtml(fmtIncidentDateTime(d.started_at))}` : 'empezando ahora'}</small>
        </div>
      </div>
    </div>
    <p class="form-hint inc-prev-note">Se activa apenas lo guardes. En la sub-sección <b>Activos</b> le vas agregando notas y, cuando termina, lo finalizás.</p>`;
}

function updateReportFormMode() {
  const title = document.getElementById('rep-form-title');
  const btn = document.getElementById('btn-save-report');
  const cancel = document.getElementById('btn-cancel-report');
  const editing = editingReportId != null;
  if (title) title.textContent = editing ? `✏️ Editando el informe #${editingReportId}` : '📋 Nuevo informe';
  if (btn) btn.textContent = editing ? '💾 Guardar cambios' : '📋 Activar informe';
  if (cancel) cancel.classList.toggle('hidden', !editing);
}

function resetReportForm() {
  editingReportId = null;
  ['rep-title', 'rep-details', 'rep-started-at'].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  document.querySelectorAll('input[name="rep-kind"]').forEach((r) => { r.checked = r.value === 'pause'; });
  const aff = document.getElementById('rep-affects-project');
  if (aff) aff.checked = false;
  repBlocksDraft = [];
  const accent = document.getElementById('rep-accent');
  if (accent) accent.value = '';
  renderReportBlockPalette();
  renderReportAccents();
  renderReportBlocks();
  onReportProjectChange();
  hideAlert('rep-form-alert');
  updateReportFormMode();
  updateReportCounters();
  try { closeFormModal(); } catch (_) {}
}

function focusReportForm() {
  openReportForm(null);
}

function openReportForm(editId) {
  switchAdminTab('reports');
  switchAdminSub('reports', 'main');
  const r = editId != null && editId !== '' ? getReport(editId) : null;
  if (editId != null && editId !== '' && !r) {
    showToast('⚠️ Informe no encontrado');
    return;
  }
  editingReportId = r ? Number(r.id) : null;

  const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
  set('rep-title', r ? r.title : '');
  set('rep-details', r ? r.details : '');
  set('rep-started-at', toLocalInputValue(r ? r.started_at : null));
  const aff = document.getElementById('rep-affects-project');
  if (aff) aff.checked = !!(r && (r.project_id || r.project_name));
  const sel = document.getElementById('rep-project');
  if (sel && r && r.project_id) sel.value = String(r.project_id);
  document.querySelectorAll('input[name="rep-kind"]').forEach((x) => {
    x.checked = x.value === ((r && r.kind) || 'pause');
  });
  // Elementos de diseño: se copian al borrador con ids nuevos de sesión.
  // La URL de la imagen se guarda como `url` en el borrador (el backend la
  // devuelve como `image_url`), así el campo editable siempre refleja el valor.
  repBlocksDraft = (Array.isArray(r?.blocks) ? r.blocks : []).map((b) => {
    const copy = { ...b, id: `b${++repBlockSeq}` };
    if (copy.type === 'image') {
      copy.url = String(copy.image_url || copy.url || '');
      delete copy.image_url;
    }
    return copy;
  });
  renderReportBlockPalette();
  renderReportAccents();
  renderReportBlocks();
  onReportProjectChange();
  hideAlert('rep-form-alert');
  updateReportFormMode();
  updateReportCounters();
  openFormModal('report');
}

async function saveReport(e) {
  if (e) e.preventDefault();
  hideAlert('rep-form-alert');
  const d = readReportDraft();
  if (!d.title) {
    showAlert('rep-form-alert', 'El título es obligatorio.', 'error');
    document.getElementById('rep-title')?.focus();
    return;
  }
  if (!d.details) {
    showAlert('rep-form-alert', 'Contá de qué trata el informe.', 'error');
    document.getElementById('rep-details')?.focus();
    return;
  }
  if (d.affects_project && (!Number.isFinite(d.project_id) || d.project_id <= 0)) {
    showAlert('rep-form-alert', 'Si afecta a un proyecto, elegí cuál.', 'error');
    document.getElementById('rep-project')?.focus();
    return;
  }
  // Los elementos vacíos no se guardan: se descartan con aviso en vez de
  // dejar placeholders colgando en el informe.
  const usable = d.blocks.filter((b) => {
    if (b.type === 'image') return String(b.image_url || '').trim();
    if (b.type === 'stat') return String(b.value || '').trim();
    if (b.type === 'list' || b.type === 'tags') return (b.items || []).length > 0;
    if (b.type === 'divider') return true;
    return String(b.text || '').trim();
  });
  const dropped = d.blocks.length - usable.length;

  const body = {
    title: d.title,
    details: d.details,
    kind: d.kind,
    project_id: d.affects_project ? d.project_id : null,
    started_at: d.started_at || null,
    blocks: usable,
    accent: d.accent
  };
  const editing = editingReportId != null;
  const url = editing ? `${API_BASE}/ows-reports/${editingReportId}` : `${API_BASE}/ows-reports`;
  const btn = document.getElementById('btn-save-report');
  if (btn) { btn.disabled = true; btn.textContent = editing ? '💾 Guardando…' : '📋 Activando…'; }
  try {
    const res = await adminFetch(url, {
      method: editing ? 'PATCH' : 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    if (dropped > 0) showToast(`🧹 Se descartaron ${dropped} ${dropped === 1 ? 'elemento vacío' : 'elementos vacíos'}.`);
    showToast(editing
      ? `✔ Informe #${data.report?.id || editingReportId} actualizado`
      : `📋 Informe activado: “${data.report?.title || d.title}”`);
    resetReportForm();
    await loadReports();
  } catch (err) {
    showAlert('rep-form-alert', err.message, 'error');
  } finally {
    if (btn) { btn.disabled = false; updateReportFormMode(); }
  }
}

// ═══════════════════════════════════════════════
// ACTUALIZACIONES — modal para escribir una nota
// ═══════════════════════════════════════════════
// Antes la nota se escribía en un cuadro dentro de la tarjeta (o en el
// modal de detalle). Ahora siempre se abre este modal: lugar para elegir
// el estado, plantillas rápidas y la vista previa de la entrada.

const REP_UPDATE_TEMPLATES = [
  { label: '🧘 Sin novedades', text: 'Sin novedades por ahora: la situación sigue igual y se sigue trabajando.' },
  { label: '🔧 Trabajando', text: 'Se está trabajando en esto: ' },
  { label: '🐢 Retraso', text: 'El desarrollo se está retrasando más de lo previsto: ' },
  { label: '📅 Nueva fecha', text: 'Fecha estimada actualizada: ' },
  { label: '✅ Resuelto', text: 'El problema quedó resuelto: ' },
  { label: '🚧 Sigue pausado', text: 'La pausa sigue vigente: todavía no se retoma el desarrollo.' }
];

function openReportUpdateModal(id) {
  const r = getReport(id);
  if (!r) return showToast('⚠️ Informe no encontrado');
  repUpdateModalId = Number(id);
  const kind = repKind(r.kind);

  const set = (elId, val) => { const el = document.getElementById(elId); if (el) el.textContent = val; };
  set('rep-upd-icon', kind.icon);
  set('rep-upd-title', 'Nueva actualización');
  set('rep-upd-sub', `#${r.id} · ${kind.icon} ${kind.label}${r.project_name ? ` · 🎯 ${r.project_name}` : ''} · “${r.title}”`);
  const tags = document.getElementById('rep-upd-tags');
  if (tags) {
    tags.innerHTML = `
      <span class="inc-pill is-cat">${kind.icon} ${escapeHtml(kind.label)}</span>
      <span class="inc-pill is-updates">💬 ${r.update_count || (Array.isArray(r.updates) ? r.updates.length : 0)} notas</span>
      <span class="inc-pill is-status">sigue activo</span>`;
  }

  const status = document.getElementById('rep-upd-status');
  if (status) status.value = (r.status && r.status !== 'resolved') ? r.status : 'active';
  const note = document.getElementById('rep-upd-note');
  if (note) note.value = '';
  hideAlert('rep-upd-alert');
  renderReportUpdateTemplates();
  updateReportUpdatePreview();

  const modal = document.getElementById('rep-upd-modal');
  if (modal) modal.classList.remove('hidden');
  try { document.body.style.overflow = 'hidden'; } catch (_) {}
  setTimeout(() => { try { note?.focus(); } catch (_) {} }, 90);
}

function closeReportUpdateModal() {
  const modal = document.getElementById('rep-upd-modal');
  if (modal) modal.classList.add('hidden');
  // Solo se libera el scroll si no quedó otro modal abierto detrás.
  const behind = ['rep-modal', 'form-modal'].some((m) => {
    const el = document.getElementById(m);
    return el && !el.classList.contains('hidden');
  });
  if (!behind) { try { document.body.style.overflow = ''; } catch (_) {} }
  repUpdateModalId = null;
}

function renderReportUpdateTemplates() {
  const box = document.getElementById('rep-upd-templates');
  if (!box) return;
  box.innerHTML = REP_UPDATE_TEMPLATES.map((t, i) => `
    <button type="button" class="rep-tpl" data-adm-ev="click" data-adm="applyReportUpdateTemplate" data-adm-a0="n:${i}">${escapeHtml(t.label)}</button>`).join('');
}

function applyReportUpdateTemplate(i) {
  const t = REP_UPDATE_TEMPLATES[Number(i)];
  const note = document.getElementById('rep-upd-note');
  if (!t || !note) return;
  const cur = note.value.replace(/\s+$/, '');
  note.value = cur ? `${cur}\n${t.text}` : t.text;
  updateReportUpdatePreview();
  try {
    note.focus();
    note.setSelectionRange(note.value.length, note.value.length);
  } catch (_) {}
}

function updateReportUpdatePreview() {
  const note = document.getElementById('rep-upd-note');
  const count = document.getElementById('rep-upd-count');
  if (note && count) count.textContent = `${note.value.length}/2000`;
  const box = document.getElementById('rep-upd-preview');
  if (!box) return;
  const r = repUpdateModalId != null ? getReport(repUpdateModalId) : null;
  const status = document.getElementById('rep-upd-status')?.value || 'active';
  const monitoring = status === 'monitoring';
  const text = (note?.value || '').trim();
  box.innerHTML = `
    <div class="inc-card-last${monitoring ? ' is-monitoring' : ''}">
      <span class="inc-last-tag">${monitoring ? '👀 En seguimiento' : '📋 Nota'} · recién</span>
      <p class="inc-last-text">${text ? escapeHtml(text) : '<span class="inc-prev-empty">La nota que escribas se va a ver así en la línea de tiempo.</span>'}</p>
      <span class="inc-last-by">👤 OceanandWild · ${r ? `en “${escapeHtml(r.title)}”` : ''}</span>
    </div>`;
}

async function saveReportUpdate() {
  const id = repUpdateModalId;
  if (!id) return;
  const note = (document.getElementById('rep-upd-note')?.value || '').trim();
  if (!note) {
    showAlert('rep-upd-alert', 'Escribí qué cambió antes de guardar.', 'error');
    document.getElementById('rep-upd-note')?.focus();
    return;
  }
  const status = document.getElementById('rep-upd-status')?.value || 'active';
  const btn = document.getElementById('btn-save-report-update');
  if (btn) { btn.disabled = true; btn.textContent = '💬 Guardando…'; }
  try {
    const res = await adminFetch(`${API_BASE}/ows-reports/${id}/updates`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ body: note, status })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    showToast(`💬 Actualización guardada (${data.report?.update_count || 0} en total)`);
    closeReportUpdateModal();
    await loadReports();
    if (reportModalId === Number(id) && reportModalMode === 'view') viewReport(id);
  } catch (err) {
    showAlert('rep-upd-alert', err.message, 'error');
    if (btn) { btn.disabled = false; btn.textContent = '💬 Guardar actualización'; }
  }
}

// Atajos del modal de actualización: Esc cierra · Ctrl+Enter guarda.
document.addEventListener('keydown', (e) => {
  const modal = document.getElementById('rep-upd-modal');
  if (!modal || modal.classList.contains('hidden')) return;
  if (e.key === 'Escape') { e.preventDefault(); closeReportUpdateModal(); return; }
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); saveReportUpdate(); }
});

// ═══════════════════════════════════════════════
// MODAL — detalle, línea de tiempo, terminar y reactivar
// ═══════════════════════════════════════════════

function reportTimelineHtml(updates) {
  const list = Array.isArray(updates) ? updates : [];
  if (!list.length) return '<p class="inc-timeline-empty">Todavía no hay notas en este informe.</p>';
  return `<ol class="inc-timeline">${list.slice().reverse().map((u) => {
    const monitoring = u.status === 'monitoring';
    return `
      <li class="inc-tl-item" data-state="${escapeHtml(u.status || 'active')}">
        <span class="inc-tl-dot" aria-hidden="true"></span>
        <div class="inc-tl-body">
          <div class="inc-tl-head">
            <span class="inc-tl-status">${monitoring ? '👀 En seguimiento' : '📋 Nota'}</span>
            <span class="inc-tl-time" title="${escapeHtml(fmtIncidentDateTime(u.at))}">${escapeHtml(fmtIncidentClock(u.at))} · ${escapeHtml(fmtIncidentAgo(u.at))}</span>
          </div>
          <p class="inc-tl-text">${escapeHtml(u.body)}</p>
          <span class="inc-tl-author">👤 ${escapeHtml(u.author || '—')}</span>
        </div>
      </li>`;
  }).join('')}</ol>`;
}

function openReportModal() {
  const modal = document.getElementById('rep-modal');
  if (modal) modal.classList.remove('hidden');
  document.body.style.overflow = 'hidden';
}

function closeReportModal() {
  const modal = document.getElementById('rep-modal');
  if (modal) modal.classList.add('hidden');
  document.body.style.overflow = '';
  reportModalMode = 'view';
  reportModalId = null;
}

function viewReport(id) {
  const body = document.getElementById('rep-modal-body');
  if (!body) return;
  const r = getReport(id);
  if (!r) {
    showToast('⚠️ Informe no encontrado');
    return;
  }
  reportModalMode = 'view';
  reportModalId = Number(id);
  const kind = repKind(r.kind);
  const updates = Array.isArray(r.updates) ? r.updates : [];
  const blocks = Array.isArray(r.blocks) ? r.blocks : [];
  const isLive = !!r.is_open;
  const sinceMs = r.started_at ? new Date(r.started_at).getTime() : Date.now();
  const liveMs = isLive ? Date.now() - sinceMs : Number(r.duration_ms ?? 0);
  const accentCls = r.accent ? ` is-${escapeHtml(repAccentKey(r.accent))}` : ' is-amber';

  body.innerHTML = `
    <div class="devmodal-head">
      <div class="devmodal-icon">${kind.icon}</div>
      <div class="devmodal-head-info">
        <h3 class="devmodal-title">${escapeHtml(r.title)}</h3>
        <p class="modal-tagline">#${r.id} · ${kind.icon} ${escapeHtml(kind.label)} · ${isLive ? '📋 Activo' : '✅ Terminado'} ${r.project_name ? `· 🎯 ${escapeHtml(r.project_name)}` : ''}</p>
        <div class="devmodal-tags">
          <span class="inc-pill is-cat">${kind.icon} ${escapeHtml(kind.label)}</span>
          ${r.project_name ? `<span class="inc-pill is-proj">🎯 ${escapeHtml(r.project_name)}</span>` : ''}
          ${blocks.length ? `<span class="inc-pill is-updates">🧱 ${blocks.length}</span>` : ''}
          <span class="inc-pill is-updates">💬 ${r.update_count || updates.length}</span>
        </div>
      </div>
    </div>

    <div class="inc-modal-times">
      <div class="inc-time-box">
        <small>🕐 Inicio</small>
        <strong>${escapeHtml(fmtIncidentDateTime(r.started_at))}</strong>
        <span>${escapeHtml(fmtIncidentAgo(r.started_at))}</span>
      </div>
      <div class="inc-time-box ${r.resolved_at ? 'is-end' : 'is-live'}">
        <small>${r.resolved_at ? '🏁 Fin' : '⏳ Activo'}</small>
        <strong>${r.resolved_at ? escapeHtml(fmtIncidentDateTime(r.resolved_at)) : '<span class="inc-elapsed" data-since="' + sinceMs + '">' + escapeHtml(fmtIncidentDuration(Date.now() - sinceMs)) + '</span>'}</strong>
        <span>${r.resolved_at ? escapeHtml(fmtIncidentAgo(r.resolved_at)) : 'sigue activo'}</span>
      </div>
      <div class="inc-time-box">
        <small>⏱ Duración</small>
        <strong>${escapeHtml(fmtIncidentDuration(liveMs))}</strong>
        <span>${r.resolved_at ? 'total del informe' : 'hasta ahora'}</span>
      </div>
    </div>

    <div class="rep-detail${accentCls}">
      ${r.details ? `<div class="modal-about"><h4 class="modal-about-title">¿De qué trata?</h4><p class="modal-about-text">${escapeHtml(r.details)}</p></div>` : ''}
      ${reportBlocksHtml(blocks)}
    </div>

    ${isLive ? `
      <div class="inc-quick is-modal">
        <span class="inc-quick-label">💬 Nueva actualización</span>
        <p class="inc-quick-hint">Abrí el editor para escribir la nota: podés elegir el estado, usar una plantilla y ver cómo queda antes de guardarla.</p>
        <div class="inc-quick-foot">
          <button type="button" class="btn btn-primary btn-sm" data-adm-ev="click" data-adm="openReportUpdateModal" data-adm-a0="r:${r.id}">💬 Escribir actualización</button>
          <span class="inc-quick-hint">El informe sigue activo hasta que lo termines.</span>
        </div>
      </div>` : ''}

    <div class="modal-about inc-tl-wrap">
      <h4 class="modal-about-title">📜 Línea de tiempo <span class="inc-tl-count">${updates.length} ${updates.length === 1 ? 'entrada' : 'entradas'}</span></h4>
      ${reportTimelineHtml(updates)}
    </div>

    <p class="inc-modal-foot">Publicado por <b>${escapeHtml(r.created_by || '—')}</b> · última edición de <b>${escapeHtml(r.updated_by || r.created_by || '—')}</b> ${escapeHtml(fmtIncidentAgo(r.updated_at || r.created_at))}</p>

    <div class="dev-step-actions">
      ${isLive
        ? `<button class="btn btn-primary" data-adm-ev="click" data-adm="openResolveReportForm" data-adm-a0="r:${r.id}">✅ Terminar informe</button>
           <button class="btn btn-ghost" data-adm-ev="click" data-adm="openReportForm" data-adm-a0="r:${r.id}">✏️ Editar</button>`
        : `<button class="btn btn-primary" data-adm-ev="click" data-adm="admCloseReportAndReopen" data-adm-a0="r:${r.id}">♻️ Reactivar</button>`}
      <button class="btn btn-danger" data-adm-ev="click" data-adm="deleteReport" data-adm-a0="r:${r.id}">🗑️ Eliminar</button>
      <button class="btn btn-ghost" data-adm-ev="click" data-adm="closeReportModal">Cerrar</button>
    </div>`;
  openReportModal();
}

function openResolveReportForm(id) {
  const body = document.getElementById('rep-modal-body');
  if (!body) return;
  const r = getReport(id);
  if (!r) {
    showToast('⚠️ Informe no encontrado');
    return;
  }
  reportModalMode = 'resolve';
  reportModalId = Number(id);
  const kind = repKind(r.kind);
  const updates = Array.isArray(r.updates) ? r.updates : [];
  const sinceMs = r.started_at ? new Date(r.started_at).getTime() : Date.now();

  body.innerHTML = `
    <div class="devmodal-head">
      <div class="devmodal-icon">✅</div>
      <div class="devmodal-head-info">
        <h3 class="devmodal-title">Terminar informe</h3>
        <p class="modal-tagline">${escapeHtml(r.title)}</p>
        <div class="devmodal-tags">
          <span class="inc-pill is-cat">${kind.icon} ${escapeHtml(kind.label)}</span>
          <span class="inc-pill is-updates">💬 ${r.update_count || updates.length}</span>
        </div>
      </div>
    </div>

    <div class="inc-modal-times">
      <div class="inc-time-box">
        <small>🕐 Inicio</small>
        <strong>${escapeHtml(fmtIncidentDateTime(r.started_at))}</strong>
        <span>${escapeHtml(fmtIncidentAgo(r.started_at))}</span>
      </div>
      <div class="inc-time-box is-live">
        <small>⏳ Lleva activo</small>
        <strong><span class="inc-elapsed" data-since="${sinceMs}">${escapeHtml(fmtIncidentDuration(Date.now() - sinceMs))}</span></strong>
        <span>hasta ahora</span>
      </div>
    </div>

    <div class="field-group">
      <label for="rep-resolve-at">Hora de fin *</label>
      <input type="datetime-local" id="rep-resolve-at" value="${toLocalInputValue(new Date())}" />
      <p class="form-hint">Por defecto es ahora. Corregila si la situación ya había terminado antes.</p>
    </div>
    <div class="field-group">
      <label for="rep-resolve-note">Nota de cierre <span class="opt-tag">opcional</span></label>
      <textarea id="rep-resolve-note" rows="3" maxlength="2000" placeholder="Cómo terminó: se retomó el desarrollo, se resolvió lo interno, etc. Queda como última entrada."></textarea>
    </div>
    <div class="inc-resolve-warn">
      <b>⚠️ Al terminar</b> el informe deja de contar como activo y entra en el <b>historial</b> con su hora de inicio, la de fin y la duración total. Podés reactivarlo después si la situación vuelve.
    </div>
    <div class="dev-step-actions">
      <button class="btn btn-primary" id="btn-resolve-report" data-adm-ev="click" data-adm="resolveReport">✅ Confirmar y terminar</button>
      <button class="btn btn-ghost" data-adm-ev="click" data-adm="viewReport" data-adm-a0="r:${r.id}">Volver</button>
      <button class="btn btn-ghost" data-adm-ev="click" data-adm="closeReportModal">Cancelar</button>
    </div>`;
  openReportModal();
  startIncidentClock();
}

async function resolveReport() {
  const id = reportModalId;
  if (!id) return;
  const at = fromLocalInputValue(document.getElementById('rep-resolve-at')?.value || '');
  if (!at) {
    showToast('⚠️ Poné la hora de fin del informe.');
    return;
  }
  const note = (document.getElementById('rep-resolve-note')?.value || '').trim();
  const btn = document.getElementById('btn-resolve-report');
  if (btn) { btn.disabled = true; btn.textContent = '✅ Terminando…'; }
  try {
    const res = await adminFetch(`${API_BASE}/ows-reports/${id}/resolve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ resolved_at: at, resolution: note })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    const rep = data.report;
    showToast(`✅ Informe terminado · duró ${fmtIncidentDuration(rep?.duration_ms)}`);
    closeReportModal();
    await loadReports();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
    if (btn) { btn.disabled = false; btn.textContent = '✅ Confirmar y terminar'; }
  }
}

async function reopenReport(id) {
  const r = getReport(id);
  if (!r) return showToast('⚠️ Informe no encontrado');
  const reason = prompt(
    `¿Por qué se reactiva el informe “${r.title}”?\n\n` +
    'Vuelve a quedar activo con las notas que tenía.',
    'La situación continúa'
  );
  if (reason === null) return;
  try {
    const res = await adminFetch(`${API_BASE}/ows-reports/${id}/reopen`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason: String(reason || '').trim() })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    showToast('♻️ Informe reactivado: volvió a activos');
    await loadReports();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

async function deleteReport(id) {
  const r = getReport(id);
  if (!r) return showToast('⚠️ Informe no encontrado');
  if (!confirm(`¿Eliminar el informe “${r.title}” con toda su línea de tiempo?\n\nEsta acción no se puede deshacer.`)) return;
  try {
    const res = await adminFetch(`${API_BASE}/ows-reports/${id}`, { method: 'DELETE' });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    showToast('🗑️ Informe eliminado');
    closeReportModal();
    await loadReports();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

// =======================================================
// NOTICIAS RÁPIDAS (⚡) — texto corto, sin imagen
// Endpoints (solo-admin): GET /ows-dashboard/quick-news/all,
// POST /ows-dashboard/quick-news, PATCH/DELETE /:id.
// El feed público es /ows-dashboard/quick-news (sin token).
// =======================================================

let quickNewsCache = [];
let editingQuickNewsId = null;

function getQuickNews(id) {
  return quickNewsCache.find((q) => Number(q.id) === Number(id)) || null;
}

function quickNewsAgo(value) {
  if (!value) return '—';
  const t = new Date(value).getTime();
  if (!Number.isFinite(t)) return '—';
  const mins = Math.round((Date.now() - t) / 60000);
  if (mins < 1) return 'ahora';
  if (mins < 60) return `hace ${mins} min`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `hace ${hours} h`;
  const days = Math.round(hours / 24);
  if (days === 1) return 'ayer';
  if (days < 30) return `hace ${days} días`;
  return new Date(value).toLocaleDateString('es-ES', { day: 'numeric', month: 'short', year: 'numeric' });
}

async function loadQuickNews(manual) {
  const list = document.getElementById('qnews-list');
  if (!list) return;
  try {
    const res = await adminFetch(API_BASE + '/ows-dashboard/quick-news/all');
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    quickNewsCache = Array.isArray(data.news) ? data.news : [];
    renderQuickNewsAdmin();
    if (manual) showToast(`⚡ Rápidas actualizadas: ${quickNewsCache.filter((q) => q.is_active).length} publicadas`);
  } catch (err) {
    list.innerHTML = `<div class="newsadm-empty"><span class="newsadm-empty-icon">⚠️</span><p><b>No se pudieron cargar</b></p><p>${escapeHtml(err.message)}</p><button class="btn btn-ghost btn-sm" data-adm-ev="click" data-adm="loadQuickNews" data-adm-a0="b:1">Reintentar</button></div>`;
  }
}

function renderQuickNewsAdmin() {
  const list = document.getElementById('qnews-list');
  if (!list) return;
  const active = quickNewsCache.filter((q) => q.is_active);
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  set('qn-stat-total', quickNewsCache.length);
  set('qn-stat-active', active.length);
  set('qn-stat-hidden', quickNewsCache.length - active.length);
  set('qn-stat-new', active.filter((q) => q.is_new).length);
  set('qnews-count', `${quickNewsCache.length} ${quickNewsCache.length === 1 ? 'rápida' : 'rápidas'}`);

  if (!quickNewsCache.length) {
    list.innerHTML = `<div class="newsadm-empty">
      <span class="newsadm-empty-icon">⚡</span>
      <p><b>Todavía no hay noticias rápidas</b></p>
      <p>Escribí una corta en el formulario: aparece al pie de la sección Noticias del Hub.</p>
    </div>`;
    return;
  }

  list.innerHTML = quickNewsCache.map((q) => {
    const on = !!q.is_active;
    return `
    <article class="qn-row ${on ? 'is-on' : 'is-off'}">
      <div class="qn-row-main">
        <div class="qn-row-top">
          <span class="qn-row-text">${escapeHtml(q.text)}</span>
          <span class="qn-row-pills">
            ${q.is_new ? '<span class="status-pill status-on">✨ Nueva</span>' : ''}
            <span class="status-pill ${on ? 'status-on' : 'status-off'}">${on ? 'Publicada' : 'Oculta'}</span>
            ${q.tag ? `<span class="status-pill status-from-projects">🏷️ ${escapeHtml(q.tag)}</span>` : ''}
            ${q.link_url ? '<span class="status-pill status-admin-only">🔗 Link</span>' : ''}
          </span>
        </div>
        <div class="qn-row-meta">
          <span>🕐 ${escapeHtml(quickNewsAgo(q.published_at || q.created_at))}</span>
          <span>👤 ${escapeHtml(q.created_by || '—')}</span>
        </div>
      </div>
      <div class="qn-row-actions">
        <button class="btn btn-ghost btn-mini" title="Editar" data-adm-ev="click" data-adm="openQuickNewsForm" data-adm-a0="r:${q.id}">✏️</button>
        <button class="btn btn-ghost btn-mini" title="${on ? 'Ocultar del Hub' : 'Volver a publicar'}" data-adm-ev="click" data-adm="toggleQuickNews" data-adm-a0="r:${q.id}">${on ? '🙈' : '👁️'}</button>
        <button class="btn btn-danger btn-mini" title="Eliminar" data-adm-ev="click" data-adm="deleteQuickNews" data-adm-a0="r:${q.id}">🗑️</button>
      </div>
    </article>`;
  }).join('');
}

// ── Formulario ──
function readQuickNewsDraft() {
  const text = document.getElementById('qnews-text');
  const tag = document.getElementById('qnews-tag');
  const link = document.getElementById('qnews-link');
  return {
    text: text ? text.value.trim() : '',
    tag: tag ? tag.value.trim() : '',
    link_url: link ? link.value.trim() : ''
  };
}

function updateQuickNewsCounters() {
  const text = document.getElementById('qnews-text');
  const count = document.getElementById('qnews-text-count');
  if (text && count) count.textContent = `${text.value.length}/240`;
  renderQuickNewsPreview();
}

function renderQuickNewsPreview() {
  const box = document.getElementById('qnews-preview');
  if (!box) return;
  const d = readQuickNewsDraft();
  const link = d.link_url && /^https?:\/\//i.test(d.link_url) ? d.link_url : '';
  box.innerHTML = `
    <div class="qnews-item is-new">
      <span class="qnews-item-dot" aria-hidden="true"></span>
      <span class="qnews-item-text">${d.text ? escapeHtml(d.text) : '<span class="qnews-prev-empty">La noticia rápida se va a ver acá…</span>'}</span>
      <span class="qnews-item-side">
        <span class="qnews-item-new">✨ Nuevo</span>
        ${d.tag ? `<span class="qnews-item-tag">${escapeHtml(d.tag)}</span>` : ''}
        <span class="qnews-item-when">ahora</span>
      </span>
      ${link ? '<span class="qnews-item-cta" aria-hidden="true">↗</span>' : ''}
    </div>
    <p class="form-hint">Así aparece en el Hub. El tag <b>✨ Nuevo</b> se borra solo a los 3 días.</p>`;
}

function updateQuickNewsFormMode() {
  const title = document.getElementById('qnews-form-title');
  const btn = document.getElementById('btn-save-qnews');
  const cancel = document.getElementById('btn-cancel-qnews');
  const editing = editingQuickNewsId != null;
  if (title) title.textContent = editing ? `✏️ Editando la rápida #${editingQuickNewsId}` : 'Nueva noticia rápida';
  if (btn) btn.textContent = editing ? '💾 Guardar cambios' : '⚡ Publicar rápida';
  if (cancel) cancel.classList.toggle('hidden', !editing);
}

function resetQuickNewsForm() {
  editingQuickNewsId = null;
  ['qnews-text', 'qnews-tag', 'qnews-link'].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  hideAlert('qnews-form-alert');
  updateQuickNewsFormMode();
  updateQuickNewsCounters();
  try { closeFormModal(); } catch (_) {}
}

function focusQuickNewsForm() {
  openQuickNewsForm(null);
}

function openQuickNewsForm(editId) {
  switchAdminTab('news');
  switchAdminSub('news', 'quick');
  const q = editId != null && editId !== '' ? getQuickNews(editId) : null;
  if (editId != null && editId !== '' && !q) {
    showToast('⚠️ Noticia rápida no encontrada');
    return;
  }
  editingQuickNewsId = q ? Number(q.id) : null;
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
  set('qnews-text', q ? q.text : '');
  set('qnews-tag', q ? (q.tag || '') : '');
  set('qnews-link', q ? (q.link_url || '') : '');
  hideAlert('qnews-form-alert');
  updateQuickNewsFormMode();
  updateQuickNewsCounters();
  openFormModal('quicknews');
}

async function saveQuickNews(e) {
  if (e) e.preventDefault();
  hideAlert('qnews-form-alert');
  const d = readQuickNewsDraft();
  if (!d.text) {
    showAlert('qnews-form-alert', 'Escribí el texto de la noticia rápida.', 'error');
    document.getElementById('qnews-text')?.focus();
    return;
  }
  if (d.link_url && !/^https?:\/\//i.test(d.link_url)) {
    showAlert('qnews-form-alert', 'El link tiene que empezar con http:// o https://', 'error');
    document.getElementById('qnews-link')?.focus();
    return;
  }
  const editing = editingQuickNewsId != null;
  const url = editing ? `${API_BASE}/ows-dashboard/quick-news/${editingQuickNewsId}` : `${API_BASE}/ows-dashboard/quick-news`;
  const btn = document.getElementById('btn-save-qnews');
  if (btn) { btn.disabled = true; btn.textContent = editing ? '💾 Guardando…' : '⚡ Publicando…'; }
  try {
    const res = await adminFetch(url, {
      method: editing ? 'PATCH' : 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(d)
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    showToast(editing ? '✔ Rápida actualizada' : `⚡ Publicada: “${data.news?.text || d.text}”`);
    resetQuickNewsForm();
    await loadQuickNews();
  } catch (err) {
    showAlert('qnews-form-alert', err.message, 'error');
  } finally {
    if (btn) { btn.disabled = false; updateQuickNewsFormMode(); }
  }
}

async function toggleQuickNews(id) {
  const q = getQuickNews(id);
  if (!q) return showToast('⚠️ Noticia rápida no encontrada');
  try {
    const res = await adminFetch(`${API_BASE}/ows-dashboard/quick-news/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ is_active: !q.is_active })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    showToast(q.is_active ? '🙈 Rápida oculta del Hub' : '👁️ Rápida publicada de nuevo');
    await loadQuickNews();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

async function deleteQuickNews(id) {
  const q = getQuickNews(id);
  if (!q) return showToast('⚠️ Noticia rápida no encontrada');
  if (!confirm(`¿Eliminar la noticia rápida “${q.text}”?`)) return;
  try {
    const res = await adminFetch(`${API_BASE}/ows-dashboard/quick-news/${id}`, { method: 'DELETE' });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    showToast('🗑️ Rápida eliminada');
    await loadQuickNews();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

// =======================================================
// NOTICIAS — diseño renovado (hero + buscador + filtros + preview)
// Mismos endpoints: GET/POST/PATCH/DELETE /ows-dashboard/news
// =======================================================

let newsCache = [];
let newsFilter = 'all';
let newsSearchTerm = '';
let newsImgFile = null;
let newsFormDate = null;

function fillNewsProjectList() {
  const dl = document.getElementById('news-project-list');
  if (!dl) return;
  const names = new Set();
  newsCache.forEach((n) => {
    const p = String(n.project_name || '').trim();
    if (p) names.add(p);
  });
  if (typeof eventsCache !== 'undefined' && Array.isArray(eventsCache)) {
    eventsCache.forEach((ev) => {
      const p = String(ev.project_name || '').trim();
      if (p) names.add(p);
    });
  }
  dl.innerHTML = [...names].sort().map((n) => `<option value="${escapeHtml(n)}"></option>`).join('');
}

function formatNewsAdminDate(value) {
  if (!value) return 'Sin fecha';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return 'Sin fecha';
  return d.toLocaleDateString('es-ES', { day: 'numeric', month: 'short', year: 'numeric' });
}

function setNewsFilter(f) {
  newsFilter = (f === 'active' || f === 'hidden') ? f : 'all';
  document.querySelectorAll('[data-newsfilter]').forEach((b) => {
    b.classList.toggle('active', b.getAttribute('data-newsfilter') === newsFilter);
  });
  renderNewsList();
}

function filterNewsList() {
  const el = document.getElementById('news-search');
  newsSearchTerm = el ? el.value.trim().toLowerCase() : '';
  renderNewsList();
}

function updateNewsCounters() {
  const t = document.getElementById('news-title');
  const d = document.getElementById('news-desc');
  const tc = document.getElementById('news-title-count');
  const dc = document.getElementById('news-desc-count');
  if (t && tc) tc.textContent = `${t.value.length}/120`;
  if (d && dc) dc.textContent = `${d.value.length}/500`;
}

function newsFormDateLabel() {
  const raw = newsFormDate || new Date().toISOString();
  const d = new Date(raw);
  if (Number.isNaN(d.getTime())) return 'Hoy';
  return d.toLocaleDateString('es-ES', { day: 'numeric', month: 'short', year: 'numeric' });
}

function currentNewsImageSrc(fallback) {
  if (newsImgFile) {
    try { return URL.createObjectURL(newsImgFile); } catch (_) { return ''; }
  }
  const urlEl = document.getElementById('news-img-url');
  const typed = urlEl ? urlEl.value.trim() : '';
  if (typed) return typed;
  return String(fallback || '');
}

function updateNewsPreview() {
  const t = document.getElementById('news-title');
  const d = document.getElementById('news-desc');
  const p = document.getElementById('news-project');
  const pt = document.getElementById('news-preview-title');
  const pd = document.getElementById('news-preview-desc');
  const pp = document.getElementById('news-preview-project');
  const pi = document.getElementById('news-preview-img');
  const pdt = document.getElementById('news-preview-date');
  if (pt) pt.textContent = (t && t.value.trim()) || 'Tu titular aparecerá aquí…';
  if (pd) pd.textContent = (d && d.value.trim()) || 'El resumen se mostrará debajo del título.';
  if (pp) pp.textContent = (p && p.value.trim()) || 'OWS';
  if (pdt) pdt.textContent = newsFormDateLabel();
  if (pi) {
    const src = currentNewsImageSrc('');
    if (src) {
      if (pi.getAttribute('src') !== src) pi.src = src;
      pi.classList.remove('hidden');
    } else {
      pi.removeAttribute('src');
      pi.classList.add('hidden');
    }
  }
}

function updateNewsStats() {
  const total = newsCache.length;
  const active = newsCache.filter((n) => n.is_active).length;
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  set('news-stat-total', total);
  set('news-stat-active', active);
  set('news-stat-hidden', total - active);
}

async function loadAdminNews(manual) {
  const list = document.getElementById('news-list');
  if (!list) return;
  try {
    const res = await fetch(API_BASE + '/ows-dashboard/news?limit=100');
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    newsCache = Array.isArray(data.news) ? data.news : [];
    updateNewsStats();
    fillNewsProjectList();
    renderNewsList();
    if (manual) showToast('✔ Noticias actualizadas');
  } catch (err) {
    list.innerHTML = `<div class="newsadm-empty"><span class="newsadm-empty-icon">⚠️</span><p><b>No se pudieron cargar las noticias</b></p><p>${escapeHtml(err.message)}</p><button class="btn btn-ghost btn-sm" data-adm-ev="click" data-adm="loadAdminNews" data-adm-a0="b:1">Reintentar</button></div>`;
  }
}

function visibleNews() {
  const q = newsSearchTerm;
  return newsCache.filter((n) => {
    if (newsFilter === 'active' && !n.is_active) return false;
    if (newsFilter === 'hidden' && n.is_active) return false;
    if (q) {
      const hay = `${n.title || ''} ${n.description || ''} ${n.project_name || ''}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  }).sort((a, b) => newsSortDate(b) - newsSortDate(a));
}

function newsSortDate(n) {
  const t = new Date(n.published_at || n.created_at || 0).getTime();
  return Number.isFinite(t) ? t : 0;
}

function renderNewsList() {
  const list = document.getElementById('news-list');
  if (!list) return;
  const badge = document.getElementById('news-count-badge');
  const items = visibleNews();
  if (badge) badge.textContent = newsCache.length ? `${items.length}/${newsCache.length}` : '';

  if (!newsCache.length) {
    list.innerHTML = `<div class="newsadm-empty">
      <span class="newsadm-empty-icon">📰</span>
      <p><b>Todavía no hay noticias</b></p>
      <p>Creá la primera con el formulario y aparecerá en el dashboard de OWS.</p>
    </div>`;
    return;
  }
  if (!items.length) {
    list.innerHTML = `<div class="newsadm-empty">
      <span class="newsadm-empty-icon">🔍</span>
      <p><b>Sin resultados</b></p>
      <p>Nada coincide con esa búsqueda o filtro.</p>
      <button class="btn btn-ghost btn-sm" data-adm-ev="click" data-adm="clearNewsSearch">Limpiar búsqueda</button>
    </div>`;
    return;
  }
  list.innerHTML = items.map((n) => {
    const on = !!n.is_active;
    const media = String(n.image_url || '').trim();
    return `
    <article class="newsadm-item ${on ? 'is-on' : 'is-off'}">
      <div class="newsadm-item-top">
        <span class="newsadm-dot"></span>
        <span class="newsadm-date">📅 ${escapeHtml(formatNewsAdminDate(n.published_at || n.created_at))}</span>
        <span class="status-pill ${on ? 'status-on' : 'status-off'}">${on ? 'Activa' : 'Oculta'}</span>
        ${media ? '<span class="newsadm-date newsadm-hasimg">🖼 Con imagen</span>' : ''}
      </div>
      <div class="newsadm-item-body">
        ${media ? `<div class="newsadm-item-media"><img src="${escapeHtml(media)}" alt="" loading="lazy" data-adm-err="rm" /></div>` : ''}
        <div class="newsadm-item-text">
          <h4 class="newsadm-item-title">${escapeHtml(n.title || '(sin título)')}</h4>
          ${n.description ? `<p class="newsadm-item-desc">${escapeHtml(n.description)}</p>` : '<p class="newsadm-item-desc newsadm-no-desc">Sin descripción.</p>'}
        </div>
      </div>
      <div class="newsadm-item-foot">
        <span class="news-item-project">${escapeHtml(n.project_name || 'OWS')}</span>
        <div class="newsadm-actions">
          <button class="btn btn-ghost btn-mini" title="Editar" data-adm-ev="click" data-adm="editNews" data-adm-a0="r:${n.id}">✏️ Editar</button>
          <button class="btn btn-ghost btn-mini" title="${on ? 'Ocultar' : 'Mostrar'}" data-adm-ev="click" data-adm="toggleNews" data-adm-a0="r:${n.id}">${on ? '👁️ Ocultar' : '🚫 Mostrar'}</button>
          <button class="btn btn-danger btn-mini" title="Eliminar" data-adm-ev="click" data-adm="deleteNews" data-adm-a0="r:${n.id}">🗑️</button>
        </div>
      </div>
    </article>`;
  }).join('');
}

function clearNewsSearch() {
  const el = document.getElementById('news-search');
  if (el) el.value = '';
  newsSearchTerm = '';
  setNewsFilter('all');
}

async function saveNews(e) {
  if (e && e.preventDefault) e.preventDefault();
  hideAlert('news-form-alert');
  const title = document.getElementById('news-title').value.trim();
  const description = document.getElementById('news-desc').value.trim();
  const project_name = document.getElementById('news-project').value.trim() || 'OWS';
  const urlEl = document.getElementById('news-img-url');
  const image_url = urlEl ? urlEl.value.trim() : '';
  if (!title) {
    showAlert('news-form-alert', 'El titular es obligatorio.', 'error');
    document.getElementById('news-title').focus();
    return;
  }
  const btn = document.getElementById('btn-save-news');
  const original = editingNewsId ? '💾 Guardar cambios' : '🚀 Publicar noticia';
  btn.disabled = true;
  btn.textContent = editingNewsId ? '⏳ Guardando…' : '⏳ Publicando…';
  try {
    const fd = new FormData();
    fd.append('title', title);
    fd.append('description', description);
    fd.append('project_name', project_name);
    fd.append('image_url', image_url);
    if (editingNewsId) {
      const item = newsCache.find((n) => Number(n.id) === Number(editingNewsId));
      fd.append('is_active', item && item.is_active === false ? 'false' : 'true');
    }
    if (newsImgFile) fd.append('image', newsImgFile, newsImgFile.name || 'noticia.jpg');
    const res = await fetch(API_BASE + (editingNewsId ? `/ows-dashboard/news/${editingNewsId}` : '/ows-dashboard/news'), {
      method: editingNewsId ? 'PATCH' : 'POST',
      headers: adminHeaders(),
      body: fd
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    showAlert('news-form-alert', editingNewsId ? 'Noticia actualizada ✔' : 'Noticia publicada ✔', 'success');
    showToast(editingNewsId ? 'Noticia actualizada ✔' : 'Noticia publicada ✔');
    resetNewsForm();
    loadAdminNews();
  } catch (err) {
    showAlert('news-form-alert', err.message || 'Error al guardar.', 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = original;
  }
}

function editNews(id) {
  const item = newsCache.find((n) => Number(n.id) === Number(id));
  if (!item) {
    showToast('⚠️ Noticia no encontrada. Recargando…');
    loadAdminNews();
    return;
  }
  editingNewsId = id;
  hideAlert('news-form-alert');
  document.getElementById('news-id').value = id;
  document.getElementById('news-title').value = item.title || '';
  document.getElementById('news-desc').value = item.description || '';
  document.getElementById('news-project').value = item.project_name || 'OWS';
  newsImgFile = null;
  const fileEl = document.getElementById('news-img-file');
  if (fileEl) fileEl.value = '';
  const imgUrlEl = document.getElementById('news-img-url');
  if (imgUrlEl) imgUrlEl.value = item.image_url || '';
  newsFormDate = item.published_at || item.created_at || null;
  renderNewsImagePreview(item.image_url || '');
  updateNewsCounters();
  updateNewsPreview();
  document.getElementById('news-form-title').textContent = `✏️ Editando #${id}`;
  const mode = document.getElementById('news-form-mode');
  if (mode) { mode.textContent = `Editando #${id}`; mode.className = 'status-pill status-on'; }
  document.getElementById('btn-cancel-news').classList.remove('hidden');
  document.getElementById('btn-save-news').textContent = '💾 Guardar cambios';
  openFormModal('news');
}

function resetNewsForm() {
  editingNewsId = null;
  hideAlert('news-form-alert');
  document.getElementById('news-id').value = '';
  document.getElementById('news-form-title').textContent = '✨ Nueva noticia';
  const mode = document.getElementById('news-form-mode');
  if (mode) { mode.textContent = 'Borrador'; mode.className = 'status-pill status-off'; }
  document.getElementById('btn-cancel-news').classList.add('hidden');
  document.getElementById('btn-save-news').textContent = '🚀 Publicar noticia';
  ['news-title', 'news-desc', 'news-project'].forEach((id) => { const el = document.getElementById(id); if (el) el.value = ''; });
  newsImgFile = null;
  newsFormDate = null;
  const fileEl = document.getElementById('news-img-file');
  if (fileEl) fileEl.value = '';
  const imgUrlEl = document.getElementById('news-img-url');
  if (imgUrlEl) imgUrlEl.value = '';
  renderNewsImagePreview('');
  updateNewsCounters();
  updateNewsPreview();
  try { closeFormModal(); } catch (_) {}
}

function setupNewsImagePreview() {
  const input = document.getElementById('news-img-file');
  if (!input || input.dataset.bound) return;
  input.dataset.bound = '1';
  const accept = (f) => {
    if (!f) return false;
    if (!/^image\//.test(f.type)) { showToast('⚠️ Solo se aceptan imágenes'); return false; }
    if (f.size > 15 * 1024 * 1024) { showToast('⚠️ La imagen supera los 15 MB'); return false; }
    return true;
  };
  const applyFile = (f) => {
    if (!accept(f)) return;
    newsImgFile = f;
    const dt = new DataTransfer();
    dt.items.add(f);
    input.files = dt.files;
    const urlEl = document.getElementById('news-img-url');
    if (urlEl) urlEl.value = '';
    renderNewsImagePreview();
    updateNewsPreview();
  };
  input.addEventListener('change', () => {
    applyFile(input.files && input.files[0] ? input.files[0] : null);
  });
  const zone = document.getElementById('news-dropzone');
  if (zone) {
    ['dragenter', 'dragover'].forEach((evt) => zone.addEventListener(evt, (e) => {
      e.preventDefault();
      zone.classList.add('ev-dropzone-active');
    }));
    ['dragleave', 'drop'].forEach((evt) => zone.addEventListener(evt, (e) => {
      e.preventDefault();
      zone.classList.remove('ev-dropzone-active');
    }));
    zone.addEventListener('drop', (e) => {
      const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
      if (f) applyFile(f);
    });
  }
  const urlInput = document.getElementById('news-img-url');
  if (urlInput && !urlInput.dataset.bound) {
    urlInput.dataset.bound = '1';
    urlInput.addEventListener('input', () => {
      if (urlInput.value.trim()) {
        newsImgFile = null;
        input.value = '';
      }
      renderNewsImagePreview();
      updateNewsPreview();
    });
  }
}

function renderNewsImagePreview(existingUrl) {
  const preview = document.getElementById('news-img-preview');
  if (!preview) return;
  const src = currentNewsImageSrc(existingUrl);
  if (!src) {
    preview.innerHTML = '';
    preview.classList.add('hidden');
    return;
  }
  preview.innerHTML = `
    <img src="${escapeHtml(src)}" alt="portada" data-adm-err="closest:.ev-preview|hidden" />
    <button type="button" class="btn btn-danger btn-mini ev-preview-remove" data-adm-ev="click" data-adm="removeNewsImage">✕ Quitar</button>`;
  preview.classList.remove('hidden');
}

function removeNewsImage() {
  newsImgFile = null;
  const fi = document.getElementById('news-img-file');
  if (fi) fi.value = '';
  const urlEl = document.getElementById('news-img-url');
  if (urlEl) urlEl.value = '';
  renderNewsImagePreview('');
  updateNewsPreview();
}

// Atajos del formulario: Ctrl/Cmd + Enter publica, Enter en el titular
// salta al resumen (flujo rápido de creación).
function setupNewsFormShortcuts() {
  const form = document.getElementById('news-form');
  if (!form || form.dataset.shortcutBound) return;
  form.dataset.shortcutBound = '1';
  form.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && (e.key === 'Enter' || e.code === 'Enter')) {
      e.preventDefault();
      const btn = document.getElementById('btn-save-news');
      if (btn && !btn.disabled) {
        if (typeof form.requestSubmit === 'function') form.requestSubmit();
        else saveNews();
      }
      return;
    }
    if (e.key === 'Enter' && e.target && e.target.id === 'news-title') {
      e.preventDefault();
      const d = document.getElementById('news-desc');
      if (d) d.focus();
    }
  });
}

async function toggleNews(id) {
  try {
    const res = await fetch(API_BASE + `/ows-dashboard/news/${id}`, {
      method: 'PATCH',
      headers: adminHeaders()
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    const item = newsCache.find((n) => Number(n.id) === Number(id));
    showToast(item && item.is_active ? 'Noticia oculta' : 'Noticia visible ✔');
    loadAdminNews();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

async function deleteNews(id) {
  const item = newsCache.find((n) => Number(n.id) === Number(id));
  if (!confirm(`¿Eliminar permanentemente "${String(item?.title || ('#' + id)).slice(0, 60)}"?`)) return;
  try {
    const res = await fetch(API_BASE + `/ows-dashboard/news/${id}`, {
      method: 'DELETE',
      headers: adminHeaders()
    });
    if (!res.ok) throw new Error(`Error (${res.status})`);
    showToast('Noticia eliminada');
    if (editingNewsId === id) resetNewsForm();
    loadAdminNews();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

// =======================================================
// EVENTOS — v2 renovado
// Calendario OWS: hero con stats, buscador, filtros, vista grid/list,
// tarjetas con fase (en curso / programado / finalizado / oculto),
// preview en vivo, dropzone, duplicar y fechas rápidas.
// Endpoints intactos: /ows-dashboard/events (multipart con imagen).
// =======================================================

const EVENT_CATEGORY_META = {
  update:       { label: 'Actualización', icon: '⬆️', cls: 'ev-cat-update' },
  launch:       { label: 'Lanzamiento',   icon: '🚀', cls: 'ev-cat-launch' },
  release:      { label: 'Release',       icon: '📦', cls: 'ev-cat-release' },
  event:        { label: 'Evento',        icon: '🎉', cls: 'ev-cat-event' },
  announcement: { label: 'Anuncio',       icon: '📢', cls: 'ev-cat-announcement' },
  maintenance:  { label: 'Mantenimiento', icon: '🛠️', cls: 'ev-cat-maintenance' }
};

let eventsCache = [];
let eventsView = 'grid';
let eventsSearchText = '';
let eventsFilterCategory = '';
let eventsFilterStatus = '';
let eventsFilterSort = 'soon';

function eventCategoryMeta(cat) {
  return EVENT_CATEGORY_META[String(cat || 'update').toLowerCase()] || EVENT_CATEGORY_META.update;
}

function localDatetimeValue(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function getEventPhase(ev) {
  if (!ev) return 'upcoming';
  if (ev.is_active === false) return 'hidden';
  const now = Date.now();
  const s = ev.starts_at ? Date.parse(ev.starts_at) : NaN;
  const e = ev.ends_at ? Date.parse(ev.ends_at) : NaN;
  if (Number.isFinite(e) && now > e) return 'ended';
  if (Number.isFinite(s) && Number.isFinite(e) && now >= s && now <= e) return 'live';
  if (Number.isFinite(s) && !Number.isFinite(e) && now >= s) return 'live';
  if (Number.isFinite(s) && now < s) return 'upcoming';
  return 'upcoming';
}

const EVENT_PHASE_META = {
  live:     { label: '● En curso',    cls: 'ev-phase-live' },
  upcoming: { label: '◷ Programado',  cls: 'ev-phase-upcoming' },
  ended:    { label: '✔ Finalizado',  cls: 'ev-phase-ended' },
  hidden:   { label: '👁️ Oculto',     cls: 'ev-phase-hidden' }
};

function formatEventDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleDateString('es-ES', { day: '2-digit', month: 'short' }) + ' · ' +
    d.toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit' });
}

function eventCountdown(ev) {
  const now = Date.now();
  const s = ev.starts_at ? Date.parse(ev.starts_at) : NaN;
  const e = ev.ends_at ? Date.parse(ev.ends_at) : NaN;
  const fmt = (ms) => {
    if (ms < 0) ms = 0;
    const m = Math.floor(ms / 60000);
    const d = Math.floor(m / 1440);
    const h = Math.floor((m % 1440) / 60);
    const mm = m % 60;
    if (d > 0) return `en ${d}d ${h}h`;
    if (h > 0) return `en ${h}h ${mm}m`;
    return `en ${mm}m`;
  };
  if (Number.isFinite(e) && now > e) return 'Finalizó';
  if (Number.isFinite(s) && Number.isFinite(e) && now >= s) return 'Termina ' + fmt(e - now).replace('en ', 'en ');
  if (Number.isFinite(s) && now < s) return 'Empieza ' + fmt(s - now);
  if (Number.isFinite(e) && now <= e) return 'Termina ' + fmt(e - now);
  return 'Sin horario';
}

function eventProgress(ev) {
  const s = ev.starts_at ? Date.parse(ev.starts_at) : NaN;
  const e = ev.ends_at ? Date.parse(ev.ends_at) : NaN;
  if (!Number.isFinite(s) || !Number.isFinite(e) || e <= s) return null;
  const now = Date.now();
  return Math.max(0, Math.min(100, Math.round(((now - s) / (e - s)) * 100)));
}

// El nombre del proyecto se muestra a mano o sale del catálogo. Estado corto
// para saber de un vistazo cuál está lanzado y cuál sigue en desarrollo.
const EVENT_PROJECT_STATUS = {
  development: 'en desarrollo',
  soon: 'próximamente',
  launched: 'lanzado',
  cancelled: 'cancelado',
  discontinued: 'descontinuado'
};

// Catálogo unificado: manageProjectsCache trae admin_only + públicos
// (include_hidden=1) y projectsCache solo los públicos.
function eventProjectCatalog() {
  const byId = new Map();
  (manageProjectsCache || []).forEach((p) => {
    if (p && p.id != null) byId.set(Number(p.id), p);
  });
  (projectsCache || []).forEach((p) => {
    if (p && p.id != null && !byId.has(Number(p.id))) byId.set(Number(p.id), p);
  });
  const all = [...byId.values()];
  const byName = (a, b) => String(a.name || '').localeCompare(String(b.name || ''));
  return {
    public: all.filter((p) => !isAdminOnlyProject(p)).sort(byName),
    adminOnly: all.filter((p) => isAdminOnlyProject(p)).sort(byName)
  };
}

function eventProjectOption(p) {
  const status = EVENT_PROJECT_STATUS[p.status] || '';
  const suffix = status ? ` · ${status}` : '';
  return `<option value="${Number(p.id)}" data-name="${escapeHtml(String(p.name || ''))}">${escapeHtml(String(p.name || ''))}${suffix}</option>`;
}

// Arma el dropdown del proyecto del evento. `keep` preserva la selección
// actual (id, 'custom' o '') para no perderla al repintar.
function populateEventProjectOptions(keep) {
  const sel = document.getElementById('event-project');
  if (!sel) return;
  const current = keep !== undefined ? keep : sel.value;
  const { public: pub, adminOnly } = eventProjectCatalog();
  const parts = ['<option value="">— Sin proyecto (general OWS) —</option>'];
  if (pub.length) parts.push(`<optgroup label="📁 Proyectos OWS">${pub.map(eventProjectOption).join('')}</optgroup>`);
  if (adminOnly.length) parts.push(`<optgroup label="🛡️ Solo admin">${adminOnly.map(eventProjectOption).join('')}</optgroup>`);
  parts.push('<option value="custom">✏️ Otro / escribir a mano…</option>');
  sel.innerHTML = parts.join('');
  const valid = [...sel.options].some((o) => o.value === String(current));
  sel.value = valid ? String(current) : '';
  onEventProjectChange();
}

function onEventProjectChange() {
  const sel = document.getElementById('event-project');
  const customGroup = document.getElementById('event-project-custom-group');
  if (customGroup) customGroup.classList.toggle('hidden', sel ? sel.value !== 'custom' : true);
  updateEventLivePreview();
}

// Proyecto elegido: id del catálogo o nombre escrito a mano.
function readEventProjectSelection() {
  const sel = document.getElementById('event-project');
  const custom = document.getElementById('event-project-custom');
  const value = sel ? sel.value : '';
  if (value === 'custom') {
    return { project_id: null, project_name: (custom && custom.value.trim()) || '' };
  }
  if (value) {
    const opt = [...sel.options].find((o) => o.value === value);
    return { project_id: Number(value), project_name: (opt && opt.dataset && opt.dataset.name) || '' };
  }
  return { project_id: null, project_name: '' };
}

// Marca en el dropdown el proyecto del evento que se está editando.
function selectEventProject(ev) {
  const sel = document.getElementById('event-project');
  const custom = document.getElementById('event-project-custom');
  if (!sel) return;
  const id = ev && ev.project_id != null ? Number(ev.project_id) : null;
  if (id && [...sel.options].some((o) => Number(o.value) === id)) {
    sel.value = String(id);
  } else {
    const name = String((ev && ev.project_name) || '').trim();
    const match = [...sel.options].find((o) => o.value && o.value !== 'custom' && o.dataset.name === name);
    if (match) {
      sel.value = match.value;
    } else if (name && name !== 'OWS') {
      sel.value = 'custom';
      if (custom) custom.value = name;
    } else {
      sel.value = '';
    }
  }
  onEventProjectChange();
}

function setupEventImagePreview() {
  const input = document.getElementById('event-image');
  const zone = document.getElementById('event-dropzone');
  if (!input) return;
  input.addEventListener('change', () => {
    eventImageFile = input.files && input.files[0] ? input.files[0] : null;
    renderEventImagePreview();
    updateEventLivePreview();
  });
  if (zone) {
    ['dragenter', 'dragover'].forEach((evt) => zone.addEventListener(evt, (e) => {
      e.preventDefault();
      zone.classList.add('ev-dropzone-active');
    }));
    ['dragleave', 'drop'].forEach((evt) => zone.addEventListener(evt, (e) => {
      e.preventDefault();
      zone.classList.remove('ev-dropzone-active');
    }));
    zone.addEventListener('drop', (e) => {
      const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
      if (!f) return;
      if (!/^image\//.test(f.type)) return showToast('⚠️ Solo se aceptan imágenes');
      if (f.size > 15 * 1024 * 1024) return showToast('⚠️ La imagen supera los 15 MB');
      const dt = new DataTransfer();
      dt.items.add(f);
      input.files = dt.files;
      eventImageFile = f;
      renderEventImagePreview();
      updateEventLivePreview();
    });
  }
  const urlInput = document.getElementById('event-image-url');
  if (urlInput && !urlInput.dataset.bound) {
    urlInput.dataset.bound = '1';
    urlInput.addEventListener('input', () => {
      if (urlInput.value.trim()) {
        eventImageFile = null;
        const fi = document.getElementById('event-image');
        if (fi) fi.value = '';
      }
      renderEventImagePreview();
    });
  }
}

function currentEventImageSrc(fallback) {
  if (eventImageFile) {
    try { return URL.createObjectURL(eventImageFile); } catch (_) { return ''; }
  }
  const urlEl = document.getElementById('event-image-url');
  const typed = urlEl ? urlEl.value.trim() : '';
  if (typed) return typed;
  return String(fallback || '');
}

function renderEventImagePreview(existingUrl) {
  const preview = document.getElementById('event-image-preview');
  if (!preview) return;
  const src = currentEventImageSrc(existingUrl);
  if (!src) {
    preview.innerHTML = '';
    preview.classList.add('hidden');
    return;
  }
  preview.innerHTML = `
    <img src="${escapeHtml(src)}" alt="portada" data-adm-err="closest:.ev-preview|hidden" />
    <button type="button" class="btn btn-danger btn-mini ev-preview-remove" data-adm-ev="click" data-adm="removeEventImage">✕ Quitar</button>`;
  preview.classList.remove('hidden');
}

function removeEventImage() {
  eventImageFile = null;
  const fi = document.getElementById('event-image');
  if (fi) fi.value = '';
  const urlEl = document.getElementById('event-image-url');
  if (urlEl) urlEl.value = '';
  renderEventImagePreview('');
  updateEventLivePreview();
}

function syncEventPriority(from) {
  const range = document.getElementById('event-priority-range');
  const num = document.getElementById('event-priority');
  const label = document.getElementById('event-priority-label');
  if (!range || !num) return;
  let v = from === 'range' ? Number(range.value) : Number(num.value);
  if (!Number.isFinite(v)) v = 0;
  v = Math.max(0, Math.min(100, Math.round(v)));
  range.value = v;
  num.value = v;
  if (label) label.textContent = String(v);
}

function setEventQuickDate(mode) {
  const startEl = document.getElementById('event-start');
  const endEl = document.getElementById('event-end');
  if (!startEl || !endEl) return;
  const pad = (n) => String(n).padStart(2, '0');
  const toLocal = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  const now = new Date();
  if (mode === 'today') {
    startEl.value = toLocal(now);
    const e = new Date(now.getTime() + 3 * 24 * 3600 * 1000);
    endEl.value = toLocal(e);
  } else if (mode === 'week') {
    const s = startEl.value ? new Date(startEl.value) : now;
    endEl.value = toLocal(new Date(s.getTime() + 7 * 24 * 3600 * 1000));
    if (!startEl.value) startEl.value = toLocal(now);
  } else if (mode === 'month') {
    const s = startEl.value ? new Date(startEl.value) : now;
    endEl.value = toLocal(new Date(s.getTime() + 30 * 24 * 3600 * 1000));
    if (!startEl.value) startEl.value = toLocal(now);
  } else if (mode === 'clear-end') {
    endEl.value = '';
  }
  updateEventLivePreview();
}

function updateEventDurationHint() {
  const hint = document.getElementById('event-duration-hint');
  if (!hint) return;
  const s = document.getElementById('event-start').value;
  const e = document.getElementById('event-end').value;
  if (!s) { hint.textContent = 'Elegí inicio y fin para ver la duración.'; return; }
  if (!e) { hint.textContent = '⏳ Sin fin: el evento quedará abierto hasta que lo finalices.'; return; }
  const ms = new Date(e) - new Date(s);
  if (Number.isNaN(ms) || ms < 0) { hint.textContent = '⚠️ El fin es anterior al inicio.'; return; }
  const days = Math.floor(ms / 86400000);
  const hours = Math.floor((ms % 86400000) / 3600000);
  hint.textContent = days > 0 ? `⏳ Duración: ${days}d ${hours}h.` : hours > 0 ? `⏳ Duración: ${hours}h.` : '⏳ Duración: menos de 1 hora.';
}

function updateEventLivePreview() {
  updateEventDurationHint();
  const box = document.getElementById('event-live-preview');
  if (!box) return;
  const titleEl = document.getElementById('event-title');
  const descEl = document.getElementById('event-desc');
  const catEl = document.getElementById('event-category');
  const startEl = document.getElementById('event-start');
  const endEl = document.getElementById('event-end');
  const tc = document.getElementById('event-title-count');
  const dc = document.getElementById('event-desc-count');
  if (tc && titleEl) tc.textContent = `${titleEl.value.length}/80`;
  if (dc && descEl) dc.textContent = `${descEl.value.length}/280`;
  const cat = eventCategoryMeta(catEl ? catEl.value : 'update');
  const title = titleEl && titleEl.value.trim() ? titleEl.value.trim() : 'Título del evento…';
  const desc = descEl && descEl.value.trim() ? descEl.value.trim() : 'La descripción aparecerá aquí tal como la verán en OWS.';
  const sel = readEventProjectSelection();
  const proj = sel.project_name || 'OWS';
  const src = currentEventImageSrc('');
  const when = startEl && startEl.value
    ? formatEventDate(new Date(startEl.value).toISOString()) + (endEl && endEl.value ? ' → ' + formatEventDate(new Date(endEl.value).toISOString()) : '')
    : 'Sin fecha todavía';
  box.innerHTML = `
    <div class="ev-live-banner">${src ? `<img src="${escapeHtml(src)}" alt="" data-adm-err="rm" />` : '<span>🗓️</span>'}
      <span class="ev-chip ${cat.cls}">${cat.icon} ${cat.label}</span>
    </div>
    <div class="ev-live-body">
      <div class="ev-live-title">${escapeHtml(title)}</div>
      <div class="ev-live-desc">${escapeHtml(desc)}</div>
      <div class="ev-live-meta">📁 ${escapeHtml(proj)} · 🕒 ${escapeHtml(when)}</div>
    </div>`;
  const vis = document.getElementById('event-visible-label');
  const visBox = document.getElementById('event-visible');
  if (vis && visBox) vis.textContent = visBox.checked ? 'Visible en OWS' : 'Oculto (solo admin)';
}

function focusEventForm() {
  const tab = document.getElementById('tab-events');
  if (tab && tab.classList.contains('hidden') && typeof switchAdminTab === 'function') switchAdminTab('events');
  resetEventForm();
  openFormModal('event');
}

function onEventsSearch(v) {
  eventsSearchText = String(v || '').trim().toLowerCase();
  renderAdminEvents();
}

function onEventsFilterChange() {
  const c = document.getElementById('events-filter-category');
  const s = document.getElementById('events-filter-status');
  const o = document.getElementById('events-filter-sort');
  eventsFilterCategory = c ? c.value : '';
  eventsFilterStatus = s ? s.value : '';
  eventsFilterSort = o ? o.value : 'soon';
  renderAdminEvents();
}

function clearEventFilters() {
  eventsSearchText = '';
  eventsFilterCategory = '';
  eventsFilterStatus = '';
  eventsFilterSort = 'soon';
  const si = document.getElementById('events-search');
  const c = document.getElementById('events-filter-category');
  const s = document.getElementById('events-filter-status');
  const o = document.getElementById('events-filter-sort');
  if (si) si.value = '';
  if (c) c.value = '';
  if (s) s.value = '';
  if (o) o.value = 'soon';
  renderAdminEvents();
  showToast('Filtros de eventos limpiados ↺');
}

function setEventsView(v) {
  eventsView = v === 'list' ? 'list' : 'grid';
  const g = document.getElementById('events-view-grid');
  const l = document.getElementById('events-view-list');
  if (g) g.classList.toggle('active', eventsView === 'grid');
  if (l) l.classList.toggle('active', eventsView === 'list');
  renderAdminEvents();
}

function updateEventsStats() {
  const total = eventsCache.length;
  let live = 0, upcoming = 0, ended = 0, hidden = 0;
  eventsCache.forEach((ev) => {
    const ph = getEventPhase(ev);
    if (ph === 'live') live++;
    else if (ph === 'upcoming') upcoming++;
    else if (ph === 'ended') ended++;
    else if (ph === 'hidden') hidden++;
  });
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = String(v); };
  set('ev-stat-total', total);
  set('ev-stat-live', live);
  set('ev-stat-upcoming', upcoming);
  set('ev-stat-ended', ended);
  set('ev-stat-hidden', hidden);
}

async function loadAdminEvents() {
  const list = document.getElementById('events-list');
  if (!list) return;
  try {
    const res = await fetch(API_BASE + '/ows-dashboard/events?include_inactive=1&limit=100');
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    eventsCache = data.events || [];
    populateEventProjectOptions();
    updateEventsStats();
    renderAdminEvents();
  } catch (err) {
    list.innerHTML = `<div class="ev-empty"><span class="ev-empty-icon">⚠️</span><p>${escapeHtml(err.message)}</p></div>`;
  }
}

function filteredEvents() {
  let arr = [...eventsCache];
  if (eventsSearchText) {
    arr = arr.filter((ev) => `${ev.title || ''} ${ev.description || ''} ${ev.project_name || ''}`.toLowerCase().includes(eventsSearchText));
  }
  if (eventsFilterCategory) {
    arr = arr.filter((ev) => String(ev.category || 'update').toLowerCase() === eventsFilterCategory);
  }
  if (eventsFilterStatus) {
    arr = arr.filter((ev) => getEventPhase(ev) === eventsFilterStatus);
  }
  if (eventsFilterSort === 'recent') {
    arr.sort((a, b) => Date.parse(b.created_at || b.starts_at || 0) - Date.parse(a.created_at || a.starts_at || 0));
  } else if (eventsFilterSort === 'priority') {
    arr.sort((a, b) => Number(b.priority || 0) - Number(a.priority || 0));
  } else if (eventsFilterSort === 'az') {
    arr.sort((a, b) => String(a.title || '').localeCompare(String(b.title || '')));
  } else {
    // 'soon': en curso primero, luego programados por fecha, luego resto
    const rank = (ph) => (ph === 'live' ? 0 : ph === 'upcoming' ? 1 : ph === 'hidden' ? 2 : 3);
    arr.sort((a, b) => {
      const r = rank(getEventPhase(a)) - rank(getEventPhase(b));
      if (r !== 0) return r;
      return Date.parse(a.starts_at || a.created_at || 0) - Date.parse(b.starts_at || b.created_at || 0);
    });
  }
  return arr;
}

function renderAdminEvents() {
  const list = document.getElementById('events-list');
  if (!list) return;
  const items = filteredEvents();
  const count = document.getElementById('events-count');
  if (count) count.textContent = `${items.length} evento${items.length === 1 ? '' : 's'}${items.length !== eventsCache.length ? ` (de ${eventsCache.length})` : ''}`;

  list.className = eventsView === 'list' ? 'events-rows' : 'events-grid';

  if (!items.length) {
    list.innerHTML = eventsCache.length
      ? `<div class="ev-empty"><span class="ev-empty-icon">🔎</span><p><b>Sin resultados</b> con esos filtros.</p><button class="btn btn-ghost btn-sm" data-adm-ev="click" data-adm="clearEventFilters">↺ Limpiar filtros</button></div>`
      : `<div class="ev-empty"><span class="ev-empty-icon">🗓️</span><p><b>No hay eventos aún.</b><br />Creá el primero: título, fecha y portada — el resto es opcional.</p><button class="btn btn-primary btn-sm" data-adm-ev="click" data-adm="focusEventForm">＋ Crear primer evento</button></div>`;
    return;
  }

  list.innerHTML = items.map((ev) => {
    const cat = eventCategoryMeta(ev.category);
    const ph = getEventPhase(ev);
    const phm = EVENT_PHASE_META[ph];
    const prog = eventProgress(ev);
    const img = ev.image_url
      ? `<img src="${escapeHtml(ev.image_url)}" alt="" loading="lazy" data-adm-err="rm" />`
      : `<span class="ev-card-fallback">${cat.icon}</span>`;
    const dates = `${formatEventDate(ev.starts_at)}${ev.ends_at ? ' → ' + formatEventDate(ev.ends_at) : ''}`;
    const prio = Number(ev.priority || 0);
    if (eventsView === 'list') {
      return `
      <div class="ev-row ${ph === 'hidden' ? 'is-hidden' : ''}">
        <div class="ev-row-thumb">${img}</div>
        <div class="ev-row-main">
          <div class="ev-row-title">${escapeHtml(ev.title)}</div>
          <div class="ev-row-sub">${escapeHtml(ev.project_name || 'OWS')} · ${escapeHtml(dates)} · ⏳ ${escapeHtml(eventCountdown(ev))}${prio ? ` · ★ ${prio}` : ''}</div>
        </div>
        <span class="ev-chip ${cat.cls}">${cat.icon} ${cat.label}</span>
        <span class="ev-chip ${phm.cls}">${phm.label}</span>
        <div class="ev-card-actions">
          <button class="btn btn-ghost btn-mini" title="Editar" data-adm-ev="click" data-adm="editEvent" data-adm-a0="r:${ev.id}">✏️</button>
          <button class="btn btn-ghost btn-mini" title="Duplicar" data-adm-ev="click" data-adm="duplicateEvent" data-adm-a0="r:${ev.id}">⧉</button>
          <button class="btn btn-ghost btn-mini" title="${ev.is_active ? 'Ocultar' : 'Mostrar'}" data-adm-ev="click" data-adm="toggleEvent" data-adm-a0="r:${ev.id}" data-adm-a1="r:${ev.is_active ? 'false' : 'true'}">${ev.is_active ? '👁️' : '🚫'}</button>
          <button class="btn btn-danger btn-mini" title="Eliminar" data-adm-ev="click" data-adm="deleteEvent" data-adm-a0="r:${ev.id}">🗑️</button>
        </div>
      </div>`;
    }
    return `
    <article class="ev-card ${ph === 'hidden' ? 'is-hidden' : ''} ${ph === 'live' ? 'is-live' : ''}">
      <div class="ev-card-banner">${img}
        <span class="ev-chip ${cat.cls} ev-card-cat">${cat.icon} ${cat.label}</span>
        ${ph === 'live' ? '<span class="ev-live-dot" title="En curso ahora"></span>' : ''}
      </div>
      <div class="ev-card-body">
        <div class="ev-card-title" title="${escapeHtml(ev.title)}">${escapeHtml(ev.title)}</div>
        ${ev.description ? `<div class="ev-card-desc" title="${escapeHtml(ev.description)}">${escapeHtml(ev.description)}</div>` : ''}
        <div class="ev-card-meta">
          <span>📁 ${escapeHtml(ev.project_name || 'OWS')}${ev.project_is_admin ? ' 🛡️ solo admin' : ''}</span>
          <span>🕒 ${escapeHtml(dates)}</span>
          <span>⏳ ${escapeHtml(eventCountdown(ev))}</span>
          ${prio ? `<span>★ Prioridad ${prio}</span>` : ''}
        </div>
        ${prog !== null ? `<div class="ev-progress"><div class="ev-progress-bar" style="width:${prog}%"></div></div>` : ''}
        <div class="ev-card-foot">
          <span class="ev-chip ${phm.cls}">${phm.label}</span>
          <div class="ev-card-actions">
            <button class="btn btn-ghost btn-mini" title="Editar" data-adm-ev="click" data-adm="editEvent" data-adm-a0="r:${ev.id}">✏️</button>
            <button class="btn btn-ghost btn-mini" title="Duplicar" data-adm-ev="click" data-adm="duplicateEvent" data-adm-a0="r:${ev.id}">⧉</button>
            <button class="btn btn-ghost btn-mini" title="${ev.is_active ? 'Ocultar' : 'Mostrar'}" data-adm-ev="click" data-adm="toggleEvent" data-adm-a0="r:${ev.id}" data-adm-a1="r:${ev.is_active ? 'false' : 'true'}">${ev.is_active ? '👁️' : '🚫'}</button>
            <button class="btn btn-danger btn-mini" title="Eliminar" data-adm-ev="click" data-adm="deleteEvent" data-adm-a0="r:${ev.id}">🗑️</button>
          </div>
        </div>
        ${ev.link_url ? `<a class="ev-card-link" href="${escapeHtml(ev.link_url)}" target="_blank" rel="noopener">🔗 Ver más →</a>` : ''}
      </div>
    </article>`;
  }).join('');
}

async function saveEvent(e) {
  if (e && e.preventDefault) e.preventDefault();
  const title = document.getElementById('event-title').value.trim();
  const description = document.getElementById('event-desc').value.trim();
  const category = document.getElementById('event-category').value;
  const proj = readEventProjectSelection();
  const startsAt = document.getElementById('event-start').value;
  const endsAt = document.getElementById('event-end').value;
  const linkUrl = document.getElementById('event-link').value.trim();
  const imageUrlEl = document.getElementById('event-image-url');
  const imageUrl = imageUrlEl ? imageUrlEl.value.trim() : '';
  const priority = Number(document.getElementById('event-priority').value || 0);
  const visBox = document.getElementById('event-visible');
  if (!title) return showToast('⚠️ El título es obligatorio');
  if (!startsAt) return showToast('⚠️ La fecha de inicio es obligatoria');
  if (endsAt && new Date(endsAt) < new Date(startsAt)) return showToast('⚠️ El fin no puede ser anterior al inicio');

  const btn = document.getElementById('btn-save-event');
  btn.disabled = true;
  btn.textContent = '⏳ Guardando…';

  try {
    // multipart/form-data: permite subir imagen a Cloudinary en el mismo request
    const fd = new FormData();
    fd.append('title', title);
    fd.append('description', description);
    fd.append('category', category);
    if (proj.project_id) fd.append('project_id', String(proj.project_id));
    else fd.append('project_id', '');
    fd.append('project_name', proj.project_name || 'OWS');
    fd.append('starts_at', new Date(startsAt).toISOString());
    if (endsAt) fd.append('ends_at', new Date(endsAt).toISOString());
    if (linkUrl) fd.append('link_url', linkUrl);
    fd.append('priority', String(priority));
    if (eventImageFile) fd.append('image', eventImageFile);
    else if (imageUrl) fd.append('image_url', imageUrl);
    else if (editingEventId && !currentEventImageSrc('')) fd.append('image_url', '');
    if (editingEventId && visBox) fd.append('is_active', visBox.checked ? 'true' : 'false');

    let res;
    if (editingEventId) {
      res = await fetch(API_BASE + `/ows-dashboard/events/${editingEventId}`, {
        method: 'PATCH',
        headers: adminHeaders(),
        body: fd
      });
    } else {
      res = await fetch(API_BASE + '/ows-dashboard/events', {
        method: 'POST',
        headers: adminHeaders(),
        body: fd
      });
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    const saved = data.event || null;
    if (saved) {
      const i = eventsCache.findIndex((x) => Number(x.id) === Number(saved.id));
      if (i >= 0) eventsCache[i] = saved;
      else eventsCache.unshift(saved);
    }
    showToast(editingEventId ? 'Evento actualizado ✔' : 'Evento publicado en el calendario ✔');
    resetEventForm();
    await loadAdminEvents();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  } finally {
    btn.disabled = false;
    updateEventSaveLabel();
  }
}

function updateEventSaveLabel() {
  const btn = document.getElementById('btn-save-event');
  if (btn) btn.textContent = editingEventId ? '💾 Guardar cambios' : '💾 Guardar evento';
}

async function editEvent(id) {
  try {
    let item = eventsCache.find((ev) => Number(ev.id) === Number(id));
    if (!item) {
      const res = await fetch(API_BASE + '/ows-dashboard/events?include_inactive=1&limit=100');
      const data = await res.json();
      item = (data.events || []).find((ev) => Number(ev.id) === Number(id));
    }
    if (!item) throw new Error('Evento no encontrado');
    editingEventId = id;
    document.getElementById('event-id').value = id;
    document.getElementById('event-title').value = item.title || '';
    document.getElementById('event-desc').value = item.description || '';
    document.getElementById('event-category').value = item.category || 'update';
    // El dropdown se rellena con el catálogo antes de marcar la opción: si el
    // proyecto del evento no está (eventos viejos a mano), cae en "Otro".
    populateEventProjectOptions();
    selectEventProject(item);
    document.getElementById('event-start').value = localDatetimeValue(item.starts_at);
    document.getElementById('event-end').value = localDatetimeValue(item.ends_at);
    document.getElementById('event-link').value = item.link_url || '';
    document.getElementById('event-priority').value = item.priority || 0;
    const range = document.getElementById('event-priority-range');
    if (range) range.value = item.priority || 0;
    const pl = document.getElementById('event-priority-label');
    if (pl) pl.textContent = String(item.priority || 0);
    const vis = document.getElementById('event-visible');
    if (vis) vis.checked = item.is_active !== false;
    eventImageFile = null;
    document.getElementById('event-image').value = '';
    const urlEl = document.getElementById('event-image-url');
    // Si la imagen actual es URL remota (no blob), mostrarla en el campo URL
    if (urlEl) urlEl.value = item.image_url && /^https?:\/\//i.test(item.image_url) ? item.image_url : '';
    renderEventImagePreview(item.image_url || '');
    document.getElementById('event-form-title').textContent = `Editando: ${item.title || '#' + id}`;
    const mode = document.getElementById('event-form-mode');
    if (mode) { mode.textContent = '✎ Editando'; mode.className = 'status-pill status-from-projects'; }
    document.getElementById('btn-cancel-event').classList.remove('hidden');
    updateEventSaveLabel();
    updateEventLivePreview();
    openFormModal('event');
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

async function duplicateEvent(id) {
  const src = eventsCache.find((ev) => Number(ev.id) === Number(id));
  if (!src) return showToast('⚠️ Evento no encontrado');
  if (!confirm(`¿Duplicar "${src.title}" como evento nuevo?`)) return;
  try {
    const fd = new FormData();
    fd.append('title', `${src.title} (copia)`);
    fd.append('description', src.description || '');
    fd.append('category', src.category || 'update');
    fd.append('project_id', src.project_id != null ? String(src.project_id) : '');
    fd.append('project_name', src.project_name || 'OWS');
    const s = src.starts_at ? new Date(src.starts_at) : new Date();
    fd.append('starts_at', new Date(s.getTime() + 7 * 24 * 3600 * 1000).toISOString());
    if (src.ends_at) {
      const e = new Date(src.ends_at);
      fd.append('ends_at', new Date(e.getTime() + 7 * 24 * 3600 * 1000).toISOString());
    }
    if (src.link_url) fd.append('link_url', src.link_url);
    fd.append('priority', String(src.priority || 0));
    if (src.image_url) fd.append('image_url', src.image_url);
    const res = await fetch(API_BASE + '/ows-dashboard/events', {
      method: 'POST',
      headers: adminHeaders(),
      body: fd
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    showToast('Evento duplicado ✔ (revisá la fecha)');
    await loadAdminEvents();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

function resetEventForm() {
  editingEventId = null;
  eventImageFile = null;
  document.getElementById('event-form-title').textContent = 'Nuevo evento';
  const mode = document.getElementById('event-form-mode');
  if (mode) { mode.textContent = '✦ Creando'; mode.className = 'status-pill status-on'; }
  document.getElementById('btn-cancel-event').classList.add('hidden');
  updateEventSaveLabel();
  ['event-title', 'event-desc', 'event-start', 'event-end', 'event-link', 'event-project-custom'].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  populateEventProjectOptions('');
  const urlEl = document.getElementById('event-image-url');
  if (urlEl) urlEl.value = '';
  document.getElementById('event-category').value = 'update';
  document.getElementById('event-priority').value = 0;
  const range = document.getElementById('event-priority-range');
  if (range) range.value = 0;
  const pl = document.getElementById('event-priority-label');
  if (pl) pl.textContent = '0';
  const vis = document.getElementById('event-visible');
  if (vis) vis.checked = true;
  const fi = document.getElementById('event-image');
  if (fi) fi.value = '';
  renderEventImagePreview('');
  updateEventLivePreview();
  try { closeFormModal(); } catch (_) {}
}

async function toggleEvent(id, newState) {
  try {
    const res = await fetch(API_BASE + `/ows-dashboard/events/${id}`, {
      method: 'PATCH',
      headers: adminHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ is_active: newState })
    });
    if (!res.ok) throw new Error(`Error (${res.status})`);
    const i = eventsCache.findIndex((x) => Number(x.id) === Number(id));
    if (i >= 0) eventsCache[i].is_active = String(newState) === 'true';
    updateEventsStats();
    renderAdminEvents();
    // Sincroniza en segundo plano por si el backend normalizó algo
    loadAdminEvents();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

async function deleteEvent(id) {
  const target = eventsCache.find((x) => Number(x.id) === Number(id));
  if (!confirm(`¿Eliminar "${target ? target.title : 'este evento'}" permanentemente?`)) return;
  try {
    const res = await fetch(API_BASE + `/ows-dashboard/events/${id}`, {
      method: 'DELETE',
      headers: adminHeaders()
    });
    if (!res.ok) throw new Error(`Error (${res.status})`);
    showToast('Evento eliminado');
    eventsCache = eventsCache.filter((x) => Number(x.id) !== Number(id));
    if (editingEventId === id) resetEventForm();
    updateEventsStats();
    renderAdminEvents();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

// =======================================================
// MODALES EMERGENTES — sub-sección de Eventos
// Modales con info + imagen. La tabla indica si se envió y cuándo.
// Cada usuario lo ve UNA vez (show_token en localStorage del cliente).
// Re-mostrar sube show_token sin recrear. Presets = plantillas.
// Endpoints: /ows-dashboard/popups + /ows-dashboard/popup-presets.
// =======================================================

let popupsCache = [];
let presetsCache = [];
let editingPopupId = null;
let popupImageFile = null;

function formatPopupDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleDateString('es-ES', { day: '2-digit', month: 'short', year: 'numeric' }) + ' · ' +
    d.toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit' });
}

function focusPopupForm() {
  resetPopupForm();
  openFormModal('popup');
}

function currentPopupImageSrc(fallback) {
  if (popupImageFile) {
    try { return URL.createObjectURL(popupImageFile); } catch (_) { return ''; }
  }
  const urlEl = document.getElementById('popup-image-url');
  const typed = urlEl ? urlEl.value.trim() : '';
  if (typed) return typed;
  return String(fallback || '');
}

function renderPopupImagePreview(existingUrl) {
  const preview = document.getElementById('popup-image-preview');
  if (!preview) return;
  const src = currentPopupImageSrc(existingUrl);
  if (!src) {
    preview.innerHTML = '';
    preview.classList.add('hidden');
    return;
  }
  preview.innerHTML = `
    <img src="${escapeHtml(src)}" alt="portada" data-adm-err="rm" />
    <button type="button" class="btn btn-danger btn-mini ev-preview-remove" data-adm-ev="click" data-adm="removePopupImage">✕ Quitar</button>`;
  preview.classList.remove('hidden');
}

function removePopupImage() {
  popupImageFile = null;
  const fi = document.getElementById('popup-image');
  if (fi) fi.value = '';
  const urlEl = document.getElementById('popup-image-url');
  if (urlEl) urlEl.value = '';
  renderPopupImagePreview('');
  updatePopupLivePreview();
}

function onPopupKindChange() {
  const kind = (document.getElementById('popup-kind') || {}).value || 'modal';
  const opts = document.getElementById('popup-toast-opts');
  if (opts) opts.classList.toggle('hidden', kind !== 'toast');
  updatePopupLivePreview();
}

function updatePopupLivePreview() {
  const box = document.getElementById('popup-live-preview');
  if (!box) return;
  const title = (document.getElementById('popup-title') || {}).value || '';
  const body = (document.getElementById('popup-body') || {}).value || '';
  const link = (document.getElementById('popup-link') || {}).value || '';
  const linkLabel = (document.getElementById('popup-link-label') || {}).value || '';
  const kind = (document.getElementById('popup-kind') || {}).value || 'modal';
  if (kind === 'toast') {
    const color = (document.getElementById('popup-toast-color') || {}).value || '#f59e0b';
    const pos = (document.getElementById('popup-toast-position') || {}).value || 'top';
    const dur = Math.max(2, Math.min(30, Number((document.getElementById('popup-toast-duration') || {}).value || 6)));
    const tc = document.getElementById('popup-title-count');
    if (tc) tc.textContent = `${title.length}/80`;
    const bc = document.getElementById('popup-body-count');
    if (bc) bc.textContent = `${body.length}/280`;
    box.innerHTML = `
      <div class="ev-live-toastprev" style="background:${escapeHtml(color)}">
        <span>📢</span>
        <span class="ev-live-toastprev-txt">${escapeHtml(title) || '<i>Título…</i>'}</span>
      </div>
      <div class="ev-live-body">
        <div class="ev-live-meta">🍞 Toast ${pos === 'bottom' ? 'abajo' : 'arriba'} · se cierra solo en ${dur}s · una sola vez por usuario.</div>
      </div>`;
    return;
  }
  const src = currentPopupImageSrc('');
  const tc = document.getElementById('popup-title-count');
  if (tc) tc.textContent = `${title.length}/80`;
  const bc = document.getElementById('popup-body-count');
  if (bc) bc.textContent = `${body.length}/280`;
  box.innerHTML = `
    ${src ? `<div class="ev-live-banner"><img src="${escapeHtml(src)}" alt="" data-adm-err="rm" /></div>` : '<div class="ev-live-banner ev-live-banner-empty">📢</div>'}
    <div class="ev-live-body">
      <span class="ev-chip ev-cat-announcement">📢 Anuncio</span>
      <div class="ev-live-title">${escapeHtml(title) || '<i style="opacity:.5">Título del modal…</i>'}</div>
      ${body ? `<div class="ev-live-desc">${escapeHtml(body)}</div>` : ''}
      ${link ? `<span class="btn btn-primary btn-mini" style="pointer-events:none">${escapeHtml(linkLabel || 'Ver más ↗')}</span>` : ''}
      <div class="ev-live-meta">👁️ Así lo verá el usuario — una sola vez.</div>
    </div>`;
}

function bindPopupImageInput() {
  const input = document.getElementById('popup-image');
  if (input && !input.dataset.bound) {
    input.dataset.bound = '1';
    input.addEventListener('change', () => {
      popupImageFile = input.files && input.files[0] ? input.files[0] : null;
      renderPopupImagePreview();
      updatePopupLivePreview();
    });
    const zone = document.getElementById('popup-dropzone');
    if (zone) {
      zone.addEventListener('drop', (e) => {
        const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
        if (!f) return;
        if (!/^image\//.test(f.type)) return showToast('⚠️ Solo se aceptan imágenes');
        if (f.size > 15 * 1024 * 1024) return showToast('⚠️ La imagen supera los 15 MB');
        const dt = new DataTransfer();
        dt.items.add(f);
        input.files = dt.files;
        popupImageFile = f;
        renderPopupImagePreview();
        updatePopupLivePreview();
      });
    }
  }
  const urlInput = document.getElementById('popup-image-url');
  if (urlInput && !urlInput.dataset.bound) {
    urlInput.dataset.bound = '1';
    urlInput.addEventListener('input', () => {
      if (urlInput.value.trim()) {
        popupImageFile = null;
        const fi = document.getElementById('popup-image');
        if (fi) fi.value = '';
      }
      renderPopupImagePreview();
    });
  }
}

async function loadEventPopups(silent) {
  const list = document.getElementById('popups-list');
  if (!list) return;
  bindPopupImageInput();
  try {
    const res = await fetch(API_BASE + '/ows-dashboard/popups', { headers: adminHeaders() });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    popupsCache = data.popups || [];
    renderEventPopups();
  } catch (err) {
    if (!silent) list.innerHTML = `<div class="ev-empty"><span class="ev-empty-icon">⚠️</span><p>${escapeHtml(err.message)}</p><button class="btn btn-ghost btn-sm" data-adm-ev="click" data-adm="loadEventPopups" data-adm-a0="b:1">Reintentar</button></div>`;
  }
}

function updatePopupStats() {
  const total = popupsCache.length;
  const sent = popupsCache.filter((p) => p.is_sent).length;
  const draft = popupsCache.filter((p) => !p.is_sent).length;
  const hidden = popupsCache.filter((p) => p.is_active === false).length;
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = String(v); };
  set('pop-stat-total', total);
  set('pop-stat-sent', sent);
  set('pop-stat-draft', draft);
  set('pop-stat-hidden', hidden);
}

function renderEventPopups() {
  const list = document.getElementById('popups-list');
  if (!list) return;
  updatePopupStats();
  const count = document.getElementById('popups-count');
  if (count) count.textContent = `${popupsCache.length} modal${popupsCache.length === 1 ? '' : 'es'}`;
  if (!popupsCache.length) {
    list.innerHTML = `<div class="ev-empty"><span class="ev-empty-icon">💬</span><p><b>No hay modales aún.</b><br />Creá el primero: título + info + imagen, y envialo cuando quieras.</p><button class="btn btn-primary btn-sm" data-adm-ev="click" data-adm="focusPopupForm">＋ Crear primer modal</button></div>`;
    return;
  }
  list.innerHTML = popupsCache.map((p) => {
    const thumb = p.image_url
      ? `<img src="${escapeHtml(p.image_url)}" alt="" loading="lazy" data-adm-err="rm" />`
      : `<span class="ev-card-fallback">📢</span>`;
    const kindChip = String(p.kind || 'modal') === 'toast'
      ? `<span class="ev-chip ev-cat-announcement">🍞 Toast <i class="ev-dot" style="background:${escapeHtml(p.toast_color || p.toastColor || '#f59e0b')}"></i></span>`
      : '<span class="ev-chip ev-cat-event">💬 Modal</span>';
    const stateChip = p.is_sent
      ? '<span class="ev-chip ev-phase-live">✔ Enviado</span>'
      : '<span class="ev-chip ev-phase-upcoming">✏️ Borrador</span>';
    const visChip = p.is_active
      ? '<span class="ev-chip ev-phase-live">👁️ Visible</span>'
      : '<span class="ev-chip ev-phase-hidden">🚫 Oculto</span>';
    return `
    <div class="ev-row ${p.is_active === false ? 'is-hidden' : ''}">
      <div class="ev-row-thumb">${thumb}</div>
      <div class="ev-row-main">
        <div class="ev-row-title">${escapeHtml(p.title)}</div>
        <div class="ev-row-sub">📤 ${p.is_sent ? escapeHtml(formatPopupDate(p.sent_at)) : 'sin enviar'} · 🔁 muestra #${Number(p.show_token || 1)}${p.link_url ? ' · 🔗 con botón' : ''}</div>
      </div>
      ${kindChip}
      ${stateChip}
      ${visChip}
      <div class="ev-card-actions">
        ${!p.is_sent ? `<button class="btn btn-primary btn-mini" title="Enviar a los usuarios (aparece 1 vez)" data-adm-ev="click" data-adm="sendPopup" data-adm-a0="r:${p.id}">📤 Enviar</button>` : ''}
        ${p.is_sent ? `<button class="btn btn-ghost btn-mini" title="Vuelve a aparecer a todos sin recrear" data-adm-ev="click" data-adm="reshowPopup" data-adm-a0="r:${p.id}">🔁 Re-mostrar</button>` : ''}
        <button class="btn btn-ghost btn-mini" title="${p.is_active ? 'Ocultar' : 'Mostrar'}" data-adm-ev="click" data-adm="togglePopup" data-adm-a0="r:${p.id}" data-adm-a1="r:${p.is_active ? 'false' : 'true'}">${p.is_active ? '👁️' : '🚫'}</button>
        <button class="btn btn-ghost btn-mini" title="Editar" data-adm-ev="click" data-adm="editPopup" data-adm-a0="r:${p.id}">✏️</button>
        <button class="btn btn-danger btn-mini" title="Eliminar" data-adm-ev="click" data-adm="deletePopup" data-adm-a0="r:${p.id}">🗑️</button>
      </div>
    </div>`;
  }).join('');
}

async function savePopup(e) {
  if (e && e.preventDefault) e.preventDefault();
  const title = document.getElementById('popup-title').value.trim();
  const body = document.getElementById('popup-body').value.trim();
  const linkUrl = document.getElementById('popup-link').value.trim();
  const linkLabel = document.getElementById('popup-link-label').value.trim();
  const imageUrlEl = document.getElementById('popup-image-url');
  const imageUrl = imageUrlEl ? imageUrlEl.value.trim() : '';
  const visBox = document.getElementById('popup-visible');
  if (!title) return showToast('⚠️ El título es obligatorio');
  const btn = document.getElementById('btn-save-popup');
  btn.disabled = true;
  btn.textContent = '⏳ Guardando…';
  try {
    const fd = new FormData();
    fd.append('title', title);
    fd.append('body', body);
    if (linkUrl) fd.append('link_url', linkUrl);
    if (linkLabel) fd.append('link_label', linkLabel);
    const kind = (document.getElementById('popup-kind') || {}).value || 'modal';
    fd.append('kind', kind);
    if (kind === 'toast') {
      fd.append('toast_color', (document.getElementById('popup-toast-color') || {}).value || '#f59e0b');
      fd.append('toast_position', (document.getElementById('popup-toast-position') || {}).value || 'top');
      const durSec = Math.max(2, Math.min(30, Number((document.getElementById('popup-toast-duration') || {}).value || 6)));
      fd.append('duration_ms', String(durSec * 1000));
    }
    if (popupImageFile) fd.append('image', popupImageFile);
    else if (imageUrl) fd.append('image_url', imageUrl);
    else if (editingPopupId && !currentPopupImageSrc('')) fd.append('image_url', '');
    if (editingPopupId && visBox) fd.append('is_active', visBox.checked ? 'true' : 'false');
    let res;
    if (editingPopupId) {
      res = await fetch(API_BASE + `/ows-dashboard/popups/${editingPopupId}`, {
        method: 'PATCH', headers: adminHeaders(), body: fd
      });
    } else {
      res = await fetch(API_BASE + '/ows-dashboard/popups', {
        method: 'POST', headers: adminHeaders(), body: fd
      });
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    showToast(editingPopupId ? 'Modal actualizado ✔' : 'Modal guardado como borrador ✔ (envialo cuando quieras)');
    resetPopupForm();
    await loadEventPopups();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = editingPopupId ? '💾 Guardar cambios' : '💾 Guardar modal';
  }
}

function editPopup(id) {
  const item = popupsCache.find((p) => Number(p.id) === Number(id));
  if (!item) return showToast('⚠️ Modal no encontrado');
  editingPopupId = id;
  document.getElementById('popup-id').value = id;
  document.getElementById('popup-title').value = item.title || '';
  document.getElementById('popup-body').value = item.body || '';
  document.getElementById('popup-link').value = item.link_url || '';
  document.getElementById('popup-link-label').value = item.link_label || '';
  document.getElementById('popup-kind').value = item.kind === 'toast' ? 'toast' : 'modal';
  const tcEl = document.getElementById('popup-toast-color');
  if (tcEl) tcEl.value = item.toast_color || item.toastColor || '#f59e0b';
  const tpEl = document.getElementById('popup-toast-position');
  if (tpEl) tpEl.value = item.toast_position || item.toastPosition || 'top';
  const tdEl = document.getElementById('popup-toast-duration');
  if (tdEl) tdEl.value = Math.round(Number(item.duration_ms || item.durationMs || 6000) / 1000);
  onPopupKindChange();
  const vis = document.getElementById('popup-visible');
  if (vis) vis.checked = item.is_active !== false;
  popupImageFile = null;
  document.getElementById('popup-image').value = '';
  const urlEl = document.getElementById('popup-image-url');
  if (urlEl) urlEl.value = item.image_url && /^https?:\/\//i.test(item.image_url) ? item.image_url : '';
  renderPopupImagePreview(item.image_url || '');
  document.getElementById('popup-form-title').textContent = `Editando: ${item.title || '#' + id}`;
  const mode = document.getElementById('popup-form-mode');
  if (mode) { mode.textContent = '✎ Editando'; mode.className = 'status-pill status-from-projects'; }
  document.getElementById('btn-cancel-popup').classList.remove('hidden');
  document.getElementById('btn-save-popup').textContent = '💾 Guardar cambios';
  updatePopupLivePreview();
  openFormModal('popup');
}

function resetPopupForm() {
  editingPopupId = null;
  popupImageFile = null;
  document.getElementById('popup-form-title').textContent = 'Nuevo modal';
  const mode = document.getElementById('popup-form-mode');
  if (mode) { mode.textContent = '✦ Creando'; mode.className = 'status-pill status-on'; }
  document.getElementById('btn-cancel-popup').classList.add('hidden');
  document.getElementById('btn-save-popup').textContent = '💾 Guardar modal';
  ['popup-title', 'popup-body', 'popup-link', 'popup-link-label', 'popup-image-url'].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  const kindEl = document.getElementById('popup-kind');
  if (kindEl) kindEl.value = 'modal';
  const tcEl = document.getElementById('popup-toast-color');
  if (tcEl) tcEl.value = '#f59e0b';
  const tpEl = document.getElementById('popup-toast-position');
  if (tpEl) tpEl.value = 'top';
  const tdEl = document.getElementById('popup-toast-duration');
  if (tdEl) tdEl.value = 6;
  const toastOpts = document.getElementById('popup-toast-opts');
  if (toastOpts) toastOpts.classList.add('hidden');
  const vis = document.getElementById('popup-visible');
  if (vis) vis.checked = true;
  const fi = document.getElementById('popup-image');
  if (fi) fi.value = '';
  renderPopupImagePreview('');
  updatePopupLivePreview();
  try { closeFormModal(); } catch (_) {}
}

async function deletePopup(id) {
  const target = popupsCache.find((x) => Number(x.id) === Number(id));
  if (!confirm(`¿Eliminar "${target ? target.title : 'este modal'}" permanentemente?`)) return;
  try {
    const res = await fetch(API_BASE + `/ows-dashboard/popups/${id}`, {
      method: 'DELETE', headers: adminHeaders()
    });
    if (!res.ok) throw new Error(`Error (${res.status})`);
    showToast('Modal eliminado');
    popupsCache = popupsCache.filter((x) => Number(x.id) !== Number(id));
    if (editingPopupId === id) resetPopupForm();
    renderEventPopups();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

async function togglePopup(id, newState) {
  try {
    const res = await fetch(API_BASE + `/ows-dashboard/popups/${id}`, {
      method: 'PATCH',
      headers: adminHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ is_active: newState })
    });
    if (!res.ok) throw new Error(`Error (${res.status})`);
    const data = await res.json().catch(() => ({}));
    const i = popupsCache.findIndex((x) => Number(x.id) === Number(id));
    if (i >= 0) popupsCache[i] = data.popup || { ...popupsCache[i], is_active: String(newState) === 'true' };
    renderEventPopups();
    loadEventPopups(true);
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

async function sendPopup(id) {
  const target = popupsCache.find((x) => Number(x.id) === Number(id));
  if (!confirm(`¿Enviar "${target ? target.title : 'este modal'}"? Aparecerá UNA vez a cada usuario.`)) return;
  try {
    const res = await fetch(API_BASE + `/ows-dashboard/popups/${id}/send`, {
      method: 'POST', headers: adminHeaders()
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    showToast('📤 Modal enviado: los usuarios lo verán una vez ✔');
    await loadEventPopups();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

async function reshowPopup(id) {
  const target = popupsCache.find((x) => Number(x.id) === Number(id));
  if (!confirm(`¿Volver a mostrar "${target ? target.title : 'este modal'}" a todos? No se recrea nada.`)) return;
  try {
    const res = await fetch(API_BASE + `/ows-dashboard/popups/${id}/reshow`, {
      method: 'POST', headers: adminHeaders()
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    showToast(`🔁 Re-mostrado (muestra #${data.popup ? data.popup.show_token : '?'}) ✔`);
    await loadEventPopups();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

// ── Presets ──
async function loadPopupPresets(silent) {
  const list = document.getElementById('popup-presets-list');
  if (!list) return;
  try {
    const res = await fetch(API_BASE + '/ows-dashboard/popup-presets', { headers: adminHeaders() });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    presetsCache = data.presets || [];
    renderPopupPresets();
  } catch (err) {
    if (!silent) list.innerHTML = `<div class="ev-empty"><span class="ev-empty-icon">⚠️</span><p>${escapeHtml(err.message)}</p><button class="btn btn-ghost btn-sm" data-adm-ev="click" data-adm="loadPopupPresets" data-adm-a0="b:1">Reintentar</button></div>`;
  }
}

function renderPopupPresets() {
  const list = document.getElementById('popup-presets-list');
  if (!list) return;
  const count = document.getElementById('presets-count');
  if (count) count.textContent = `${presetsCache.length} preset${presetsCache.length === 1 ? '' : 's'}`;
  if (!presetsCache.length) {
    list.innerHTML = `<div class="ev-empty"><span class="ev-empty-icon">🎨</span><p><b>No hay presets aún.</b><br />Guardá el primero desde el formulario o desde un modal con “Guardar como preset”.</p></div>`;
    return;
  }
  list.innerHTML = presetsCache.map((p) => {
    const thumb = p.image_url
      ? `<img src="${escapeHtml(p.image_url)}" alt="" loading="lazy" data-adm-err="rm" />`
      : `<span class="ev-card-fallback">🎨</span>`;
    const kindChip = String(p.kind || 'modal') === 'toast'
      ? `<span class="ev-chip ev-cat-announcement">🍞 Toast <i class="ev-dot" style="background:${escapeHtml(p.toast_color || p.toastColor || '#f59e0b')}"></i></span>`
      : '<span class="ev-chip ev-cat-event">💬 Modal</span>';
    return `
    <div class="ev-row">
      <div class="ev-row-thumb">${thumb}</div>
      <div class="ev-row-main">
        <div class="ev-row-title">🎨 ${escapeHtml(p.name)}</div>
        <div class="ev-row-sub">${escapeHtml(p.title || '— sin título —')}${p.link_url ? ' · 🔗 con botón' : ''}</div>
      </div>
      ${kindChip}
      <div class="ev-card-actions">
        <button class="btn btn-primary btn-mini" title="Cargar en el formulario de Modales" data-adm-ev="click" data-adm="usePreset" data-adm-a0="r:${p.id}">⬆️ Usar</button>
        <button class="btn btn-danger btn-mini" title="Eliminar preset" data-adm-ev="click" data-adm="deletePreset" data-adm-a0="r:${p.id}">🗑️</button>
      </div>
    </div>`;
  }).join('');
}

async function savePreset(e) {
  if (e && e.preventDefault) e.preventDefault();
  const name = document.getElementById('preset-name').value.trim();
  const title = document.getElementById('preset-title').value.trim();
  const body = document.getElementById('preset-body').value.trim();
  const imageUrl = document.getElementById('preset-image-url').value.trim();
  const linkUrl = document.getElementById('preset-link').value.trim();
  const linkLabel = document.getElementById('preset-link-label').value.trim();
  const kind = (document.getElementById('preset-kind') || {}).value || 'modal';
  const toastColor = (document.getElementById('preset-toast-color') || {}).value || '#f59e0b';
  const toastPosition = (document.getElementById('preset-toast-position') || {}).value || 'top';
  const durSec = Math.max(2, Math.min(30, Number((document.getElementById('preset-toast-duration') || {}).value || 6)));
  if (!name) return showToast('⚠️ El nombre del preset es obligatorio');
  const btn = document.getElementById('btn-save-preset');
  btn.disabled = true;
  btn.textContent = '⏳ Guardando…';
  try {
    const res = await fetch(API_BASE + '/ows-dashboard/popup-presets', {
      method: 'POST',
      headers: adminHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ name, title, body, image_url: imageUrl, link_url: linkUrl, link_label: linkLabel, kind, toast_color: toastColor, toast_position: toastPosition, duration_ms: durSec * 1000 })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    showToast('Preset guardado ✔');
    resetPresetForm();
    await loadPopupPresets();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = '💾 Guardar preset';
  }
}

function resetPresetForm() {
  ['preset-name', 'preset-title', 'preset-body', 'preset-image-url', 'preset-link', 'preset-link-label'].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  const kindEl = document.getElementById('preset-kind');
  if (kindEl) kindEl.value = 'modal';
  const tcEl = document.getElementById('preset-toast-color');
  if (tcEl) tcEl.value = '#f59e0b';
  const tpEl = document.getElementById('preset-toast-position');
  if (tpEl) tpEl.value = 'top';
  const tdEl = document.getElementById('preset-toast-duration');
  if (tdEl) tdEl.value = 6;
  try { closeFormModal(); } catch (_) {}
}

async function deletePreset(id) {
  const target = presetsCache.find((x) => Number(x.id) === Number(id));
  if (!confirm(`¿Eliminar el preset "${target ? target.name : ''}"?`)) return;
  try {
    const res = await fetch(API_BASE + `/ows-dashboard/popup-presets/${id}`, {
      method: 'DELETE', headers: adminHeaders()
    });
    if (!res.ok) throw new Error(`Error (${res.status})`);
    showToast('Preset eliminado');
    presetsCache = presetsCache.filter((x) => Number(x.id) !== Number(id));
    renderPopupPresets();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

// Carga un preset en el formulario de Modales (cambia a esa sub-sección)
function usePreset(id) {
  const p = presetsCache.find((x) => Number(x.id) === Number(id));
  if (!p) return showToast('⚠️ Preset no encontrado');
  resetPopupForm();
  document.getElementById('popup-title').value = p.title || '';
  document.getElementById('popup-body').value = p.body || '';
  document.getElementById('popup-link').value = p.link_url || '';
  document.getElementById('popup-link-label').value = p.link_label || '';
  document.getElementById('popup-kind').value = p.kind === 'toast' ? 'toast' : 'modal';
  const tcEl = document.getElementById('popup-toast-color');
  if (tcEl) tcEl.value = p.toast_color || p.toastColor || '#f59e0b';
  const tpEl = document.getElementById('popup-toast-position');
  if (tpEl) tpEl.value = p.toast_position || p.toastPosition || 'top';
  const tdEl = document.getElementById('popup-toast-duration');
  if (tdEl) tdEl.value = Math.round(Number(p.duration_ms || p.durationMs || 6000) / 1000);
  onPopupKindChange();
  const urlEl = document.getElementById('popup-image-url');
  if (urlEl) urlEl.value = p.image_url && /^https?:\/\//i.test(p.image_url) ? p.image_url : '';
  popupImageFile = null;
  renderPopupImagePreview(p.image_url || '');
  updatePopupLivePreview();
  switchAdminSub('events', 'popups');
  showToast(`Preset “${p.name}” cargado: revisá y guardá ✔`);
  openFormModal('popup');
}

// Guarda el formulario actual de Modales como preset (pide el nombre en Presets)
function savePopupFormAsPreset() {
  document.getElementById('preset-name').value = '';
  document.getElementById('preset-title').value = document.getElementById('popup-title').value || '';
  document.getElementById('preset-body').value = document.getElementById('popup-body').value || '';
  document.getElementById('preset-image-url').value = document.getElementById('popup-image-url').value || '';
  document.getElementById('preset-link').value = document.getElementById('popup-link').value || '';
  document.getElementById('preset-link-label').value = document.getElementById('popup-link-label').value || '';
  document.getElementById('preset-kind').value = document.getElementById('popup-kind').value || 'modal';
  const tcEl = document.getElementById('preset-toast-color');
  if (tcEl) tcEl.value = document.getElementById('popup-toast-color').value || '#f59e0b';
  const tpEl = document.getElementById('preset-toast-position');
  if (tpEl) tpEl.value = document.getElementById('popup-toast-position').value || 'top';
  const tdEl = document.getElementById('preset-toast-duration');
  if (tdEl) tdEl.value = document.getElementById('popup-toast-duration').value || 6;
  switchAdminSub('events', 'presets');
  showToast('Poné un nombre y guardá el preset 🎨');
  openFormModal('preset');
  const n = document.getElementById('preset-name');
  if (n) setTimeout(() => n.focus({ preventScroll: true }), 350);
}

// =======================================================
// PROYECTOS OWS (lanzables — catálogo exclusivo, NO el de OWS Store)
// Endpoint: /ows-launch-projects (tabla ows_launch_projects)
// =======================================================

const LAUNCH_STATUS_META = {
  development:  { label: 'En desarrollo', cls: 'status-chip-dev' },
  soon:         { label: 'Próximamente',  cls: 'status-chip-soon' },
  launched:     { label: 'Lanzado',       cls: 'status-chip-launched' },
  cancelled:    { label: 'Cancelado',     cls: 'status-chip-cancelled' },
  discontinued: { label: 'Descontinuado', cls: 'status-chip-discontinued' }
};

// Feedback obligatorio por estado (solo-admin): cada estado pide justificar
// por qué se eligió. El campo aparece con animación al cambiar el estado.
const MANAGE_STATUS_FEEDBACK = {
  development: {
    tag: 'En desarrollo',
    placeholder: '¿En qué punto está el desarrollo? Contá avances, bloqueos o próximos pasos.',
    hint: 'Obligatorio: explicá por qué sigue en desarrollo y qué falta.'
  },
  soon: {
    tag: 'Próximamente',
    placeholder: '¿Por qué pasa a próximamente? Indicá qué falta para lanzarlo y cuándo.',
    hint: 'Obligatorio: justificá qué lo acerca al lanzamiento.'
  },
  launched: {
    tag: 'Lanzado',
    placeholder: '¿Por qué se considera lanzado? Indicá versión, dónde está disponible o notas del lanzamiento.',
    hint: 'Obligatorio: dejá constancia del lanzamiento (versión, alcance).'
  },
  cancelled: {
    tag: 'Cancelado',
    placeholder: '¿Por qué se cancela? Dejá el motivo para el registro.',
    hint: 'Obligatorio: el motivo de la cancelación queda registrado.'
  },
  discontinued: {
    tag: 'Descontinuado',
    placeholder: '¿Por qué se descontinúa? Indicá motivo, reemplazo si lo hay y fecha de corte.',
    hint: 'Obligatorio: motivo del fin del proyecto y qué lo reemplaza (si aplica).'
  }
};

function manageFeedbackKey(status) {
  const k = String(status || 'development').trim().toLowerCase();
  return MANAGE_STATUS_FEEDBACK[k] ? k : 'development';
}

// Actualiza etiqueta, placeholder y ayuda del feedback según el estado.
// Con animate=true re-dispara la animación de aparición del campo.
function updateManageFeedbackField(animate) {
  const sel = document.getElementById('mproj-status');
  const wrap = document.getElementById('mproj-feedback-wrap');
  const area = document.getElementById('mproj-feedback');
  const tag = document.getElementById('mproj-feedback-tag');
  const hint = document.getElementById('mproj-feedback-hint');
  if (!sel || !wrap || !area) return;
  const key = manageFeedbackKey(sel.value);
  const meta = MANAGE_STATUS_FEEDBACK[key];
  if (tag) tag.textContent = meta.tag;
  area.placeholder = meta.placeholder;
  if (hint) hint.textContent = meta.hint;
  wrap.classList.remove('feedback-development', 'feedback-soon', 'feedback-launched', 'feedback-cancelled', 'feedback-discontinued');
  wrap.classList.add('feedback-' + key);
  if (animate) {
    wrap.classList.remove('feedback-animate');
    void wrap.offsetWidth; // reflow: reinicia la animación
    wrap.classList.add('feedback-animate');
  }
}

// Permanencia del estado: solo tiene sentido en estados terminales.
// Cancelado — ¿definitivo o en pausa? Descontinuado — ¿fin de vida o pausa?
// En desarrollo / próximamente / lanzado el campo ni aparece (no aplica).
const MANAGE_PERMANENCE_STATES = new Set(['cancelled', 'discontinued']);

const MANAGE_PERMANENCE_HINTS = {
  cancelled: '¿La cancelación es permanente (definitiva) o temporal (el proyecto podría retomarse)?',
  discontinued: '¿La descontinuación es permanente (fin de vida) o temporal (pausa con posible retorno)?'
};

function manageNeedsPermanence(status) {
  return MANAGE_PERMANENCE_STATES.has(String(status || '').trim().toLowerCase());
}

// Punto único al cambiar el estado: refresca feedback + permanencia.
function onManageStatusChange() {
  updateManageFeedbackField(true);
  updateManagePermanenceField(true);
}

// Muestra el bloque de permanencia solo cuando el estado lo requiere,
// con la misma animación de aparición del feedback.
function updateManagePermanenceField(animate) {
  const sel = document.getElementById('mproj-status');
  const wrap = document.getElementById('mproj-permanence-wrap');
  const hint = document.getElementById('mproj-permanence-hint');
  if (!sel || !wrap) return;
  const key = String(sel.value || '').trim().toLowerCase();
  if (!manageNeedsPermanence(key)) {
    wrap.classList.add('hidden');
    return;
  }
  if (hint) hint.textContent = MANAGE_PERMANENCE_HINTS[key] || '';
  wrap.classList.remove('hidden');
  if (animate) {
    wrap.classList.remove('feedback-animate');
    void wrap.offsetWidth;
    wrap.classList.add('feedback-animate');
  }
}

// Lee la permanencia elegida: true = permanente, false = temporal, null = sin elegir.
function getManagePermanence() {
  const checked = document.querySelector('input[name="mproj-perm"]:checked');
  if (!checked) return null;
  return checked.value === 'permanent' ? true : (checked.value === 'temporary' ? false : null);
}

function setManagePermanence(value) {
  document.querySelectorAll('input[name="mproj-perm"]').forEach((r) => {
    r.checked = (value === true && r.value === 'permanent') || (value === false && r.value === 'temporary');
  });
}

function managePermanenceChip(p) {
  const v = (p.status_permanent !== undefined) ? p.status_permanent : p.statusPermanent;
  if (v === true) return '<span class="status-pill status-perm-permanent">🔒 Permanente</span>';
  if (v === false) return '<span class="status-pill status-perm-temporary">⏸️ Temporal</span>';
  return '';
}

const PLATFORM_KEYS = ['windows', 'android', 'web', 'mac', 'linux'];

function launchStatusMeta(status) {
  return LAUNCH_STATUS_META[String(status || '').trim().toLowerCase()] || LAUNCH_STATUS_META.development;
}

function readPlatformChecks() {
  return PLATFORM_KEYS.filter((k) => {
    const el = document.getElementById(`plat-${k}`);
    return el && el.checked;
  });
}

// =======================================================
// PROYECTOS — subida directa de imagenes a Cloudinary
// =======================================================

async function uploadProjectImage(file, kind) {
  // kind: 'icon' | 'banner' — solo para el public_id y el mensaje de error
  const fd = new FormData();
  fd.append('file', file);
  fd.append('upload_preset', CLOUDINARY_UPLOAD_PRESET);
  fd.append('public_id', `${kind}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
  const res = await fetch(`https://api.cloudinary.com/v1_1/${CLOUDINARY_CLOUD}/image/upload`, {
    method: 'POST',
    body: fd
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data.secure_url) {
    throw new Error(data?.error?.message || `No se pudo subir la imagen del ${kind} (${res.status})`);
  }
  return data.secure_url;
}

function wireProjectImageInput(inputId, previewId, setFile) {
  const input = document.getElementById(inputId);
  if (!input) return;
  input.addEventListener('change', () => {
    const file = input.files && input.files[0] ? input.files[0] : null;
    setFile(file);
    const preview = document.getElementById(previewId);
    if (file) {
      const url = URL.createObjectURL(file);
      preview.innerHTML = `<img src="${url}" alt="preview" />`;
      preview.classList.remove('hidden');
    } else {
      preview.innerHTML = '';
      preview.classList.add('hidden');
    }
  });
}

function clearProjectImageFiles() {
  projIconFile = null;
  projBannerFile = null;
  ['proj-icon-file', 'proj-banner-file'].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  ['proj-icon-preview', 'proj-banner-preview'].forEach((id) => {
    const el = document.getElementById(id);
    if (el) { el.innerHTML = ''; el.classList.add('hidden'); }
  });
}

function setupProjectImageInputs() {
  wireProjectImageInput('proj-icon-file', 'proj-icon-preview', (f) => { projIconFile = f; });
  wireProjectImageInput('proj-banner-file', 'proj-banner-preview', (f) => { projBannerFile = f; });
  wireProjectImageInput('mproj-icon-file', 'mproj-icon-preview', (f) => { manageIconFile = f; });
  wireProjectImageInput('mproj-banner-file', 'mproj-banner-preview', (f) => { manageBannerFile = f; });
}

function writePlatformChecks(platforms) {
  const list = Array.isArray(platforms) ? platforms.map((p) => String(p).toLowerCase()) : [];
  PLATFORM_KEYS.forEach((k) => {
    const el = document.getElementById(`plat-${k}`);
    if (el) el.checked = list.includes(k);
  });
}

// Porcentaje de desarrollo de un proyecto (viene de ows_project_development,
// la MISMA tabla que usa Gestión: el % es uno solo, no dos copias).
function projectProgressFor(p) {
  const pid = Number(p?.id || 0);
  const d = devProgressCache.find((x) => Number(x.project_id) === pid);
  return d ? round2(d.percent) : null;
}

// El % solo tiene sentido mientras el proyecto NO salió: 'En desarrollo' y
// 'Próximamente' son editables; 'Lanzado' ya está terminado.
function projectTracksProgress(p) {
  const s = String(p?.status || '').trim().toLowerCase();
  return s === 'development' || s === 'soon';
}

function projectProgressHtml(p) {
  const status = String(p?.status || '').trim().toLowerCase();
  if (status === 'launched') return '<span class="proj-prog-done">🎉 Ya lanzado</span>';
  if (!projectTracksProgress(p)) return '';
  const tracked = projectProgressFor(p);
  const v = tracked === null ? 0 : tracked;
  return `
    <div class="proj-prog">
      <div class="proj-prog-bar" title="${fmtPct(v)} completado"><div class="proj-prog-fill" style="width:${v}%"></div></div>
      <span class="proj-prog-pct">${fmtPct(v)}</span>
      ${tracked === null ? '<span class="proj-prog-none">sin registrar</span>' : ''}
    </div>`;
}

async function loadAdminProjects() {
  const list = document.getElementById('projects-list');
  if (!list) return;
  try {
    // include_hidden=1: el panel necesita ver tambien los proyectos ocultos.
    // Aquí se muestran SOLO los públicos (admin_only = false); los
    // solo-admin viven en la sección Gestión.
    const res = await fetch(API_BASE + '/ows-launch-projects?include_hidden=1');
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    const all = data.projects || [];
    hiddenAdminOnlyCount = all.filter((p) => p.admin_only === true || p.adminOnly === true).length;
    projectsCache = all.filter((p) => !(p.admin_only === true || p.adminOnly === true));
    renderAdminProjectsList();
    // El catálogo cambió: el dropdown de proyecto de Eventos se rearma.
    populateEventProjectOptions();
  } catch (err) {
    list.innerHTML = `<p class="loading-note">⚠️ ${escapeHtml(err.message)}</p>`;
  }
}

// Render separado del fetch: permite repintar la lista al cambiar un %
// sin volver a pegarle al servidor.
function renderAdminProjectsList() {
  const list = document.getElementById('projects-list');
  if (!list) return;
  if (!projectsCache.length) {
    list.innerHTML = (hiddenAdminOnlyCount
      ? `<p class="loading-note">🔒 Hay ${hiddenAdminOnlyCount} proyecto(s) solo-admin en Gestión. No hay proyectos disponibles aún. Crea el primero ←</p>`
      : '<p class="loading-note">No hay proyectos OWS aún. Crea el primero ←</p>');
    return;
  }
  const notice = hiddenAdminOnlyCount
    ? `<p class="loading-note" style="margin-bottom:8px">🔒 ${hiddenAdminOnlyCount} proyecto(s) solo-admin viven en <b>Gestión</b> (no se listan aquí).</p>`
    : '';
  list.innerHTML = notice + projectsCache.map((p) => {
    const meta = launchStatusMeta(p.status);
    const latestVer = (p.latest_release && p.latest_release.version) || (p.latestRelease && p.latestRelease.version) || p.itch_version || p.itchVersion || '';
    const chips = [
      `<span class="status-pill ${meta.cls}">${meta.label}</span>`,
      (p.has_release || p.hasRelease || latestVer) ? `<span class="status-pill status-on">📦 v${escapeHtml(latestVer || '?')}</span>` : '<span class="status-pill">📦 sin versión</span>',
      p.is_active ? '' : '<span class="status-pill status-off">Oculto</span>'
    ].filter(Boolean).join(' ');
    const platforms = (p.platforms || []).map((x) => escapeHtml(x)).join(', ') || '—';
    const dates = [p.expected_date, p.confirmed_date].filter(Boolean).map((d) => d.slice(0, 10)).join(' / ');
    const createdDay = fmtProjectCreatedDay(p.created_at);
    const desc = String(p.description || '').trim();
    // El emoji va siempre como base; el icono se dibuja encima y, si falla,
    // se elimina a si mismo revelando el emoji (sin comillas anidadas frágiles).
    const iconHtml = `<div class="admin-item-thumb project-icon-wrap" style="width:50px;height:50px">📁${p.icon_url ? `<img src="${escapeHtml(p.icon_url)}" alt="" data-adm-err="rm" />` : ''}</div>`;
    const canProgress = projectTracksProgress(p);
    return `
      <div class="admin-item">
        ${iconHtml}
        <div class="admin-item-info">
          <span class="admin-item-title">${escapeHtml(p.name)} ${chips}</span>
          <span class="admin-item-sub">${escapeHtml(p.slug)} · ${platforms}${p.genre ? ' · ' + escapeHtml(p.genre) : ''}${dates ? ' · ' + dates : ''}${createdDay ? ` · 🗓️ creado ${createdDay}` : ''}</span>
          ${desc
            ? `<span class="admin-item-desc" title="${escapeHtml(desc)}">📝 ${escapeHtml(desc)}</span>`
            : '<span class="admin-item-desc is-empty">Sin info del proyecto: editá y contá de qué trata.</span>'}
          ${projectProgressHtml(p)}
        </div>
        <div class="admin-item-actions">
          ${canProgress ? `<button class="btn btn-ghost btn-mini" title="Modificar % de desarrollo" data-adm-ev="click" data-adm="openDevModal" data-adm-a0="r:${p.id}">📈</button>` : ''}
          <button class="btn btn-ghost btn-mini" title="Versiones descargables del Hub" data-adm-ev="click" data-adm="openReleasesModal" data-adm-a0="r:${p.id}">📦</button>
          <button class="btn btn-ghost btn-mini" data-adm-ev="click" data-adm="editProject" data-adm-a0="r:${p.id}">✏️</button>
          <button class="btn btn-ghost btn-mini" data-adm-ev="click" data-adm="toggleProject" data-adm-a0="r:${p.id}" data-adm-a1="r:${p.is_active ? 'false' : 'true'}">${p.is_active ? '👁️' : '🚫'}</button>
          <button class="btn btn-danger btn-mini" data-adm-ev="click" data-adm="deleteProject" data-adm-a0="r:${p.id}">🗑️</button>
        </div>
      </div>
    `;
  }).join('');
}

async function saveProject(e) {
  if (e && e.preventDefault) e.preventDefault();
  const slug = document.getElementById('proj-slug').value.trim().toLowerCase();
  const name = document.getElementById('proj-name').value.trim();
  if (!slug || !name) return showToast('⚠️ Slug y nombre son obligatorios');

  const btn = document.getElementById('btn-save-project');
  const fail = (msg) => {
    // Error persistente en el formulario (el toast desaparece en 4s y se pierde)
    showAlert('proj-alert', msg, 'error');
    showToast('⚠️ ' + msg);
  };
  btn.disabled = true;

  try {
    // Subir primero los archivos elegidos (si los hay) para resolver sus URLs
    if (projIconFile) {
      btn.textContent = '⏳ Subiendo icono…';
      document.getElementById('proj-icon').value = await uploadProjectImage(projIconFile, 'icono');
      projIconFile = null;
      document.getElementById('proj-icon-file').value = '';
    }
    if (projBannerFile) {
      btn.textContent = '⏳ Subiendo banner…';
      document.getElementById('proj-banner').value = await uploadProjectImage(projBannerFile, 'banner');
      projBannerFile = null;
      document.getElementById('proj-banner-file').value = '';
    }

    const payload = {
      slug,
      name,
      description: document.getElementById('proj-desc').value.trim(),
      status: document.getElementById('proj-status').value,
      genre: document.getElementById('proj-genre').value.trim(),
      platforms: readPlatformChecks(),
      icon_url: document.getElementById('proj-icon').value.trim(),
      link_url: document.getElementById('proj-link').value.trim(),
      expected_date: document.getElementById('proj-expected').value || null,
      confirmed_date: document.getElementById('proj-confirmed').value || null
    };
    // Fecha real de creación: al crear se manda si se puso; al editar solo
    // si cambió el día (así no se reescribe la hora original sin querer).
    const projCreatedVal = (document.getElementById('proj-created') || {}).value || '';
    if (projCreatedVal) {
      const orig = editingProjectId
        ? projectsCache.find((x) => Number(x.id) === Number(editingProjectId))
        : null;
      const origDay = orig && orig.created_at ? String(orig.created_at).slice(0, 10) : '';
      if (!editingProjectId || projCreatedVal !== origDay) payload.created_at = projCreatedVal;
    }
    // banner_url vive en metadata (merge en el servidor)
    const bannerUrl = document.getElementById('proj-banner').value.trim();
    if (bannerUrl) payload.metadata = { banner_url: bannerUrl };

    btn.textContent = '💾 Guardando…';
    let res;
    if (editingProjectId) {
      res = await fetch(API_BASE + `/ows-launch-projects/${editingProjectId}`, {
        method: 'PATCH',
        headers: adminHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(payload)
      });
    } else {
      res = await fetch(API_BASE + '/ows-launch-projects', {
        method: 'POST',
        headers: adminHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(payload)
      });
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(res.status === 409
        ? `Ya existe un proyecto con el slug "${slug}". Si estabas editando, volvé a entrar en ✏️ y guardá de nuevo (la imagen ya quedó en el formulario).`
        : (data.error || `Error (${res.status})`));
    }
    hideAlert('proj-alert');
    showToast(editingProjectId ? 'Proyecto OWS actualizado ✔' : '🎉 Proyecto OWS creado + festejo en Celebraciones');
    resetProjectForm();
    loadAdminProjects();
    // Mantener Gestión sincronizada (conteos del filtro solo-lectura)
    if (typeof loadAdminManage === 'function') loadAdminManage();
    try { loadCelebrations(); } catch (_) {}
  } catch (err) {
    fail(err.message || 'Error al guardar el proyecto');
  } finally {
    btn.disabled = false;
    btn.textContent = editingProjectId ? '💾 Guardar cambios' : '📁 Crear proyecto OWS';
  }
}

async function editProject(id) {
  const p = projectsCache.find((x) => Number(x.id) === Number(id));
  if (!p) return showToast('⚠️ Proyecto no encontrado en caché');
  editingProjectId = id;
  hideAlert('proj-alert');
  document.getElementById('proj-slug').value = p.slug || '';
  document.getElementById('proj-slug').disabled = true; // el slug es la clave, no se edita
  document.getElementById('proj-name').value = p.name || '';
  document.getElementById('proj-desc').value = p.description || '';
  document.getElementById('proj-status').value = p.status || 'development';
  document.getElementById('proj-genre').value = p.genre || '';
  writePlatformChecks(p.platforms);
  document.getElementById('proj-icon').value = p.icon_url || '';
  document.getElementById('proj-banner').value = (p.metadata && p.metadata.banner_url) || p.banner_url || '';
  document.getElementById('proj-link').value = p.link_url || '';
  document.getElementById('proj-expected').value = p.expected_date ? String(p.expected_date).slice(0, 10) : '';
  document.getElementById('proj-confirmed').value = p.confirmed_date ? String(p.confirmed_date).slice(0, 10) : '';
  document.getElementById('proj-created').value = p.created_at ? String(p.created_at).slice(0, 10) : '';
  clearProjectImageFiles();
  const title = document.querySelector('#tab-projects .form-title');
  if (title) title.textContent = `Editando proyecto: ${p.name}`;
  document.getElementById('btn-cancel-project').classList.remove('hidden');
  document.getElementById('btn-save-project').textContent = '💾 Guardar cambios';
  openFormModal('project');
}

function resetProjectForm() {
  editingProjectId = null;
  hideAlert('proj-alert');
  document.getElementById('proj-slug').disabled = false;
  document.getElementById('proj-slug').value = '';
  document.getElementById('proj-name').value = '';
  document.getElementById('proj-desc').value = '';
  document.getElementById('proj-status').value = 'development';
  document.getElementById('proj-genre').value = '';
  writePlatformChecks(['windows']);
  document.getElementById('proj-icon').value = '';
  document.getElementById('proj-banner').value = '';
  document.getElementById('proj-link').value = '';
  document.getElementById('proj-expected').value = '';
  document.getElementById('proj-confirmed').value = '';
  document.getElementById('proj-created').value = '';
  clearProjectImageFiles();
  const btn = document.querySelector('#tab-projects .form-title');
  if (btn) btn.textContent = 'Nuevo proyecto OWS';
  const cancel = document.getElementById('btn-cancel-project');
  if (cancel) cancel.classList.add('hidden');
  const save = document.getElementById('btn-save-project');
  if (save) save.textContent = '📁 Crear proyecto OWS';
  try { closeFormModal(); } catch (_) {}
}

async function toggleProject(id, newState) {
  try {
    const res = await fetch(API_BASE + `/ows-launch-projects/${id}`, {
      method: 'PATCH',
      headers: adminHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ is_active: newState })
    });
    if (!res.ok) throw new Error(`Error (${res.status})`);
    loadAdminProjects();
    if (typeof loadAdminManage === 'function') loadAdminManage();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

async function deleteProject(id) {
  if (!confirm('¿Eliminar este proyecto OWS permanentemente?')) return;
  try {
    const res = await fetch(API_BASE + `/ows-launch-projects/${id}`, {
      method: 'DELETE',
      headers: adminHeaders()
    });
    if (!res.ok) throw new Error(`Error (${res.status})`);
    showToast('Proyecto eliminado');
    if (editingProjectId === id) resetProjectForm();
    loadAdminProjects();
    if (typeof loadAdminManage === 'function') loadAdminManage();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

// =======================================================
// VERSIONES DESCARGABLES — builds del Hub por proyecto
// (tabla ows_project_releases). Sin release activa el Hub NO
// ofrece descarga y el modal muestra el estado del proyecto.
// Vale para proyectos de Proyectos y de Gestión (misma tabla).
// =======================================================

let relProjectId = 0;
let relProjectRef = null;
let relListCache = [];
let editingReleaseId = 0;

function findAnyLaunchProject(id) {
  const nid = Number(id);
  const inProjects = (typeof projectsCache !== 'undefined' ? projectsCache : []).find((x) => Number(x.id) === nid);
  if (inProjects) return inProjects;
  const inManage = (typeof manageProjectsCache !== 'undefined' ? manageProjectsCache : []).find((x) => Number(x.id) === nid);
  return inManage || null;
}

function releaseRowBadge(r) {
  const parts = [`<span class="status-pill">📦 v${escapeHtml(r.version || '?')}</span>`];
  if (r.channel && r.channel !== 'stable') parts.push(`<span class="status-pill">${escapeHtml(r.channel)}</span>`);
  parts.push(r.platform && r.platform !== 'windows'
    ? `<span class="status-pill">${r.platform === 'android' ? '🤖 Android' : '🌐 Todas'}</span>`
    : '<span class="status-pill">🪟 Windows</span>');
  parts.push(r.is_active
    ? '<span class="status-pill status-on">Activa</span>'
    : '<span class="status-pill status-off">Inactiva</span>');
  return parts.join(' ');
}

async function openReleasesModal(id) {
  const p = findAnyLaunchProject(id);
  if (!p) return showToast('⚠️ Proyecto no encontrado en caché');
  relProjectId = Number(p.id);
  relProjectRef = p;
  editingReleaseId = 0;
  const body = document.getElementById('rel-modal-body');
  if (!body) return;
  const onlyAdmin = (p.admin_only === true || p.adminOnly === true);
  body.innerHTML = `
    <h3 class="form-title">📦 Versiones — ${escapeHtml(p.name)}</h3>
    <p class="form-hint">${escapeHtml(p.slug)} ${onlyAdmin ? '· 🔒 solo-admin' : '· 📁 público'} · Sin release activa el Hub no muestra descarga.</p>
    <div id="rel-list" class="admin-list"><p class="loading-note">Cargando versiones…</p></div>
    <h4 class="form-title" id="rel-form-title" style="margin-top:14px">Nueva versión</h4>
    <form data-adm-ev="submit" data-adm="saveRelease" data-adm-a0="ev">
      <div class="field-row">
        <div class="field-group">
          <label for="rel-version">Versión *</label>
          <input type="text" id="rel-version" placeholder="ej: 0.1.0" required maxlength="40" />
        </div>
        <div class="field-group">
          <label for="rel-channel">Canal</label>
          <select id="rel-channel">
            <option value="stable">stable</option>
            <option value="beta">beta</option>
            <option value="alpha">alpha</option>
            <option value="demo">demo</option>
          </select>
        </div>
      </div>
      <div class="field-row">
        <div class="field-group">
          <label for="rel-platform">Plataforma del build</label>
          <select id="rel-platform">
            <option value="windows">Windows (.exe / .msi)</option>
            <option value="android">Android (.apk)</option>
            <option value="all">Todas</option>
          </select>
        </div>
      </div>
      <div class="field-row">
        <div class="field-group">
          <label for="rel-file">Archivo</label>
          <input type="text" id="rel-file" placeholder="ej: Wilder Gambit.exe" maxlength="200" />
        </div>
        <div class="field-group">
          <label for="rel-size">Tamaño</label>
          <input type="text" id="rel-size" placeholder="ej: 652 kB" maxlength="40" />
        </div>
      </div>
      <div class="field-group">
        <label for="rel-installer">Installer URL (descarga directa, opcional)</label>
        <input type="text" id="rel-installer" placeholder="https://…" />
      </div>
      <div class="field-row">
        <div class="field-group">
          <label for="rel-itch">itch.io URL (opcional)</label>
          <input type="text" id="rel-itch" placeholder="https://….itch.io/…" />
        </div>
        <div class="field-group">
          <label for="rel-date">Fecha de release</label>
          <input type="date" id="rel-date" />
        </div>
      </div>
      <div class="field-group">
        <label for="rel-notes">Notas</label>
        <textarea id="rel-notes" rows="2" maxlength="1000" placeholder="Qué trae esta versión…"></textarea>
      </div>
      <div id="rel-alert" class="alert-box hidden"></div>
      <button type="submit" class="btn btn-primary btn-block" id="btn-save-release">📦 Guardar versión</button>
      <button type="button" class="btn btn-ghost btn-block hidden" id="btn-cancel-release" data-adm-ev="click" data-adm="resetReleaseForm">Cancelar edición</button>
    </form>`;
  document.getElementById('rel-modal').classList.remove('hidden');
  document.body.style.overflow = 'hidden';
  loadReleasesList();
}

function closeReleasesModal() {
  const m = document.getElementById('rel-modal');
  if (m) m.classList.add('hidden');
  try {
    if (!document.querySelector('.devmodal-overlay:not(.hidden)')) document.body.style.overflow = '';
  } catch (_) { document.body.style.overflow = ''; }
  relProjectId = 0;
  relProjectRef = null;
  editingReleaseId = 0;
}

async function loadReleasesList() {
  const box = document.getElementById('rel-list');
  if (!box || !relProjectRef) return;
  box.innerHTML = '<p class="loading-note">Cargando versiones…</p>';
  try {
    const res = await fetch(
      API_BASE + '/ows-project-releases?slug=' + encodeURIComponent(relProjectRef.slug) + '&include_inactive=1',
      { headers: adminHeaders() }
    );
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || ('Error ' + res.status));
    relListCache = data.releases || [];
    if (!relListCache.length) {
      box.innerHTML = '<p class="loading-note">📦 Sin versiones: el Hub muestra el estado del proyecto sin descarga. Creá la primera ↓</p>';
      return;
    }
    box.innerHTML = relListCache.map((r) => {
      const when = r.released_at ? String(r.released_at).slice(0, 10) : '—';
      const file = [r.file_label, r.size_label].filter(Boolean).join(' · ') || '—';
      return `
      <div class="admin-item">
        <div class="admin-item-info">
          <span class="admin-item-title">${releaseRowBadge(r)}</span>
          <span class="admin-item-sub">📁 ${escapeHtml(file)} · 🗓️ ${escapeHtml(when)}</span>
          ${r.notes ? `<span class="admin-item-desc">📝 ${escapeHtml(r.notes)}</span>` : ''}
        </div>
        <div class="admin-item-actions">
          <button class="btn btn-ghost btn-mini" data-adm-ev="click" data-adm="editRelease" data-adm-a0="r:${r.id}">✏️</button>
          <button class="btn btn-ghost btn-mini" data-adm-ev="click" data-adm="toggleRelease" data-adm-a0="r:${r.id}" data-adm-a1="r:${r.is_active ? 'false' : 'true'}">${r.is_active ? '👁️' : '🚫'}</button>
          <button class="btn btn-danger btn-mini" data-adm-ev="click" data-adm="deleteRelease" data-adm-a0="r:${r.id}">🗑️</button>
        </div>
      </div>`;
    }).join('');
  } catch (err) {
    box.innerHTML = `<p class="loading-note">⚠️ ${escapeHtml(err.message)}</p>`;
  }
}

async function saveRelease(e) {
  if (e && e.preventDefault) e.preventDefault();
  if (!relProjectId) return showToast('⚠️ Abrí las versiones de un proyecto primero');
  const version = document.getElementById('rel-version').value.trim();
  if (!version) return showToast('⚠️ La versión es obligatoria');
  const payload = {
    version,
    channel: document.getElementById('rel-channel').value,
    platform: document.getElementById('rel-platform') ? document.getElementById('rel-platform').value : 'windows',
    file_label: document.getElementById('rel-file').value.trim(),
    size_label: document.getElementById('rel-size').value.trim(),
    installer_url: document.getElementById('rel-installer').value.trim(),
    itch_url: document.getElementById('rel-itch').value.trim(),
    notes: document.getElementById('rel-notes').value.trim(),
    released_at: document.getElementById('rel-date').value || undefined
  };
  try {
    let res;
    if (editingReleaseId) {
      res = await fetch(API_BASE + '/ows-project-releases/' + editingReleaseId, {
        method: 'PATCH',
        headers: adminHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(payload)
      });
    } else {
      res = await fetch(API_BASE + '/ows-project-releases', {
        method: 'POST',
        headers: adminHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ project_id: relProjectId, ...payload })
      });
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || ('Error ' + res.status));
    showToast(editingReleaseId ? 'Versión actualizada ✔' : 'Versión creada ✔');
    resetReleaseForm();
    loadReleasesList();
    if (typeof loadAdminProjects === 'function') loadAdminProjects();
    if (typeof loadAdminManage === 'function') loadAdminManage();
  } catch (err) {
    showToast('⚠️ ' + err.message);
  }
}

function editRelease(id) {
  const r = relListCache.find((x) => Number(x.id) === Number(id));
  if (!r) return showToast('⚠️ Versión no encontrada');
  editingReleaseId = Number(id);
  document.getElementById('rel-version').value = r.version || '';
  document.getElementById('rel-channel').value = r.channel || 'stable';
  const relPlat = document.getElementById('rel-platform');
  if (relPlat) relPlat.value = r.platform || 'windows';
  document.getElementById('rel-file').value = r.file_label || '';
  document.getElementById('rel-size').value = r.size_label || '';
  document.getElementById('rel-installer').value = r.installer_url || '';
  document.getElementById('rel-itch').value = r.itch_url || '';
  document.getElementById('rel-notes').value = r.notes || '';
  document.getElementById('rel-date').value = r.released_at ? String(r.released_at).slice(0, 10) : '';
  document.getElementById('rel-form-title').textContent = 'Editar versión v' + (r.version || '');
  document.getElementById('btn-save-release').textContent = '💾 Guardar cambios';
  document.getElementById('btn-cancel-release').classList.remove('hidden');
}

function resetReleaseForm() {
  editingReleaseId = 0;
  ['rel-version', 'rel-file', 'rel-size', 'rel-installer', 'rel-itch', 'rel-notes', 'rel-date'].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  const ch = document.getElementById('rel-channel');
  if (ch) ch.value = 'stable';
  const pl = document.getElementById('rel-platform');
  if (pl) pl.value = 'windows';
  const t = document.getElementById('rel-form-title');
  if (t) t.textContent = 'Nueva versión';
  const b = document.getElementById('btn-save-release');
  if (b) b.textContent = '📦 Guardar versión';
  const c = document.getElementById('btn-cancel-release');
  if (c) c.classList.add('hidden');
}

async function toggleRelease(id, newState) {
  try {
    const res = await fetch(API_BASE + '/ows-project-releases/' + Number(id), {
      method: 'PATCH',
      headers: adminHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ is_active: newState })
    });
    if (!res.ok) throw new Error('Error ' + res.status);
    loadReleasesList();
    if (typeof loadAdminProjects === 'function') loadAdminProjects();
    if (typeof loadAdminManage === 'function') loadAdminManage();
  } catch (err) {
    showToast('⚠️ ' + err.message);
  }
}

async function deleteRelease(id) {
  if (!confirm('¿Eliminar esta versión permanentemente?')) return;
  try {
    const res = await fetch(API_BASE + '/ows-project-releases/' + Number(id), {
      method: 'DELETE',
      headers: adminHeaders()
    });
    if (!res.ok) throw new Error('Error ' + res.status);
    showToast('Versión eliminada');
    if (editingReleaseId === Number(id)) resetReleaseForm();
    loadReleasesList();
    if (typeof loadAdminProjects === 'function') loadAdminProjects();
    if (typeof loadAdminManage === 'function') loadAdminManage();
  } catch (err) {
    showToast('⚠️ ' + err.message);
  }
}

// =======================================================
// SESIONES DE TRABAJO — los "minidevlogs del momento"
// =======================================================
// El devlog sigue siendo el registro que se publica al final del día. Las
// sesiones son el bloque de trabajo en sí: se abren, se anotan con la hora
// aproximada de inicio y fin, y se cierran. Todas las de un mismo día se
// combinan en un devlog del día (ver renderWsDaily / publishDailyDevlog).
//
// El reparto de una sesión que cae después de las 00:00 lo hace el servidor
// (splitWorkSession) usando el desplazamiento del navegador, así el corte cae
// en la medianoche del admin. Cada sesión llega con sus `segments`: un tramo
// por día tocado, con los minutos y si es la parte inicial o la continuación.
//
// El avance NO se vuelve a sumar: se aplica al % del proyecto cuando la sesión
// se cierra (ya queda en el historial) y el devlog del día solo lo agrupa.
// =======================================================

let wsCache = [];          // /ows-work-sessions
let wsDailyCache = null;   // vista previa del devlog del día
let wsEditingId = null;    // sesión abierta en el formulario
let wsDay = '';            // 'YYYY-MM-DD' del día que se está mirando
let wsClockTimer = null;
// Vista de la línea de tiempo: 'all' = categorizada por día (todas las
// fechas apiladas con su cabecera), 'day' = un solo día (el de wsDay).
// Se pide categorizada por día, así que el valor por defecto es 'all'.
let wsTimelineMode = (() => {
  try {
    const saved = localStorage.getItem('ws_timeline_mode');
    return saved === 'day' ? 'day' : 'all';
  } catch (_) { return 'all'; }
})();
const WS_TIMELINE_DAYS_LIMIT = 14;

// El corte por día del servidor necesita saber en qué huso está el admin.
// -getTimezoneOffset() son los minutos que hay que SUMAR a la hora UTC para
// obtener la local (en UTC-3: -180).
function wsTzOffset() {
  return -new Date().getTimezoneOffset();
}

// 'HH:MM' de un instante, en hora local del admin.
function wsClock(iso) {
  if (!iso) return '--:--';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '--:--';
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}

// '1 h 25 min' / '45 min' — el mismo formato que usa el backend.
function wsMinutes(min) {
  const m = Math.max(0, Math.round(Number(min) || 0));
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60);
  const r = m % 60;
  return r ? `${h} h ${r} min` : `${h} h`;
}

// Segundos transcurridos del tramo que se está trabajando (para el reloj en
// vivo). Si la sesión se interrumpió y se retomó, cuenta desde el último
// tramo: la pausa anterior no se está trabajando ahora. Una sesión cerrada o
// pausada no tiene tramo en curso, así que devuelve 0.
function wsElapsedSeconds(s) {
  const parts = (s && s.parts) || [];
  if (!parts.length) {
    // Sesión vieja, sin tramos: cuenta desde el inicio, como antes.
    const from = s && s.started_at ? new Date(s.started_at).getTime() : NaN;
    return Number.isFinite(from) ? Math.max(0, Math.floor((Date.now() - from) / 1000)) : 0;
  }
  const last = parts[parts.length - 1];
  if (!last || !last.open) return 0;
  const from = new Date(last.from).getTime();
  if (Number.isNaN(from)) return 0;
  return Math.max(0, Math.floor((Date.now() - from) / 1000));
}
function wsStopwatch(sec) {
  const s = Math.max(0, Math.floor(Number(sec) || 0));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const r = s % 60;
  return h
    ? `${h}:${String(m).padStart(2, '0')}:${String(r).padStart(2, '0')}`
    : `${m}:${String(r).padStart(2, '0')}`;
}

// En español el plural de "sesión" es "sesiones" (pierde la tilde). Un solo
// helper para no repetir el `${n === 1 ? 'sesión' : 'sesiones'}` por todos lados.
function wsCount(n, one, many) {
  return `${n} ${Number(n) === 1 ? one : many}`;
}
const WS_SESSION_1 = 'sesión';
const WS_SESSION_N = 'sesiones';

// ── Sesiones del día ──
function wsTodayKey() {
  return paxKeyFromDate(new Date());
}

// Día que se está mirando (por defecto, hoy).
function wsActiveDay() {
  return wsDay || wsTodayKey();
}
function setWsDayKey(key, fromPicker) {
  wsDay = key || wsTodayKey();
  syncWsDayInputs();
  // Elegir fecha a mano (picker o botón Hoy) pasa a vista de un solo día;
  // los cambios internos (guardar, detener, retomar) conservan la vista.
  if (fromPicker === true && wsTimelineMode !== 'day') {
    wsTimelineMode = 'day';
    try { localStorage.setItem('ws_timeline_mode', 'day'); } catch (_) {}
    syncWsTimelineModeUI();
  }
  loadWorkSessions();
  loadWsDaily();
}
// Los dos selectores de fecha (sesiones y devlog) siempre muestran el mismo
// día activo y no permiten elegir futuro: publicar un día futuro no tiene
// sentido y publicar "hoy" algo de otro día quedaría técnicamente mal.
function syncWsDayInputs() {
  ['ws-day', 'ws-daily-day'].forEach((id) => {
    const el = document.getElementById(id);
    if (!el) return;
    if (el.value !== wsDay) el.value = wsDay;
    el.max = wsTodayKey();
  });
}
function onWsDailyDayChange() {
  const el = document.getElementById('ws-daily-day');
  setWsDayKey(el ? el.value : '', true);
}
function onWsDayChange() {
  const el = document.getElementById('ws-day');
  setWsDayKey(el ? el.value : '', true);
}
// Cambia entre "Por día" (todas categorizadas) y "Un día" (solo wsDay).
// scrollDay: al volver a "Por día" se puede bajar hasta ese día.
function setWsTimelineMode(mode, scrollDay) {
  wsTimelineMode = mode === 'day' ? 'day' : 'all';
  try { localStorage.setItem('ws_timeline_mode', wsTimelineMode); } catch (_) {}
  if (wsTimelineMode === 'day' && !wsDay) {
    wsDay = wsTodayKey();
    syncWsDayInputs();
  }
  syncWsTimelineModeUI();
  renderWsTimeline();
  if (wsTimelineMode === 'day') loadWsDaily();
  const target = scrollDay || (wsTimelineMode === 'all' ? wsDay : '');
  if (target) {
    setTimeout(() => {
      const anchor = document.getElementById(`ws-day-${target}`);
      if (anchor) anchor.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 30);
  }
}
function syncWsTimelineModeUI() {
  const all = document.getElementById('ws-view-all');
  const one = document.getElementById('ws-view-day');
  if (all) all.classList.toggle('is-on', wsTimelineMode !== 'day');
  if (one) one.classList.toggle('is-on', wsTimelineMode === 'day');
  const day = document.getElementById('ws-day');
  if (day) day.classList.toggle('is-single', wsTimelineMode === 'day');
}
// "Hoy — lunes 30/09/2026" / "Ayer — ..." / fecha larga del resto.
function wsDayTitle(day) {
  const today = wsTodayKey();
  const long = (typeof paxDayLong === 'function' ? paxDayLong(day) : day);
  if (day === today) return `Hoy — ${long}`;
  try {
    const [y, m, d] = String(day).split('-').map(Number);
    const dt = new Date(y, m - 1, d);
    const t = new Date();
    const yd = new Date(t.getFullYear(), t.getMonth(), t.getDate() - 1);
    if (dt.getFullYear() === yd.getFullYear() && dt.getMonth() === yd.getMonth() && dt.getDate() === yd.getDate()) {
      return `Ayer — ${long}`;
    }
  } catch (_) {}
  return long;
}
// Días distintos tocados por las sesiones, de más nuevo a más viejo.
function wsAllDays(limit) {
  const set = new Set();
  (wsCache || []).forEach((s) => {
    (s.segments || []).forEach((g) => { if (g && g.day) set.add(g.day); });
  });
  // Las sesiones sin segmentos (abiertas viejas) aportan su día local.
  (wsCache || []).forEach((s) => {
    if (s && s.local_day) set.add(s.local_day);
  });
  const days = [...set].filter((d) => /^\d{4}-\d{2}-\d{2}$/.test(d)).sort().reverse();
  return days.slice(0, limit || WS_TIMELINE_DAYS_LIMIT);
}

// ¿Esta sesión toca el día que se está mirando?
function wsTouchesDay(s, day) {
  return (s?.segments || []).some((g) => g.day === day);
}
// Tramos de una sesión para un día concreto. Puede ser MÁS de uno: si la
// sesión se interrumpió y se retomó el mismo día, tiene un tramo por cada
// bloque trabajado, y hay que sumar todos los minutos.
function wsDaySegmentsOf(s, day) {
  return (s?.segments || []).filter((g) => g.day === day);
}
// Tramo de una sesión para un día concreto (o null). El primero del día: es el
// que marca dónde empezó el trabajo visible en esa fecha.
function wsSegmentOf(s, day) {
  return wsDaySegmentsOf(s, day)[0] || null;
}
// Minutos que la sesión aporta a un día, sumando todos sus tramos.
function wsDayMinutesOf(s, day) {
  return wsDaySegmentsOf(s, day).reduce((n, g) => n + (g.minutes || 0), 0);
}
// Rango del día: del primer tramo al último.
function wsDayRangeOf(s, day) {
  const segs = wsDaySegmentsOf(s, day);
  if (!segs.length) return null;
  return { from: segs[0].from, to: segs[segs.length - 1].to, count: segs.length };
}
// Sesiones del día, ordenadas por hora de inicio (las más recientes arriba).
function wsDaySessions(day) {
  const d = day || wsActiveDay();
  return wsCache
    .filter((s) => wsTouchesDay(s, d))
    .sort((a, b) => String(b.segments.find((g) => g.day === d)?.from || b.started_at)
      .localeCompare(String(a.segments.find((g) => g.day === d)?.from || a.started_at)));
}

// ── Cómo terminó el bloque ──
// Un bloque de trabajo puede cerrar de tres maneras, y las tres se anotan:
//   ✅ Completado con éxito → se aplicó el avance y listo.
//   ⏸ Interrumpido, lo sigo después → la sesión queda PAUSADA: el cronómetro
//      se detiene acá y más tarde se retoma con "▶ Continuar", que abre un
//      tramo nuevo. Queda escrito "se interrumpió a las X, se continuó a las
//      Y" y, cuando por fin se cierra, que se finalizó con éxito.
//   ⚠️ Quedó a medias → se cierra y no se va a retomar.
// En los dos últimos el motivo es obligatorio: hay motivos predefinidos para
// no tener que escribir, pero el campo queda editable.
const WS_END_OPTIONS = [
  { value: 'complete',   icon: '✅', label: 'Completado con éxito' },
  { value: 'paused',     icon: '⏸', label: 'Interrumpido, lo sigo después' },
  { value: 'incomplete', icon: '⚠️', label: 'Quedó a medias' }
];

const WS_INCOMPLETE_REASONS = [
  { icon: '⏰', text: 'Por falta de tiempo' },
  { icon: '🔀', text: 'Interrumpida por otra cosa' },
  { icon: '😴', text: 'Cansancio / fatigue' },
  { icon: '🐛', text: 'Bloqueo técnico' },
  { icon: '🤔', text: 'Me equivoqué y no sirvió' },
  { icon: '📌', text: 'Quedó a medias, la sigo otro día' },
  { icon: '💬', text: 'Sin ganas de seguir' }
];

// Motivos propios de una pausa: acá siempre se vuelve, así que la lista es
// distinta de la de "quedó a medias".
const WS_PAUSE_REASONS = [
  { icon: '⏰', text: 'Por falta de tiempo' },
  { icon: '📞', text: 'Me llamaron por otra cosa' },
  { icon: '🍽️', text: 'Pausa para comer / descansar' },
  { icon: '😴', text: 'Cansancio, lo sigo mañana' },
  { icon: '🐛', text: 'Bloqueo técnico' },
  { icon: '📆', text: 'Se me complicó el día, lo sigo otro día' }
];

// Motivos según el final elegido.
function wsReasonsFor(kind) {
  return kind === 'paused' ? WS_PAUSE_REASONS : WS_INCOMPLETE_REASONS;
}

// HTML de la sección "¿cómo terminó?". Se usa en el modal de detener y en el
// formulario de edición, así que va en una función sola.
//   prefix: prefijo de los ids (wsrt- o ws-), para no repetir markup.
function wsCompletionHtml(prefix, session) {
  const kind = wsKindOf(session);
  const reason = session ? String(session.incomplete_reason || '') : '';
  return `
    <div class="ws-comp is-${kind}" id="${prefix}-comp">
      <span class="ws-comp-label">¿Cómo terminó este bloque?</span>
      <div class="ws-end-opts" id="${prefix}-end-opts">
        ${WS_END_OPTIONS.map((o) => `
          <label class="ws-end-opt is-${o.value}${kind === o.value ? ' is-on' : ''}">
            <input type="radio" name="${prefix}-end" value="${o.value}"
              ${kind === o.value ? 'checked' : ''} data-adm-ev="change" data-adm="onWsCompletionChange" data-adm-a0="s:${prefix}" />
            <span class="ws-end-icon">${o.icon}</span>
            <span class="ws-end-text">${escapeHtml(o.label)}</span>
          </label>`).join('')}
      </div>
      <p class="ws-comp-help" id="${prefix}-comp-help"></p>
      <div class="ws-comp-body${kind === 'complete' ? ' hidden' : ''}" id="${prefix}-comp-body">
        <div class="ws-comp-chips" id="${prefix}-comp-chips">
          ${wsReasonsFor(kind).map((r) => `<button type="button" class="ws-comp-chip"
            data-text="${escapeHtml(r.text)}"
            data-adm-ev="click" data-adm="setWsIncompleteReason" data-adm-a0="s:${prefix}" data-adm-a1="thp:dataset.text"
            title="Usar este motivo">${r.icon} ${escapeHtml(r.text)}</button>`).join('')}
        </div>
        <input type="text" id="${prefix}-incomplete-reason" maxlength="300"
          placeholder="O escribí tu propio motivo…" value="${escapeHtml(reason)}"
          data-adm-ev="input" data-adm="onWsIncompleteReasonInput" data-adm-a0="s:${prefix}" />
        <p class="form-hint" id="${prefix}-comp-hint"></p>
      </div>
    </div>`;
}

// Qué final tiene guardado una sesión (para abrir el formulario con lo que ya
// tenía, corregible después).
function wsKindOf(session) {
  const k = String(session?.completion || 'complete');
  return k === 'paused' || k === 'incomplete' ? k : 'complete';
}

function onWsCompletionChange(prefix) {
  const box = document.getElementById(`${prefix}-comp`);
  const body = document.getElementById(`${prefix}-comp-body`);
  const help = document.getElementById(`${prefix}-comp-help`);
  const chips = document.getElementById(`${prefix}-comp-chips`);
  const comp = readWsCompletion(prefix);
  const boxEl = box;
  if (boxEl) boxEl.className = `ws-comp is-${comp.completion}`;
  // El resaltado sigue al radio elegido. Sin esto la opción anterior queda
  // marcada para siempre y parece que el clic no se registró: el admin ve
  // "Completado con éxito" abajo de "Interrumpido" y termina guardando lo
  // contrario de lo que quiso.
  document.querySelectorAll(`#${prefix}-end-opts .ws-end-opt`).forEach((opt) => {
    const input = opt.querySelector('input');
    opt.classList.toggle('is-on', !!(input && input.checked));
  });
  if (body) body.classList.toggle('hidden', comp.completion === 'complete');
  // Los motivos cambian según el final elegido.
  if (chips) {
    chips.innerHTML = wsReasonsFor(comp.completion).map((r) => `<button type="button" class="ws-comp-chip"
      data-text="${escapeHtml(r.text)}"
      data-adm-ev="click" data-adm="setWsIncompleteReason" data-adm-a0="s:${prefix}" data-adm-a1="thp:dataset.text"
      title="Usar este motivo">${r.icon} ${escapeHtml(r.text)}</button>`).join('');
  }
  if (help) help.textContent = wsCompletionHelp(comp.completion);
  // En el modal de detener el botón principal cambia según el final. El id es
  // propio del modal: el del formulario manual (ws-save) no se toca.
  const go = document.getElementById(`${prefix}-end-btn`);
  if (go) {
    go.textContent = wsEndButtonLabel(comp.completion);
    go.className = `btn ${wsEndButtonClass(comp.completion)}`;
  }
  onWsIncompleteReasonInput(prefix);
  if (comp.completion !== 'complete') {
    const input = document.getElementById(`${prefix}-incomplete-reason`);
    if (input && !input.value) setTimeout(() => input.focus(), 30);
  }
}

// Explicación de una línea de cada final: qué va a pasar exactamente.
function wsCompletionHelp(kind) {
  if (kind === 'paused') {
    return 'Se detiene el cronómetro y la sesión queda esperando. Cuando quieras seguir, tocá "▶ Continuar": '
      + 'se anota que se interrumpió, a qué hora se continuó y, al terminar, que se completó.';
  }
  if (kind === 'incomplete') {
    return 'La sesión se cierra y queda como trabajo a medias. El motivo queda escrito en el devlog del día.';
  }
  return 'La sesión se cierra y el avance se aplica al % del proyecto.';
}

function wsEndButtonLabel(kind) {
  if (kind === 'paused') return '⏸ Interrumpir y seguir después';
  if (kind === 'incomplete') return '⚠️ Guardar como incompleta';
  return '⏹ Detener y guardar';
}
function wsEndButtonClass(kind) {
  if (kind === 'paused') return 'btn-ws-pause';
  if (kind === 'incomplete') return 'btn-ws-inc';
  return 'ws-stop-btn';
}

// Al elegir un motivo predefinido se lo pone en el campo: así el admin puede
// dejarlo tal cual o seguir escribiendo encima.
function setWsIncompleteReason(prefix, text) {
  const input = document.getElementById(`${prefix}-incomplete-reason`);
  if (!input) return;
  input.value = text;
  onWsIncompleteReasonInput(prefix);
  input.focus();
}

// El campo es obligatorio para poder pausar o dejar a medias.
function onWsIncompleteReasonInput(prefix) {
  const input = document.getElementById(`${prefix}-incomplete-reason`);
  const hint = document.getElementById(`${prefix}-comp-hint`);
  const comp = readWsCompletion(prefix);
  if (comp.completion === 'complete') { if (hint) hint.textContent = ''; return true; }
  const val = input ? input.value.trim() : '';
  if (hint) {
    hint.textContent = val ? '✓ Con el motivo escrito se puede guardar.' : '⚠️ Falta el motivo: elegí uno o escribilo.';
    hint.className = `form-hint ${val ? 'is-ok' : 'is-warn'}`;
  }
  if (input) input.classList.toggle('is-invalid', !val);
  return !!val;
}

// Lee la sección. Devuelve completion 'complete' | 'paused' | 'incomplete'.
// El guardado se corta antes de pegarle al servidor si falta el motivo.
function readWsCompletion(prefix) {
  const sel = document.querySelector(`input[name="${prefix}-end"]:checked`);
  const kind = wsKindOf({ completion: sel ? sel.value : 'complete' });
  const input = document.getElementById(`${prefix}-incomplete-reason`);
  return {
    completion: kind,
    incomplete_reason: kind === 'complete' ? '' : (input ? input.value.trim().replace(/\s+/g, ' ').slice(0, 300) : '')
  };
}

// ── Sesión EN TIEMPO REAL (cronómetro) ──
// A diferencia del formulario manual, acá el admin no escribe las horas: da
// los datos primero y el reloj se encarga del resto.
//   1. openWsRealtimeForm() → pide proyecto / qué hizo / detalle.
//   2. startWsRealtime()    → POST con realtime:true. El SERVIDOR pone la
//      hora de inicio (no la manda el navegador, así no depende de la hora
//      del dispositivo) y abre la barra en vivo.
//   3. openWsStopForm()     → al detener, pregunta cuánto avanzó.
//   4. stopWsRealtime()     → POST /:id/stop. El servidor pone la hora de
//      fin y aplica el avance al % del proyecto.
//
// La barra vive aunque se recargue la página: la sesión sigue abierta del
// lado del servidor y el cronómetro se reconstruye desde started_at.

// ¿Hay sesiones en vivo corriendo ahora mismo? (solo las realtime)
// Pueden ser VARIAS a la vez: cada una lleva su propio cronómetro.
function wsRunningList() {
  return wsCache
    .filter((s) => s && s.status === 'active' && s.realtime === true)
    .sort((a, b) => new Date(a.started_at).getTime() - new Date(b.started_at).getTime());
}
function wsRunning() {
  return wsRunningList()[0] || null;
}
function wsRunningId() {
  const s = wsRunning();
  return s ? Number(s.id) : 0;
}

// Sesiones interrumpidas a la espera de ser retomadas. Se listan aparte de la
// barra en vivo porque no están corriendo: solo esperando a que el admin vuelva.
function wsPausedList() {
  return wsCache.filter((s) => s.status === 'paused');
}

// ── Cambios registrados en vivo ──────────────────────────────────────
// Una sesión lleva anotado qué se hizo y a qué hora: 17:00 nuevo objeto,
// 18:30 bug crítico corregido. La hora la puso el servidor al registrarlo.
// Se pintan apilados, uno debajo del otro, en orden cronológico.
// Cada cambio lleva tamaño (chico/mediano/grande/crítico/personalizado) y
// color (el del tamaño o uno elegido a mano).
const WS_CHANGE_KINDS = {
  chico: { label: 'Chico', color: '#34d399', hint: 'Ajuste menor' },
  mediano: { label: 'Mediano', color: '#fbbf24', hint: 'Cambio normal' },
  grande: { label: 'Grande', color: '#f97316', hint: 'Cambio importante' },
  critico: { label: 'Crítico', color: '#ef4444', hint: 'Bug crítico, caída' },
  custom: { label: 'Personalizado', color: '#a855f7', hint: 'Nombre y color libres' }
};
function wsChangeKindMeta(kind) {
  return WS_CHANGE_KINDS[kind] || WS_CHANGE_KINDS.mediano;
}
function wsChangeKindLabel(c) {
  if (c?.kind === 'custom') return String(c?.custom_label || '').trim().slice(0, 40) || 'Personalizado';
  return wsChangeKindMeta(c?.kind).label;
}
// Color seguro para pintar (solo hex válido, si no el del tamaño).
function wsChangeColor(color, kind) {
  const s = String(color || '').trim();
  if (/^#[0-9a-fA-F]{6}$/.test(s)) return s.toLowerCase();
  if (/^#[0-9a-fA-F]{3}$/.test(s)) return `#${s[1]}${s[1]}${s[2]}${s[2]}${s[3]}${s[3]}`.toLowerCase();
  return wsChangeKindMeta(kind).color;
}
function wsChangesHtml(changes, opts = {}) {
  const list = Array.isArray(changes) ? changes : [];
  if (!list.length) {
    return opts.empty
      ? '<p class="ws-change-empty">Todavía no hay cambios anotados en esta sesión.</p>'
      : '';
  }
  // Un cambio puede colgar de un rework (cambio masivo). Los que son del mismo
  // rework se agrupan juntos, así se ve de un vistazo qué cambios están
  // conectados y cuánto lleva el trabajo grande.
  const rows = list.map((c, idx) => ({ c, idx, rw: wsReworkOfChange(c, opts.session) }));
  const order = [];
  const groups = new Map();
  rows.forEach((r) => {
    const key = r.rw ? r.rw.key : '';
    if (!groups.has(key)) { groups.set(key, { rw: r.rw, items: [] }); order.push(key); }
    groups.get(key).items.push(r);
  });
  return `<ol class="ws-change-list">${order.map((key) => {
    const g = groups.get(key);
    const own = g.items;
    return `${wsReworkGroupHeadHtml(g.rw, own, opts)}${own.map((r) => wsChangeItemHtml(r.c, r.idx, g.rw, opts)).join('')}`;
  }).join('')}</ol>`;
}

function wsChangeItemHtml(c, idx, rw, opts = {}) {
  const color = rw ? wsReworkColor(rw.color) : wsChangeColor(c?.color, c?.kind);
  const d = round2(Number(c?.delta) || 0);
  // El borde izquierdo toma el color del rework (si lo hay) y el puntito de la
  // línea de tiempo conserva el color del tamaño del cambio.
  return `
    <li class="ws-change-item${rw ? ' is-rw' : ''}">
      <span class="ws-change-dot" style="background:${wsChangeColor(c?.color, c?.kind)};box-shadow:0 0 0 3px ${wsChangeColor(c?.color, c?.kind)}29" aria-hidden="true"></span>
      <div class="ws-change-body" style="border-left-color:${color}">
        <div class="ws-change-head">
          <span class="ws-change-time">⏺ ${escapeHtml(wsClock(c?.at))} · cambio #${idx + 1}</span>
          <span class="ws-change-ago">${escapeHtml(fmtIncidentAgo(c?.at))}</span>
        </div>
        <div class="ws-change-tags">
          <span class="ws-change-kind" style="color:${wsChangeColor(c?.color, c?.kind)};border-color:${wsChangeColor(c?.color, c?.kind)}88;background:${wsChangeColor(c?.color, c?.kind)}22">${escapeHtml(wsChangeKindLabel(c))}</span>
          ${d ? `<span class="ws-change-delta" title="Aporte aplicado al % del proyecto al registrarlo">+${fmtPct(d)} aplicado</span>` : ''}
          ${rw ? wsReworkChipHtml(rw, { compact: true }) : ''}
        </div>
        <p class="ws-change-text">${escapeHtml(c?.text || '')}</p>
        <span class="ws-change-by">👤 ${escapeHtml(c?.author || '—')}</span>
      </div>
    </li>`;
}

// ── Reworks (cambios masivos) ──────────────────────────────────────────
// Un rework agrupa los cambios que son parte del MISMO trabajo grande, para no
// perderlos en una lista larga y saber de un vistazo cuánto lleva y si está
// en pausa. El estado lo decide la sesión: si la sesión en vivo se pausa, el
// rework queda pausado también hasta que se retome.
//
//   active  → la sesión está corriendo: se trabaja ahora.
//   paused  → la sesión se pausó: el rework también.
//   pending → la sesión se cerró pero el rework sigue abierto (falta otra).
//   done    → el admin lo marcó como terminado.
const WS_REWORK_STATES = {
  active: { icon: '🔄', label: 'en curso', title: 'La sesión que lo contiene está corriendo: el grupo se trabaja ahora' },
  paused: { icon: '⏸', label: 'pausado', title: 'Pausado junto con la sesión en vivo. Se retoma cuando la sesión vuelva' },
  pending: { icon: '⏳', label: 'esperando', title: 'La sesión se cerró y el grupo sigue abierto: falta retomarlo en otra sesión' },
  done: { icon: '✅', label: 'terminado', title: 'Marcado como terminado' }
};
const WS_REWORK_COLORS = ['#a855f7', '#22d3ee', '#f97316', '#34d399', '#ec4899', '#818cf8', '#facc15', '#fb7185'];
const WS_REWORK_1 = 'grupo';
const WS_REWORK_N = 'grupos';
// Tipo de grupo: 'rework' = revamp/rediseño de algo que ya existe,
// 'major' = trabajo grande nuevo (se destaca porque suele aportar mucho %).
// Lo viejo sin tipo cuenta como rework, que era lo único que había.
const WS_REWORK_KINDS = {
  rework: { icon: '♻️', label: 'Rework', title: 'Revamp o rediseño de algo que ya existe' },
  major: { icon: '🚀', label: 'Trabajo grande', title: 'Trabajo grande nuevo: suele aportar mucho % al proyecto' }
};
function wsReworkKindMeta(kind) {
  return WS_REWORK_KINDS[kind] || WS_REWORK_KINDS.rework;
}

function wsReworkStateMeta(state) {
  return WS_REWORK_STATES[state] || WS_REWORK_STATES.pending;
}
function wsReworkColor(color) {
  const s = String(color || '').trim();
  if (/^#[0-9a-fA-F]{6}$/.test(s)) return s.toLowerCase();
  if (/^#[0-9a-fA-F]{3}$/.test(s)) return `#${s[1]}${s[1]}${s[2]}${s[2]}${s[3]}${s[3]}`.toLowerCase();
  return '#a855f7';
}
function wsReworksOf(s) {
  return Array.isArray(s?.reworks) ? s.reworks : [];
}
// Mismo nombre → misma clave (sin tildes, minúsculas). Es lo que permite que
// un rework se reconoce aunque el trabajo se haya cortado y siga en otra sesión.
function wsReworkKey(name) {
  return String(name || '').trim().toLowerCase()
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60);
}
// Color por defecto: se va girando para que dos reworks nuevos no salgan igual.
function wsNextReworkColor() {
  const all = Object.values(wsReworkIndexAll()).filter((r) => r && r.status !== 'done');
  const n = all.length % WS_REWORK_COLORS.length;
  return WS_REWORK_COLORS[n];
}

// Índice de TODOS los reworks de las sesiones ya cargadas (por clave). Se
// memoriza porque se usa mucho (cada cambio pregunta por su rework) y solo
// cambia cuando se recargan las sesiones.
let wsReworkIndex = null;
function wsInvalidateReworkIndex() { wsReworkIndex = null; }
function wsReworkIndexAll() {
  if (wsReworkIndex) return wsReworkIndex;
  const map = new Map();
  (Array.isArray(wsCache) ? wsCache : []).forEach((s) => {
    wsReworksOf(s).forEach((r) => {
      const prev = map.get(r.key);
      // Si vive en varias sesiones se queda el que más cambios tiene: es el
      // que mejor resume el rework.
      if (!prev || Number(r.changes_count || 0) > Number(prev.changes_count || 0)) map.set(r.key, r);
    });
  });
  wsReworkIndex = map;
  return map;
}
// El rework de un cambio: primero el de la sesión, y si ya no está (se
// deshizo), el índice global, para no dejar el cambio sin identificar.
function wsReworkOfChange(c, session) {
  const key = c?.rework_key;
  if (!key) return null;
  return wsReworksOf(session).find((r) => r.key === key)
    || wsReworkIndexAll().get(key)
    || null;
}
// Todos los reworks de todas las sesiones, sin repetir los que están en varias.
function wsAllReworks() {
  return [...wsReworkIndexAll().values()];
}
// Reworks que todavía no están terminados y se pueden colgar o seguir: solo
// los de sesiones abiertas del mismo proyecto (o de sesiones generales).
function wsOpenReworks(projectId, sessionId) {
  const pid = projectId != null ? Number(projectId) : null;
  const seen = new Set();
  const out = [];
  (Array.isArray(wsCache) ? wsCache : []).forEach((s) => {
    wsReworksOf(s).forEach((r) => {
      if (r.status === 'done' || seen.has(r.key)) return;
      // Del mismo proyecto, o generales, o de la misma sesión.
      const pids = (s.project_id != null) ? Number(s.project_id) : null;
      if (pid != null && pids != null && pids !== pid) return;
      if (s.status === 'done') return;
      seen.add(r.key);
      out.push(r);
    });
  });
  return out.sort((a, b) => String(b.last_at || '').localeCompare(String(a.last_at || '')));
}
// Un chip del grupo con su tipo y su estado. El ⏸ es lo que deja claro que
// está pausado junto con la sesión.
function wsReworkChipHtml(rw, opts = {}) {
  if (!rw) return '';
  const color = wsReworkColor(rw.color);
  const meta = wsReworkStateMeta(rw.state);
  const kind = wsReworkKindMeta(rw.kind);
  const title = opts.compact
    ? `${rw.name} — ${kind.label} — ${meta.label}`
    : `${rw.name} · ${kind.label} · ${meta.label}${rw.changes_count ? ` · ${wsCount(rw.changes_count, 'cambio', 'cambios')}` : ''}${rw.changes_delta ? ` · +${fmtPct(rw.changes_delta)}` : ''}`;
  return `<span class="ws-rw-chip is-${escapeHtml(rw.state || 'pending')}" style="color:${color};border-color:${color}99;background:${color}22" title="${escapeHtml(title)}">
    <i style="background:${color}"></i>${kind.icon} ${escapeHtml(rw.name)}
    <b title="${escapeHtml(meta.title)}">${meta.icon} ${escapeHtml(meta.label)}</b>
  </span>`;
}
// Cabecera que separa los cambios de un mismo grupo: nombre, tipo, estado,
// cuántos cambios lleva y el % que ya aportó. Con `actions` aparecen los botones.
function wsReworkGroupHeadHtml(rw, items, opts = {}) {
  if (!rw) return '';
  const color = wsReworkColor(rw.color);
  const meta = wsReworkStateMeta(rw.state);
  const kind = wsReworkKindMeta(rw.kind);
  const major = rw.kind === 'major';
  const ats = items.map((r) => r.c?.at).filter(Boolean);
  const delta = round2(items.reduce((sum, r) => sum + (r.c?.applied ? (Number(r.c?.delta) || 0) : 0), 0));
  const range = ats.length > 1 ? `${wsClock(ats[0])} → ${wsClock(ats[ats.length - 1])}` : wsClock(ats[0]);
  const paused = rw.state === 'paused';
  return `
    <li class="ws-rw-head${opts.actions ? ' has-actions' : ''}${major ? ' is-major' : ''}" style="--rw:${color}" data-ws-rw="${escapeHtml(rw.key)}">
      <span class="ws-rw-line" aria-hidden="true"></span>
      <div class="ws-rw-info">
        <div class="ws-rw-title">
          <span class="ws-rw-name">${kind.icon} ${escapeHtml(rw.name)}</span>
          <span class="ws-rw-kind is-${major ? 'major' : 'rework'}" title="${escapeHtml(kind.title)}">${kind.icon} ${escapeHtml(kind.label)}</span>
          <span class="ws-rw-state is-${escapeHtml(rw.state || 'pending')}" title="${escapeHtml(meta.title)}">${meta.icon} ${escapeHtml(meta.label)}</span>
        </div>
        <div class="ws-rw-meta">
          ${wsCount(items.length, 'cambio', 'cambios')}
          ${delta ? (major
            ? ` · <b class="ws-rw-big-delta">+${fmtPct(delta)} al proyecto 🚀</b>`
            : ` · <b>+${fmtPct(delta)}</b> aplicado al proyecto`) : ''}
          ${range && range !== '--:--' ? ` · ${escapeHtml(range)}` : ''}
          ${rw.note ? ` · ${escapeHtml(rw.note)}` : ''}
        </div>
        ${paused ? `<p class="ws-rw-note">⏸ <b>Pausado junto con la sesión en vivo.</b> Los ${wsCount(items.length, 'cambio', 'cambios')} quedan esperando: cuando retomes la sesión, el grupo sigue como estaba.</p>` : ''}
      </div>
      ${opts.actions ? `
      <span class="ws-rw-actions">
        <button class="btn btn-ghost btn-mini" data-adm-ev="click" data-adm="openWsReworkForm" data-adm-a0="s:${escapeHtml(rw.key)}" title="Renombrar, cambiar el tipo, el color o la nota">✏️</button>
        ${rw.status === 'done'
          ? `<button class="btn btn-ghost btn-mini" data-adm-ev="click" data-adm="setWsReworkDone" data-adm-a0="s:${escapeHtml(rw.key)}" data-adm-a1="b:0" title="Volver a abrirlo">↩️ Reabrir</button>`
          : `<button class="btn btn-ghost btn-mini" data-adm-ev="click" data-adm="setWsReworkDone" data-adm-a0="s:${escapeHtml(rw.key)}" data-adm-a1="b:1" title="Marcar el grupo como terminado">✅ Terminado</button>`}
      </span>` : ''}
    </li>`;
}
// Tira de reworks de una sesión: qué hay activo, qué está pausado y qué
// quedó esperando. Se pinta en la fila de la sesión y en la barra en vivo.
function wsReworksStripHtml(s, opts = {}) {
  const list = wsReworksOf(s);
  if (!list.length) return '';
  const open = list.filter((r) => r.status !== 'done');
  return `<div class="ws-rw-strip">
    <span class="ws-rw-strip-label">🧩 ${wsCount(list.length, WS_REWORK_1, WS_REWORK_N)}</span>
    ${list.map((r) => wsReworkChipHtml(r)).join('')}
    ${open.length && !opts.bare ? `<span class="ws-rw-strip-hint" title="Los cambios del grupo quedan conectados entre sí y se identifican por nombre">${wsCount(open.length, 'grupo abierto', 'grupos abiertos')}</span>` : ''}
  </div>`;
}
// Los reworks que tiene la sesión, ordenados: primero los que hay que mirar
// (en curso / pausados), después los que esperan y al final los terminados.
function wsReworksSorted(s) {
  const order = { active: 0, paused: 1, pending: 2, done: 3 };
  return wsReworksOf(s).slice().sort((a, b) =>
    (order[a.state] ?? 9) - (order[b.state] ?? 9)
    || String(b.last_at || '').localeCompare(String(a.last_at || '')));
}

// ── Barra en vivo (MULTI) ──
// Una fila por sesión corriendo, cada una con su cronómetro y sus botones.
// Se refresca con el mismo tick de 1s del reloj (startWsClock).
// Para no tapar clics, solo se reconstruye el HTML cuando cambia la lista;
// cada segundo solo se actualizan los cronómetros.
let wsLiveSig = '';
function renderWsLiveBar() {
  renderWsPausedBar();
  const bar = document.getElementById('ws-live-bar');
  if (!bar) return;
  const note = document.getElementById('ws-live-note');
  const list = wsRunningList();
  const btn = document.getElementById('ws-start-btn');
  // El botón principal SIEMPRE abre una nueva sesión: ya no se bloquea ni
  // se convierte en "detener" aunque haya otras corriendo.
  if (btn) {
    btn.textContent = list.length ? `＋ Iniciar otra en vivo (${list.length} corriendo)` : '⏱ Iniciar en tiempo real';
    btn.classList.remove('ws-start-btn-stop');
    btn.onclick = () => openWsRealtimeForm();
  }
  if (!list.length) {
    wsLiveSig = '';
    bar.classList.add('hidden');
    bar.innerHTML = '';
    if (note) { note.classList.add('hidden'); note.innerHTML = ''; }
    return;
  }
  bar.classList.remove('hidden');
  // Solo se repinta la estructura si cambió la lista (evita tapar clics).
  const sig = list.map((s) => `${s.id}:${s.status}:${s.title}:${s.project_id}:${wsReworksOf(s).map((r) => `${r.key}:${r.state}:${r.changes_count}`).join(',')}`).join('|');
  if (sig !== wsLiveSig) {
    wsLiveSig = sig;
    bar.innerHTML = list.map((s) => `
      <div class="ws-live-row" data-ws-live-row="${Number(s.id)}">
        <div class="ws-live-main">
          <span class="ws-live-pulse" aria-hidden="true"></span>
          <div class="ws-live-info">
            <span class="ws-live-tag">EN VIVO</span>
            <span class="ws-live-proj">${escapeHtml(s.project_id ? (s.project_name || `#${s.project_id}`) : 'Sin proyecto')}</span>
            <span class="ws-live-title">${escapeHtml(s.title)}</span>
            <span class="ws-live-since" data-ws-since="${Number(s.id)}">${escapeHtml(wsLiveSinceLabel(s))}</span>
            ${wsReworksStripHtml(s)}
          </div>
        </div>
        <div class="ws-live-right">
          <span class="ws-live-timer" data-ws-timer="${Number(s.id)}">${wsStopwatch(wsElapsedSeconds(s))}</span>
          <button class="btn btn-ghost btn-sm" data-adm-ev="click" data-adm="openWsChangeForm" data-adm-a0="r:${Number(s.id)}" title="Anotar qué hiciste: queda con la hora en esta sesión">⏺ Cambio</button>
          <button class="btn btn-ghost btn-sm" data-adm-ev="click" data-adm="openWsReworkForm" data-adm-a0="x:" data-adm-a1="r:${Number(s.id)}" title="Crear un grupo en ESTA sesión: agrupa los cambios que son parte del mismo trabajo grande">🧩 Grupo</button>
          <button class="btn btn-ghost btn-sm" data-adm-ev="click" data-adm="openWsStopForm" data-adm-a0="r:${Number(s.id)}" title="Corregir los datos antes de cerrar">✏️ Datos</button>
          <button class="btn ws-stop-btn btn-sm" data-adm-ev="click" data-adm="openWsStopForm" data-adm-a0="r:${Number(s.id)}" title="Detener el cronómetro">⏹ Detener</button>
        </div>
      </div>`).join('');
  }
  // Cronómetros al día (sin reconstruir).
  list.forEach((s) => {
    const t = bar.querySelector(`[data-ws-timer="${Number(s.id)}"]`);
    if (t) t.textContent = wsStopwatch(wsElapsedSeconds(s));
  });
  // Nota conjunta: qué sigue abierto + avisos de medianoche por sesión.
  if (note) {
    const names = list.map((s) => `<b>${escapeHtml(s.title)}</b>`).join(' · ');
    const crosses = list.filter((s) => s.crosses_midnight);
    const crossMsg = crosses.length
      ? ` Ya cruzó la medianoche: ${escapeHtml((wsCrossSplit(crosses[0]) || {}).text || 'el trabajo se va a repartir entre los dos días')}${crosses.length > 1 ? ` (+${crosses.length - 1} más)` : ''}.`
      : '';
    // Los reworks abiertos que hay ahora mismo: al pausar la sesión, el rework
    // se pausa con ella, así que conviene nombrarlo desde ya.
    const liveReworks = [];
    list.forEach((s) => wsReworksSorted(s).forEach((r) => {
      if (r.status === 'done') return;
      if (liveReworks.some((x) => x.key === r.key)) return;
      liveReworks.push(r);
    }));
    const rwMsg = liveReworks.length
      ? ` <b>${liveReworks.length === 1 ? 'Grupo en curso' : 'Grupos en curso'}:</b> ${liveReworks.map((r) => `<b>${escapeHtml(r.name)}</b> (${wsCount(r.changes_count || 0, 'cambio', 'cambios')}${r.changes_delta ? ` · +${fmtPct(r.changes_delta)}` : ''})`).join(' · ')}. Al pausar la sesión, ${liveReworks.length === 1 ? 'queda pausado también' : 'quedan pausados también'} hasta que la retomes.`
      : '';
    note.innerHTML = `<span>● ${list.length} en vivo: ${names}. El cronómetro corre y al detener cada una se guarda sola su hora de fin.${crossMsg}${rwMsg}</span>`;
    note.classList.remove('hidden');
  }
}

// "desde las 15:00", "retomada a las 15:00" y, si empezó otro día, el día:
// trabajando después de las 00:00 hay que saber que el bloque es de ayer.
function wsLiveSinceLabel(s) {
  const last = (s.parts && s.parts.length ? s.parts[s.parts.length - 1] : null) || s;
  const at = wsClock(last.from || s.started_at);
  if (last.resumed) return `retomada a las ${at}`;
  const startDay = (s.parts && s.parts.length && s.parts[0].day) || '';
  const crossDay = startDay && startDay !== wsTodayKey() ? ` del ${wsShortDay(startDay)}` : '';
  return `desde las ${at}${crossDay}`;
}

// "28/09" a partir de "2026-09-28".
function wsShortDay(key) {
  const s = String(key || '');
  return /^\d{4}-\d{2}-\d{2}$/.test(s) ? `${s.slice(8)}/${s.slice(5, 7)}` : s;
}

// Una sesión que cruzó la medianoche se reparte sola entre los días (lo hace
// el backend al partir por día). Esto es solo para que se entienda: dice
// cuántos minutos quedan en cada día en vez de solo nombrar las fechas.
function wsCrossSplit(s) {
  const first = String(s?.local_day || '');
  const last = String(s?.end_local_day || '');
  const days = [...new Set((s?.segments || []).map((g) => g.day))];
  if (!first || !last || first === last || days.length < 2) return null;
  // Con más de dos días, el reparto se vuelve largo: se resume.
  if (days.length > 2) {
    return {
      days: days.length,
      text: `el trabajo se reparte entre ${wsCount(days.length, 'día', 'días')} `
        + `(${wsShortDay(first)} a ${wsShortDay(last)}), a ${wsMinutes(days.map((d) => wsDayMinutesOf(s, d)).reduce((a, b) => a + b, 0))} en total`
    };
  }
  const beforeMin = wsDayMinutesOf(s, first);
  const afterMin = wsDayMinutesOf(s, last);
  return {
    days: 2,
    beforeMin,
    afterMin,
    beforeDay: first,
    afterDay: last,
    text: `${wsMinutes(beforeMin)} para el ${wsShortDay(first)} `
      + `y ${wsMinutes(afterMin)} para el ${wsShortDay(last)}`
  };
}

// Barra de las sesiones pausadas: avisa que hay trabajo interrumpido esperando
// ser retomado, con un botón para seguir ahora mismo. Los reworks abiertos de
// esas sesiones también están pausados: se nombran acá para que quede claro
// que ese cambio masivo espera junto con la sesión.
let wsPausedSig = '';
function renderWsPausedBar() {
  const bar = document.getElementById('ws-paused-bar');
  if (!bar) return;
  const list = wsPausedList();
  if (!list.length) {
    wsPausedSig = '';
    bar.classList.add('hidden');
    bar.innerHTML = '';
    return;
  }
  const first = list[0];
  // El reloj llama a esto cada segundo: solo se repinta cuando cambia algo,
  // porque rehacer el innerHTML taparía el clic en "Continuar".
  const pausedReworks = [];
  list.forEach((s) => wsReworksSorted(s).forEach((r) => {
    if (r.status === 'done' || pausedReworks.some((x) => x.key === r.key)) return;
    pausedReworks.push(r);
  }));
  const sig = list.map((s) => `${s.id}:${s.status}:${s.ended_at || ''}`).join('|')
    + `#${pausedReworks.map((r) => `${r.key}:${r.changes_count}`).join(',')}`;
  const age = Math.floor(wsMinutesSince(first.ended_at) / 5);   // el "hace X" cada 5 min
  const full = `${sig}#${age}`;
  if (full === wsPausedSig) return;
  wsPausedSig = full;
  bar.classList.remove('hidden');
  const extra = list.length > 1 ? ` y ${list.length - 1} más` : '';
  const howLong = first.ended_at ? `hace ${wsMinutes(wsMinutesSince(first.ended_at))}` : '';
  // Los reworks pausados: son los cambios masivos que también quedaron
  // esperando, con lo que llevan hecho para poder retomarlos de un vistazo.
  const rwLine = pausedReworks.length
    ? `<div class="ws-paused-reworks">
        <span class="ws-paused-rw-label">🧩 ${pausedReworks.length === 1 ? 'Grupo pausado también' : 'Grupos pausados también'}</span>
        ${pausedReworks.map((r) => `
          <span class="ws-paused-rw" style="--rw:${wsReworkColor(r.color)}">
            <b>${escapeHtml(r.name)}</b>
            <span class="ws-rw-state is-paused" title="${escapeHtml(wsReworkStateMeta('paused').title)}">⏸ pausado</span>
            <span>${wsCount(r.changes_count || 0, 'cambio', 'cambios')}${r.changes_delta ? ` · +${fmtPct(r.changes_delta)}` : ''}</span>
          </span>`).join('')}
        <span class="ws-paused-rw-hint">Se retoman juntos: cuando continués la sesión, el grupo vuelve a la cola.</span>
      </div>`
    : '';
  bar.innerHTML = `
    <span class="ws-paused-icon" aria-hidden="true">⏸</span>
    <span class="ws-paused-info">
      <b>${escapeHtml(first.title)}</b> quedó pausada${extra}${howLong ? ` · ${howLong}` : ''}
      ${first.incomplete_reason ? `<em> — ${escapeHtml(first.incomplete_reason)}</em>` : ''}
      ${rwLine}
    </span>
    <button class="btn btn-ws-pause btn-sm" data-adm-ev="click" data-adm="resumeWsSession" data-adm-a0="r:${Number(first.id)}"
      title="Abrir un tramo nuevo y arrancar el cronómetro de nuevo">▶ Continuar ahora</button>`;
}

// Minutos transcurridos desde un instante (para "hace 2 h 5 min").
function wsMinutesSince(iso) {
  const t = iso ? new Date(iso).getTime() : NaN;
  if (!Number.isFinite(t)) return 0;
  return Math.max(0, Math.round((Date.now() - t) / 60000));
}

// ── Paso 1: pedir los datos ANTES de arrancar ──
// Se pueden tener VARIAS en vivo a la vez: nunca se redirige a detener.
function openWsRealtimeForm() {
  const running = wsRunningList();
  const body = document.getElementById('ws-modal-body');
  if (!body) return;
  wsModalStep = 'start';
  hideAlert('wsrt-alert');
  body.innerHTML = `
    <div class="devmodal-head">
      <div class="devmodal-icon">⏱</div>
      <div class="devmodal-head-info">
        <h3 class="devmodal-title">Iniciar sesión en tiempo real</h3>
        <p class="modal-tagline">Contá qué vas a hacer y el reloj arranca solo.</p>
      </div>
    </div>
    <div class="wsrt-note">
      🕐 Al confirmar, la <b>hora de inicio se toma automáticamente</b> y queda corriendo un cronómetro.
      Cuando la detengas se toma sola la <b>hora de fin</b> y se aplica el avance al proyecto.
      ${running.length ? `<br>ℹ️ Ya hay <b>${running.length} en vivo</b> (${running.map((s) => escapeHtml(s.title)).join(' · ')}): esta arranca como una más, con su propio cronómetro.` : ''}
    </div>
    <div class="field-group">
      <label for="wsrt-project">¿De qué proyecto?</label>
      <select id="wsrt-project" data-adm-ev="change" data-adm="onWsrtProjectChange"></select>
    </div>
    <div class="field-group">
      <label for="wsrt-title">¿Qué vas a hacer? *</label>
      <input type="text" id="wsrt-title" maxlength="160" placeholder="Ej: Sistema de combate" autocomplete="off" />
    </div>
    <div class="field-group">
      <label for="wsrt-details">Detalle <small>(opcional, lo podés completar al terminar)</small></label>
      <textarea id="wsrt-details" rows="2" maxlength="4000" placeholder="Qué pensás hacer, qué queda pendiente…"></textarea>
    </div>
    <div id="wsrt-alert" class="alert-box hidden"></div>
    <div class="ws-step-actions">
      <button type="button" class="btn btn-ghost" data-adm-ev="click" data-adm="closeWsModal">Cancelar</button>
      <button type="button" class="btn ws-start-btn" id="wsrt-go" data-adm-ev="click" data-adm="startWsRealtime">▶ Iniciar ahora</button>
    </div>`;
  const sel = document.getElementById('wsrt-project');
  if (sel) {
    sel.innerHTML = devlogProjectOptions();
    const last = lastWsProjectId();
    if (last) sel.value = String(last);
  }
  onWsrtProjectChange();
  openWsModal();
  const first = document.getElementById('wsrt-title');
  if (first) setTimeout(() => first.focus(), 40);
}

// Último proyecto usado: evita tener que elegirlo en cada sesión.
let wsLastProjectId = 0;
function lastWsProjectId() {
  const sel = document.getElementById('wsrt-project');
  if (sel && sel.value) {
    wsLastProjectId = Number(sel.value);
  } else {
    const recent = wsCache.find((s) => s.project_id);
    if (recent) wsLastProjectId = Number(recent.project_id);
  }
  return wsLastProjectId;
}

function onWsrtProjectChange() {
  const sel = document.getElementById('wsrt-project');
  if (sel && sel.value) wsLastProjectId = Number(sel.value);
}

async function startWsRealtime() {
  const btn = document.getElementById('wsrt-go');
  const titleEl = document.getElementById('wsrt-title');
  const title = titleEl ? titleEl.value.trim() : '';
  if (!title) {
    return showAlert('wsrt-alert', 'Escribí qué vas a hacer antes de empezar.', 'error');
  }
  const sel = document.getElementById('wsrt-project');
  if (btn) { btn.disabled = true; btn.textContent = '▶ Arrancando…'; }
  try {
    const res = await adminFetch(API_BASE + '/ows-work-sessions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        project_id: sel && sel.value ? Number(sel.value) : null,
        title,
        details: (document.getElementById('wsrt-details') || {}).value || '',
        realtime: true,
        tz_offset: wsTzOffset(),
        created_by: getCurrentAdminName()
      })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    closeWsModal();
    // La sesión arranca en su día; si el panel estaba en otro día, saltamos.
    const s = data.session;
    if (s && s.local_day) setWsDayKey(s.local_day);
    else await loadWorkSessions();
    // El tick del reloj ya corre; la barra se pinta en el siguiente frame.
    setTimeout(() => { renderWsLiveBar(); startWsClock(); }, 0);
    showToast(`⏱ Sesión iniciada: ${title} — el cronómetro corre desde las ${wsClock(s && s.started_at)}`);
  } catch (err) {
    showAlert('wsrt-alert', err.message || 'No se pudo iniciar la sesión.', 'error');
    if (btn) { btn.disabled = false; btn.textContent = '▶ Iniciar ahora'; }
  }
}

// ── Paso 2: detener y decir cuánto avanzó ──
function openWsStopForm(id) {
  const s = wsCache.find((x) => Number(x.id) === Number(id)) || wsRunning();
  if (!s) return showToast('⚠️ No hay ninguna sesión en vivo corriendo');
  const body = document.getElementById('ws-modal-body');
  if (!body) return;
  wsModalStep = 'stop';
  wsStopId = Number(s.id);
  hideAlert('wsrt-alert');
  const elapsed = wsElapsedSeconds(s);
  const proj = s.project_id ? (s.project_name || `#${s.project_id}`) : 'Sin proyecto';
  const room = Math.max(0, 100 - currentProjectPercent(s.project_id));
  // Si ya cruzó la medianoche, se avisa ANTES de guardar nada: el reparto lo
  // hace el backend solo, pero conviene que se vea cuánto queda en cada día.
  const cross = s.crosses_midnight;
  const split = wsCrossSplit(s);
  // Si la sesión ya fue interrumpida antes, se recuerda el historial: es lo que
  // deja claro que este cierre es "la vuelta después de la pausa".
  const history = wsStoryHtml(s, { compact: false });
  body.innerHTML = `
    <div class="devmodal-head">
      <div class="devmodal-icon">⏹</div>
      <div class="devmodal-head-info">
        <h3 class="devmodal-title">${s.parts_count > 1 ? 'Cerrar la sesión retomada' : 'Detener la sesión'}</h3>
        <p class="modal-tagline">La hora de fin se toma automáticamente.</p>
      </div>
    </div>
    ${history}
    <div class="wsrt-summary">
      <div class="wsrt-sum-row"><span>Proyecto</span><b>${escapeHtml(proj)}</b></div>
      <div class="wsrt-sum-row"><span>Empezó</span><b>${wsClock(s.started_at)}</b></div>
      <div class="wsrt-sum-row wsrt-sum-live"><span>Este tramo</span><b id="wsrt-elapsed">${wsStopwatch(elapsed)}</b></div>
      ${s.parts_count > 1 ? `<div class="wsrt-sum-row"><span>Trabajado antes</span><b>${wsMinutes(s.duration_minutes)}</b></div>` : ''}
      ${split ? `<div class="wsrt-sum-row wsrt-sum-split"><span>Reparto por día</span><b>${escapeHtml(split.days === 2
        ? `${wsMinutes(split.beforeMin)} ${wsShortDay(split.beforeDay)} · ${wsMinutes(split.afterMin)} ${wsShortDay(split.afterDay)}`
        : split.text)}</b></div>` : ''}
      <div class="wsrt-sum-row"><span>Terminará</span><b id="wsrt-end">${wsClock(new Date().toISOString())}</b></div>
    </div>
    ${cross ? `<div class="wsrt-note is-warn">🌙 Esta sesión cruzó la medianoche: se va a repartir sola, <b>${split ? escapeHtml(split.text) : 'entre los dos días'}</b>. No tenés que hacer nada.</div>` : ''}
    <div class="ws-change-block">
      <label class="ws-change-label">⏺ Cambios de esta sesión <small>qué hiciste y a qué hora</small></label>
      <div id="ws-stop-changes">${wsChangesHtml(s.changes, { empty: true, session: s })}</div>
      <div class="ws-change-add">
        <input type="text" id="ws-change-inline-${Number(s.id)}" maxlength="500" placeholder="Ej: Corregí el bug crítico del inventario" data-adm-ev="keydown" data-adm-key="Enter" data-adm="addWsChange" data-adm-a0="r:${Number(s.id)}" data-adm-a1="o:inline" autocomplete="off" />
        <button type="button" class="btn btn-ghost btn-mini" id="ws-change-rework-toggle-inline-${Number(s.id)}" title="Asignar a un grupo (solo para trabajos muy grandes)" data-adm-ev="click" data-adm="toggleWsChangeReworkInline" data-adm-a0="r:${Number(s.id)}">🧩</button>
        <span id="ws-change-rework-wrap-inline-${Number(s.id)}" class="ws-change-rework-wrap hidden">
        <select id="ws-change-rework-inline-${Number(s.id)}" class="ws-change-rework-sel" title="Grupo (solo para trabajos muy grandes)" data-adm-ev="change" data-adm="syncWsChangeReworkInline" data-adm-a0="r:${Number(s.id)}">${wsReworkSelectHtml(s)}</select>
        <span id="ws-change-rework-new-inline-${Number(s.id)}" class="ws-change-rework-new hidden">
          <input type="text" id="ws-change-rework-name-inline-${Number(s.id)}" maxlength="80" placeholder="Nombre del grupo" data-adm-ev="input" data-adm="syncWsChangeReworkInline" data-adm-a0="r:${Number(s.id)}" autocomplete="off" />
          <input type="color" id="ws-change-rework-color-inline-${Number(s.id)}" value="${wsNextReworkColor()}" title="Color del grupo" />
        </span>
        </span>
        <select id="ws-change-preset-inline-${Number(s.id)}" class="ws-change-preset-sel" title="Preset de estado (Bug, Limpieza…)" data-adm-ev="change" data-adm="applyWsChangePresetInline" data-adm-a0="r:${Number(s.id)}">${wsChangePresetOptionsHtml()}</select>
        <select id="ws-change-kind-inline-${Number(s.id)}" class="ws-change-kind-sel" title="Tamaño del cambio" data-adm-ev="change" data-adm="admClearWsPresetInline" data-adm-a0="r:${Number(s.id)}">
          <option value="chico">Chico</option>
          <option value="mediano" selected>Mediano</option>
          <option value="grande">Grande</option>
          <option value="critico">Crítico</option>
          <option value="custom">Personali…</option>
        </select>
        <input type="color" id="ws-change-color-inline-${Number(s.id)}" class="ws-change-color" value="#fbbf24" title="Color del cambio" />
        <span class="ws-change-delta-wrap" title="Aporte al %: se aplica al instante">
          <input type="text" id="ws-change-delta-inline-${Number(s.id)}" class="ws-change-delta-num" inputmode="decimal" value="0" autocomplete="off" /><span class="ws-delta-sign">%</span>
        </span>
        <button type="button" class="btn btn-ghost btn-sm" data-adm-ev="click" data-adm="addWsChange" data-adm-a0="r:${Number(s.id)}" data-adm-a1="o:inline">＋ Registrar</button>
      </div>
      <p class="form-hint" id="ws-stop-changes-hint"></p>
        <p class="form-hint">La hora se pone sola. Queda en la sesión y en el devlog del día. Solo para trabajos muy grandes: con 🧩 se conecta el cambio a un rework (se pausa junto con la sesión).</p>
    </div>
    <div class="field-group">
      <label for="wsrt-title2">¿Qué hiciste?</label>
      <input type="text" id="wsrt-title2" maxlength="160" value="${escapeHtml(s.title)}" />
    </div>
    <div class="field-group">
      <label for="wsrt-details2">Detalle</label>
      <textarea id="wsrt-details2" rows="3" maxlength="4000" placeholder="Qué se hizo, qué quedó pendiente…">${escapeHtml(s.details || '')}</textarea>
    </div>
    <div class="field-group">
      <label>¿Cuánto avanzó? <small>(en total, contando los tramos anteriores)</small></label>
      <div class="ws-delta">
        <input type="range" id="wsrt-delta-range" min="0" max="${room}" step="0.5" value="0" data-adm-ev="input" data-adm="syncWsrtDelta" />
        <input type="text" id="wsrt-delta-num" inputmode="decimal" value="0" data-adm-ev="input" data-adm="syncWsrtDelta" data-adm-a0="b:1" />
        <span class="ws-delta-sign">%</span>
      </div>
      <p class="form-hint" id="wsrt-delta-hint"></p>
    </div>
    ${wsCompletionHtml('wsrt', s)}
    <div id="wsrt-alert" class="alert-box hidden"></div>
    <div class="ws-step-actions">
      <button type="button" class="btn btn-danger" data-adm-ev="click" data-adm="discardWsRunning">🗑️ Descartar</button>
      <button type="button" class="btn btn-ghost" data-adm-ev="click" data-adm="closeWsModal">Seguir trabajando</button>
      <button type="button" class="btn ws-stop-btn" id="wsrt-end-btn" data-adm-ev="click" data-adm="stopWsRealtime">⏹ Detener y guardar</button>
    </div>`;
  bindDecBlur('wsrt-delta-num', room);
  wsrtRoom = room;
  wsrtProject = s.project_id;
  onWsrtStopHint();
  onWsCompletionChange('wsrt');
  renderWsStopChanges(Number(s.id));
  openWsModal();
  startWsClock();
}

let wsModalStep = 'start';
let wsStopId = 0;
let wsrtRoom = 100;
let wsrtProject = null;

// El tick de 1s de startWsClock() ya refresca el modal de detener, así que
// acá no hace falta un temporizador propio.
function syncWsrtDelta(fromNum) {
  const range = document.getElementById('wsrt-delta-range');
  const num = document.getElementById('wsrt-delta-num');
  if (!range || !num) return;
  const { text, value } = fromNum
    ? readDecField(num.value, wsrtRoom)
    : readDecField(range.value, wsrtRoom);
  if (num.value !== text) num.value = text;
  range.value = String(value);
}
function onWsrtStopHint() {
  const hint = document.getElementById('wsrt-delta-hint');
  if (!hint) return;
  hint.innerHTML = wsrtProject
    ? `Queda <b>${fmtPct(currentProjectPercent(wsrtProject))}</b> de este proyecto: la sesión puede mover hasta <b>${fmtPct(wsrtRoom)}</b>. Con 0 la sesión queda registrada sin tocar el %.`
    : 'Sin proyecto no hay % que aplicar: con 0 la sesión queda solo registrada.';
}

async function stopWsRealtime() {
  const btn = document.getElementById('wsrt-end-btn');
  const id = wsStopId || wsRunningId();
  if (!id) return closeWsModal();
  const comp = readWsCompletion('wsrt');
  if (comp.completion !== 'complete' && !comp.incomplete_reason) {
    const msg = comp.completion === 'paused'
      ? 'Marcá por qué la interrumpiste: elegí un motivo o escribí uno.'
      : 'Marcá por qué quedó incompleta: elegí un motivo o escribí uno.';
    return showAlert('wsrt-alert', msg, 'error');
  }
  const delta = readDecField((document.getElementById('wsrt-delta-num') || {}).value, wsrtRoom).value || 0;
  const busy = comp.completion === 'complete' ? '⏹ Guardando…' : wsEndButtonLabel(comp.completion).replace(/^\S+\s*/, '');
  if (btn) { btn.disabled = true; btn.textContent = busy; }
  try {
    const res = await adminFetch(API_BASE + `/ows-work-sessions/${id}/stop`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        progress_delta: delta,
        completion: comp.completion,
        incomplete_reason: comp.incomplete_reason,
        title: (document.getElementById('wsrt-title2') || {}).value || undefined,
        details: (document.getElementById('wsrt-details2') || {}).value || undefined,
        tz_offset: wsTzOffset(),
        created_by: getCurrentAdminName()
      })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    closeWsModal();
    // El % se movió: se sincroniza con lo que dice el servidor.
    if (data.development) {
      const i = devProgressCache.findIndex((d) => Number(d.project_id) === Number(data.development.project_id));
      if (i >= 0) devProgressCache[i] = { ...devProgressCache[i], ...data.development };
      else devProgressCache.push(data.development);
      renderDevList();
      renderAdminProjectsList();
    }
    const s = data.session;
    const dur = data.duration_minutes != null ? data.duration_minutes : (s ? s.duration_minutes : 0);
    // Si terminó otro día, el panel salta a ese día (setWsDayKey ya recarga
    // las sesiones y el resumen de ese día).
    if (s && s.end_local_day) setWsDayKey(s.end_local_day);
    else { await loadWorkSessions(); await loadWsDaily(); }
    showWsStopToast(s, comp, dur, delta);
  } catch (err) {
    showAlert('wsrt-alert', err.message || 'No se pudo detener la sesión.', 'error');
    if (btn) { btn.disabled = false; btn.textContent = wsEndButtonLabel(readWsCompletion('wsrt').completion); }
  }
}

// El aviso de qué pasó. Si la sesión estaba pausada y se retomó, se cuenta la
// historia entera: se interrumpió, se continuó y se finalizó con éxito.
function showWsStopToast(s, comp, dur, delta) {
  const resumed = !!(s && s.parts_count > 1);
  // Los reworks abiertos de la sesión se nombran: es lo que el admin necesita
  // saber de una, porque son los cambios masivos que quedan a medio hacer.
  const openReworks = wsReworksSorted(s || {}).filter((r) => r.status !== 'done');
  const rwNames = openReworks.map((r) => r.name).join(', ');
  const rwTail = (state) => (openReworks.length
    ? ` 🧩 ${wsCount(openReworks.length, WS_REWORK_1, WS_REWORK_N)} (${rwNames}) ${state}.`
    : '');
  if (comp.completion === 'paused') {
    showToast(`⏸ Sesión pausada: ${wsMinutes(dur)} de trabajo. Cuando quieras seguir, tocá "▶ Continuar ahora" — `
      + `quedó anotado que se interrumpió (${comp.incomplete_reason}).`
      + rwTail('queda pausado también, hasta que la retomes'));
    return;
  }
  // Ya no está pausada: lo que quedó abierto pasa a "esperando otra sesión".
  const rwWait = rwTail('queda esperando a que lo retomes en otra sesión');
  if (comp.completion === 'incomplete') {
    showToast(`⚠️ Sesión guardada como incompleta: ${wsMinutes(dur)}${delta ? ` · ${fmtDelta(delta)} sumados al %` : ''} · ${comp.incomplete_reason}`
      + rwWait);
    return;
  }
  if (resumed && s.crosses_midnight) {
    showToast(`✅ Se interrumpió y se continuó: ${wsMinutes(dur)} en ${wsCount(s.parts_count, 'tramo', 'tramos')}, `
      + `repartidos entre el ${wsShortDay(s.local_day)} y el ${wsShortDay(s.end_local_day)} — finalizada con éxito.`
      + rwWait);
    return;
  }
  if (resumed) {
    const first = s.interrupts[0];
    showToast(`✅ Finalizada con éxito: se interrumpió a las ${wsClock(first.at)}${first.reason ? ` (${first.reason})` : ''}, `
      + `se continuó a las ${wsClock(first.resumed_at)} y terminó ahora. ${wsMinutes(dur)}${delta ? ` · ${fmtDelta(delta)} sumados al %` : ''}`
      + rwWait);
    return;
  }
  if (s && s.crosses_midnight) {
    const sp = wsCrossSplit(s);
    showToast(`🌙 ${wsMinutes(dur)}: empezó el ${wsShortDay(s.local_day)} y terminó el ${wsShortDay(s.end_local_day)}`
      + `${sp ? ` — ${sp.text}` : ' — repartido entre los dos días'}.` + rwWait);
    return;
  }
  showToast(`⏹ Sesión detenida: ${wsMinutes(dur)}${delta ? ` · ${fmtDelta(delta)} sumados al %` : ''}` + rwWait);
}

// Retomar una sesión pausada: el servidor abre un tramo nuevo y arranca el
// cronómetro de nuevo. Lo que ya se había trabajado queda intacto.
async function resumeWsSession(id) {
  if (!(await requireAuth())) return;
  const s = wsCache.find((x) => Number(x.id) === Number(id));
  if (!s) return;
  const last = (s.parts && s.parts.length ? s.parts[s.parts.length - 1] : null) || {};
  const since = s.ended_at ? ` Se había pausado ${last.reason ? `(${last.reason}) ` : ''}a las ${wsClock(s.ended_at)}.` : '';
  if (!window.confirm(`¿Retomar "${s.title}"?${since}\n\nEl cronómetro arranca de nuevo y el trabajo anterior queda como un tramo más.`)) return;
  try {
    const res = await adminFetch(API_BASE + `/ows-work-sessions/${id}/resume`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tz_offset: wsTzOffset(), created_by: getCurrentAdminName() })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    const ss = data.session;
    if (ss && ss.local_day) setWsDayKey(ss.local_day);
    else await loadWorkSessions();
    setTimeout(() => { renderWsLiveBar(); startWsClock(); }, 0);
    // Al retomar, los reworks que estaban pausados vuelven a la cola con ella.
    const backReworks = wsReworksSorted(s).filter((r) => r.status !== 'done');
    showToast(`▶ Retomada: ${ss.title} — el cronómetro corre desde las ${wsClock((ss.parts[ss.parts.length - 1] || {}).from)}. `
      + `Se anotó que se interrumpió a las ${wsClock(last.to || ss.started_at)} y se continuó ahora.`
      + (backReworks.length
        ? ` 🧩 ${wsCount(backReworks.length, 'grupo vuelve', 'grupos vuelven')} a la cola: ${backReworks.map((r) => r.name).join(', ')}.`
        : ''));
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

// ── Cambios en vivo: qué se hizo y a qué hora ──────────────────────────
// Con la sesión corriendo, el admin anota cada avance ("17:00 nuevo objeto",
// "18:30 bug crítico") y queda con la hora del servidor dentro de la sesión.
let wsChangeId = 0;
let wsChangeRoom = 100;
let wsChangeProject = null;
let wsChangeRework = '';

function openWsChangeForm(id) {
  const s = wsCache.find((x) => Number(x.id) === Number(id));
  if (!s) return showToast('⚠️ Sesión no encontrada');
  if (s.status === 'done') return showToast('⚠️ Esa sesión ya está cerrada.');
  const body = document.getElementById('ws-modal-body');
  if (!body) return;
  wsModalStep = 'change';
  wsChangeId = Number(s.id);
  wsChangeProject = s.project_id;
  wsChangeRoom = Math.max(0, 100 - currentProjectPercent(s.project_id));
  wsChangeRework = '';
  hideAlert('ws-change-alert');
  body.innerHTML = `
    <div class="devmodal-head">
      <div class="devmodal-icon">⏺</div>
      <div class="devmodal-head-info">
        <h3 class="devmodal-title">Registrar cambio</h3>
        <p class="modal-tagline">${escapeHtml(s.title)} · el cronómetro sigue corriendo</p>
      </div>
    </div>
    <div id="ws-change-list">${wsChangesHtml(s.changes, { empty: true, session: s })}</div>
    <details class="ws-rw-block ws-rw-details">
      <summary class="ws-rw-label">🧩 Grupo <small>opcional · solo para trabajos muy grandes</small></summary>
      <div class="ws-rw-row">
        <select id="ws-change-rework" data-adm-ev="change" data-adm="syncWsChangeRework">${wsReworkSelectHtml(s)}</select>
        <button type="button" class="btn btn-ghost btn-sm" data-adm-ev="click" data-adm="openWsReworkForm" title="Crear un grupo: se puede hacer antes o después de anotar el cambio">＋ Nuevo</button>
      </div>
      <div id="ws-change-rework-new" class="hidden">
        <input type="text" id="ws-change-rework-name" maxlength="80" placeholder="Ej: Menú de tiburones, Refactor del inventario…" data-adm-ev="input" data-adm="syncWsChangeRework" autocomplete="off" />
        <input type="color" id="ws-change-rework-color" value="${wsNextReworkColor()}" data-adm-ev="input" data-adm="syncWsChangeRework" title="Color del grupo" />
      </div>
      <div id="ws-change-rework-info" class="hidden"></div>
      <p class="form-hint">Los grupos son para <b>trabajos muy grandes</b>: si elegís uno, este cambio queda <b>conectado</b> a los demás del mismo grupo. Para cambios normales no hace falta tocar nada. Si pausás la sesión en vivo, <b>el grupo queda pausado también</b> hasta que la retomes.</p>
    </details>
    <div class="field-group">
      <label for="ws-change-text">¿Qué hiciste? *</label>
      <textarea id="ws-change-text" rows="2" maxlength="500" placeholder="Ej: Agregué el objeto X al juego"></textarea>
      <p class="form-hint">La hora se pone sola al registrarlo. Podés anotar varios en la misma sesión.</p>
    </div>
    <div class="field-group">
      <label>Presets de estado <small>Bugs, Limpiezas…: guardá nombre y color para reutilizarlos</small></label>
      <div class="ws-preset-row" id="ws-change-presets">${wsChangePresetsHtml()}</div>
    </div>
    <div class="field-group">
      <label>Tamaño del cambio *</label>
      <div class="ws-kind-grid">
        ${Object.entries(WS_CHANGE_KINDS).map(([k, m]) => `
          <label class="ws-kind${k === 'mediano' ? ' is-checked' : ''}" data-kind="${k}" style="--kind:${m.color}">
            <input type="radio" name="ws-change-kind" value="${k}"${k === 'mediano' ? ' checked' : ''} data-adm-ev="change" data-adm="syncWsChangeKind" />
            <span><i style="background:${m.color}"></i><b>${escapeHtml(m.label)}</b><small>${escapeHtml(m.hint)}</small></span>
          </label>`).join('')}
      </div>
    </div>
    <div class="field-group hidden" id="ws-change-custom-group">
      <label for="ws-change-custom">Nombre personalizado</label>
      <input type="text" id="ws-change-custom" maxlength="40" placeholder="Ej: Hotfix, Contenido, Balance…" data-adm-ev="input" data-adm="syncWsChangePreview" autocomplete="off" />
    </div>
    <div class="field-group">
      <label for="ws-change-color">Color del cambio</label>
      <div class="ws-color-row">
        <input type="color" id="ws-change-color" value="${WS_CHANGE_KINDS.mediano.color}" data-adm-ev="input" data-adm="syncWsChangePreview" title="Elegí el color" />
        <span class="ws-change-kind" id="ws-change-preview">Mediano</span>
      </div>
    </div>
    <div class="field-group">
      <label for="ws-change-delta">¿Cuánto avanzó con este cambio? <small>(opcional)</small></label>
      <div class="ws-delta">
        <input type="text" id="ws-change-delta" inputmode="decimal" value="0" data-adm-ev="input" data-adm="syncWsChangeDeltaHint" autocomplete="off" />
        <span class="ws-delta-sign">%</span>
      </div>
      <p class="form-hint" id="ws-change-delta-hint"></p>
    </div>
    <div id="ws-change-alert" class="alert-box hidden"></div>
    <div class="ws-step-actions">
      <button type="button" class="btn btn-ghost" data-adm-ev="click" data-adm="closeWsModal">Cerrar</button>
      <button type="button" class="btn ws-start-btn" id="ws-change-go" data-adm-ev="click" data-adm="addWsChange" data-adm-a0="r:${Number(s.id)}">⏺ Registrar cambio</button>
    </div>`;
  openWsModal();
  syncWsChangeKind();
  syncWsChangeRework();
  bindDecBlur('ws-change-delta', wsChangeRoom);
  syncWsChangeDeltaHint();
  const first = document.getElementById('ws-change-text');
  if (first) setTimeout(() => first.focus(), 40);
}

// Opciones del selector: primero los reworks de esta sesión (con lo que ya
// llevan) y después los que quedaron abiertos en otras sesiones del mismo
// proyecto, para poder seguir el mismo rework más adelante.
function wsReworkSelectHtml(s) {
  const own = wsReworksSorted(s);
  const others = wsOpenReworks(s && s.project_id, s && s.id)
    .filter((r) => !own.some((x) => x.key === r.key));
  const opt = (r, suffix) => `<option value="${escapeHtml(r.key)}">${wsReworkKindMeta(r.kind).icon} ${escapeHtml(r.name)}${suffix}</option>`;
  // Los grupos terminados se muestran deshabilitados: ya no aceptan cambios.
  const optOwn = (r) => {
    const suffix = r.status === 'done'
      ? ' · ✅ terminado'
      : (r.changes_count
        ? ` · ${wsCount(r.changes_count, 'cambio', 'cambios')}${r.changes_delta ? ` · +${fmtPct(r.changes_delta)}` : ''}`
        : '');
    return r.status === 'done'
      ? `<option value="${escapeHtml(r.key)}" disabled>${wsReworkKindMeta(r.kind).icon} ${escapeHtml(r.name)}${suffix}</option>`
      : opt(r, suffix);
  };
  return [
    '<option value="">— Sin grupo (cambio suelto) —</option>',
    own.length ? `<optgroup label="En esta sesión">${own.map(optOwn).join('')}</optgroup>` : '',
    others.length ? `<optgroup label="Abiertos en otras sesiones">${others.map((r) => opt(r, ` · ${wsCount(r.changes_count || 0, 'cambio', 'cambios')}`)).join('')}</optgroup>` : '',
    '<option value="__new">＋ Crear un grupo nuevo…</option>'
  ].join('');
}

// Muestra la tarjeta del rework elegido (o los campos para uno nuevo).
function syncWsChangeRework() {
  const sel = document.getElementById('ws-change-rework');
  if (!sel) return;
  const val = sel.value || '';
  // Si se eligió un rework, el bloque opcional queda abierto para que se vea.
  const det = sel.closest('details');
  if (det && val) det.open = true;
  const isNew = val === '__new';
  const box = document.getElementById('ws-change-rework-new');
  const info = document.getElementById('ws-change-rework-info');
  wsChangeRework = isNew ? '' : val;
  if (box) box.classList.toggle('hidden', !isNew);
  if (!info) return;
  if (isNew) {
    info.classList.add('hidden');
    info.innerHTML = '';
    syncWsChangeDeltaHint();
    return;
  }
  const rw = val ? wsReworkIndexAll().get(val) : null;
  if (!rw) {
    info.classList.add('hidden');
    info.innerHTML = '';
    syncWsChangeDeltaHint();
    return;
  }
  const meta = wsReworkStateMeta(rw.state);
  const kind = wsReworkKindMeta(rw.kind);
  const color = wsReworkColor(rw.color);
  info.classList.remove('hidden');
  info.innerHTML = `
    <div class="ws-rw-card is-${escapeHtml(rw.state || 'pending')}" style="--rw:${color}">
      <div class="ws-rw-card-head">
        <span class="ws-rw-card-dot" aria-hidden="true"></span>
        <b>${escapeHtml(rw.name)}</b>
        <span class="ws-rw-kind is-${rw.kind === 'major' ? 'major' : 'rework'}" title="${escapeHtml(kind.title)}">${kind.icon} ${escapeHtml(kind.label)}</span>
        <span class="ws-rw-state is-${escapeHtml(rw.state || 'pending')}" title="${escapeHtml(meta.title)}">${meta.icon} ${escapeHtml(meta.label)}</span>
        <button type="button" class="btn btn-ghost btn-mini" data-adm-ev="click" data-adm="openWsReworkForm" data-adm-a0="s:${escapeHtml(rw.key)}" title="Renombrar, cambiar el tipo, el color o la nota">✏️</button>
      </div>
      <div class="ws-rw-card-meta">
        ${wsCount(rw.changes_count || 0, 'cambio conectado', 'cambios conectados')}
        ${rw.changes_delta ? ` · ya aportó <b>+${fmtPct(rw.changes_delta)}</b>` : ' · todavía sin avance'}
        ${rw.last_at ? ` · último a las ${wsClock(rw.last_at)}` : ''}
      </div>
      ${rw.note ? `<p class="ws-rw-card-note">${escapeHtml(rw.note)}</p>` : ''}
      ${rw.state === 'paused' ? '<p class="ws-rw-card-warn">⏸ <b>Este grupo está pausado</b> porque la sesión que lo contiene quedó pausada. Se retoma solo cuando vuelvas a continuar esa sesión.</p>' : ''}
      ${rw.state === 'pending' ? '<p class="ws-rw-card-warn">⏳ La sesión anterior se cerró con este grupo todavía abierto: al registrar este cambio vuelve a quedar en curso.</p>' : ''}
      ${rw.status === 'done' ? '<p class="ws-rw-card-warn">✅ <b>Este grupo está terminado:</b> ya no se le pueden agregar más cambios. Reabrilo para continuarlo.</p>' : ''}
    </div>`;
  syncWsChangeDeltaHint();
}

// Hint del aporte: se aplica al instante, no espera al cierre. Si el cambio
// entra en un grupo, se aclara que se suma a lo que ya lleva ese grupo.
function syncWsChangeDeltaHint() {
  const hint = document.getElementById('ws-change-delta-hint');
  if (!hint) return;
  const rw = wsChangeRework ? wsReworkIndexAll().get(wsChangeRework) : null;
  const rwTxt = rw ? ` Este % se suma al grupo <b>${escapeHtml(rw.name)}</b>, que ya va ${rw.changes_delta ? `en <b>+${fmtPct(rw.changes_delta)}</b>` : 'en 0'}.` : '';
  hint.innerHTML = wsChangeProject
    ? `Queda <b>${fmtPct(currentProjectPercent(wsChangeProject))}</b> del proyecto: con más de 0 se aplica <b>al instante</b> al registrarlo. Con 0 solo queda anotado.${rwTxt}`
    : `Sin proyecto no hay % que mover: con 0 el cambio solo queda anotado.${rwTxt}`;
}

// ── Presets de estado del cambio ─────────────────────────────────────
// Nombre + color guardados para no tener que reescribirlos cada vez
// (Ej: Bug, Limpieza, Hotfix…). Se guardan en el navegador.
const WS_CHANGE_PRESETS_KEY = 'ows_change_presets';
const WS_CHANGE_PRESETS_DEFAULT = [
  { name: 'Bug', color: '#ef4444' },
  { name: 'Limpieza', color: '#22d3ee' }
];
function wsChangePresets() {
  try {
    const raw = JSON.parse(localStorage.getItem(WS_CHANGE_PRESETS_KEY) || 'null');
    if (Array.isArray(raw)) {
      return raw.filter((p) => p && typeof p.name === 'string' && p.name.trim())
        .map((p) => ({ name: p.name.trim().slice(0, 40), color: wsChangeColor(p.color, 'custom') }))
        .slice(0, 24);
    }
  } catch (_) {}
  return WS_CHANGE_PRESETS_DEFAULT.slice();
}
function wsSaveChangePresets(list) {
  try { localStorage.setItem(WS_CHANGE_PRESETS_KEY, JSON.stringify(list.slice(0, 24))); } catch (_) {}
}
function wsChangePresetsHtml() {
  const presets = wsChangePresets();
  return `${presets.map((p, i) => `
      <span class="ws-preset" style="--p:${p.color}">
        <button type="button" class="ws-preset-go" title="Usar «${escapeHtml(p.name)}»" data-adm-ev="click" data-adm="applyWsChangePreset" data-adm-a0="r:${i}"><i style="background:${p.color}"></i>${escapeHtml(p.name)}</button>
        <button type="button" class="ws-preset-x" title="Borrar preset" data-adm-ev="click" data-adm="delWsChangePreset" data-adm-a0="r:${i}">×</button>
      </span>`).join('')}
    <button type="button" class="ws-preset ws-preset-add" title="Guardar el nombre y color actuales como preset" data-adm-ev="click" data-adm="addWsChangePreset">＋ Guardar actual</button>`;
}
function wsChangePresetOptionsHtml() {
  return [
    '<option value="">— Preset… —</option>',
    ...wsChangePresets().map((p) => `<option value="${escapeHtml(p.name)}">${escapeHtml(p.name)}</option>`)
  ].join('');
}
function refreshWsChangePresets() {
  const box = document.getElementById('ws-change-presets');
  if (box) box.innerHTML = wsChangePresetsHtml();
  document.querySelectorAll('select[id^="ws-change-preset-inline-"]').forEach((sel) => {
    const keep = sel.value;
    sel.innerHTML = wsChangePresetOptionsHtml();
    sel.value = keep;
  });
}
// Aplica un preset al modal: queda como cambio personalizado con ese nombre.
function applyWsChangePreset(idx) {
  const p = wsChangePresets()[idx];
  if (!p) return;
  const radio = document.querySelector('input[name="ws-change-kind"][value="custom"]');
  if (radio) radio.checked = true;
  syncWsChangeKind();
  const custom = document.getElementById('ws-change-custom');
  if (custom) custom.value = p.name;
  const color = document.getElementById('ws-change-color');
  if (color) color.value = p.color;
  syncWsChangePreview();
}
// En la fila inline: un preset fija nombre (personalizado) y color.
function applyWsChangePresetInline(sid) {
  const sel = document.getElementById(`ws-change-preset-inline-${sid}`);
  const name = sel ? sel.value : '';
  const kindSel = document.getElementById(`ws-change-kind-inline-${sid}`);
  const color = document.getElementById(`ws-change-color-inline-${sid}`);
  if (!name) return;
  const p = wsChangePresets().find((x) => x.name === name);
  if (!p) return;
  if (kindSel) kindSel.value = 'custom';
  if (color) color.value = p.color;
}
function addWsChangePreset() {
  const custom = document.getElementById('ws-change-custom');
  const colorEl = document.getElementById('ws-change-color');
  const name = ((custom && custom.value) || '').trim().slice(0, 40);
  if (!name) return showToast('⚠️ Escribí el nombre del preset en «Nombre personalizado» (elegí Personalizado).');
  const list = wsChangePresets().filter((p) => p.name.toLowerCase() !== name.toLowerCase());
  list.push({ name, color: wsChangeColor(colorEl ? colorEl.value : '', 'custom') });
  wsSaveChangePresets(list);
  refreshWsChangePresets();
  showToast(`⏺ Preset «${name}» guardado`);
}
function delWsChangePreset(idx) {
  const list = wsChangePresets();
  const name = list[idx] ? list[idx].name : '';
  wsSaveChangePresets(list.filter((_, i) => i !== idx));
  refreshWsChangePresets();
  if (name) showToast(`Preset «${name}» borrado`);
}

// Tamaño elegido → muestra el nombre libre solo en personalizado y propone
// su color (después se puede cambiar a mano).
function syncWsChangeKind() {
  const checked = document.querySelector('input[name="ws-change-kind"]:checked');
  const kind = checked ? checked.value : 'mediano';
  document.querySelectorAll('.ws-kind').forEach((el) =>
    el.classList.toggle('is-checked', el.getAttribute('data-kind') === kind));
  const group = document.getElementById('ws-change-custom-group');
  if (group) group.classList.toggle('hidden', kind !== 'custom');
  const color = document.getElementById('ws-change-color');
  if (color) color.value = wsChangeKindMeta(kind).color;
  syncWsChangePreview();
}

function syncWsChangePreview() {
  const checked = document.querySelector('input[name="ws-change-kind"]:checked');
  const kind = checked ? checked.value : 'mediano';
  const colorEl = document.getElementById('ws-change-color');
  const prev = document.getElementById('ws-change-preview');
  if (!prev) return;
  const color = wsChangeColor(colorEl ? colorEl.value : '', kind);
  const label = kind === 'custom'
    ? ((document.getElementById('ws-change-custom')?.value || '').trim().slice(0, 40) || 'Personalizado')
    : wsChangeKindMeta(kind).label;
  prev.textContent = label;
  prev.style.color = color;
  prev.style.borderColor = `${color}88`;
  prev.style.background = `${color}22`;
}

// Lee tamaño + etiqueta libre + color del modal (o de la fila inline).
function readWsChangeMeta(sid, inline) {
  if (inline) {
    const presetName = (document.getElementById(`ws-change-preset-inline-${sid}`)?.value || '').trim();
    const color = document.getElementById(`ws-change-color-inline-${sid}`)?.value || '';
    if (presetName) {
      const p = wsChangePresets().find((x) => x.name === presetName);
      return { kind: 'custom', custom_label: presetName, color: p ? p.color : color };
    }
    const kind = document.getElementById(`ws-change-kind-inline-${sid}`)?.value || 'mediano';
    return { kind, custom_label: '', color };
  }
  const checked = document.querySelector('input[name="ws-change-kind"]:checked');
  const kind = checked ? checked.value : 'mediano';
  const custom_label = kind === 'custom'
    ? ((document.getElementById('ws-change-custom')?.value || '').trim().slice(0, 40))
    : '';
  const color = document.getElementById('ws-change-color')?.value || '';
  return { kind, custom_label, color };
}

// Lee el rework elegido (modal o fila inline) y arma lo que se manda:
//   uno existente → rework_key (el servidor lo reutiliza / lo trae de otra)
//   uno nuevo     → rework_name + rework_color (el servidor lo crea)
function readWsChangeRework(sid, inline) {
  const empty = { body: {} };
  const doneGuard = (val) => {
    const rw = wsReworkIndexAll().get(val);
    if (rw && rw.status === 'done') return { error: `El grupo "${rw.name}" ya está terminado: no se le pueden agregar más cambios. Reabrilo para continuarlo.` };
    return null;
  };
  if (inline) {
    const val = (document.getElementById(`ws-change-rework-inline-${sid}`)?.value || '').trim();
    if (!val) return empty;
    if (val === '__new') {
      const name = (document.getElementById(`ws-change-rework-name-inline-${sid}`)?.value || '').trim().slice(0, 80);
      if (!name) return { error: 'Ponéle un nombre al grupo nuevo.' };
      return { body: { rework_name: name, rework_color: document.getElementById(`ws-change-rework-color-inline-${sid}`)?.value || '' } };
    }
    const blocked = doneGuard(val);
    if (blocked) return blocked;
    return { body: { rework_key: val } };
  }
  const sel = document.getElementById('ws-change-rework');
  const val = (sel?.value || '').trim();
  if (!val) return empty;
  if (val === '__new') {
    const name = (document.getElementById('ws-change-rework-name')?.value || '').trim().slice(0, 80);
    if (!name) return { error: 'Ponéle un nombre al grupo nuevo.' };
    return { body: { rework_name: name, rework_color: document.getElementById('ws-change-rework-color')?.value || '' } };
  }
  const blocked = doneGuard(val);
  if (blocked) return blocked;
  return { body: { rework_key: val } };
}

async function addWsChange(id, opts = {}) {
  const sid = Number(id || wsChangeId || 0);
  if (!sid) return;
  const fieldId = opts.inline ? `ws-change-inline-${sid}` : 'ws-change-text';
  const alertId = opts.inline ? null : 'ws-change-alert';
  const text = (document.getElementById(fieldId)?.value || '').trim();
  if (!text) {
    if (alertId) showAlert(alertId, 'Escribí qué hiciste antes de registrarlo.', 'error');
    else showToast('⚠️ Escribí qué hiciste antes de registrarlo.');
    document.getElementById(fieldId)?.focus();
    return;
  }
  const btn = opts.inline ? null : document.getElementById('ws-change-go');
  if (btn) { btn.disabled = true; btn.textContent = '⏺ Registrando…'; }
  const meta = readWsChangeMeta(sid, !!opts.inline);
  // Aporte al %: en el modal se acota a lo que le queda al proyecto; en la
  // fila inline se acota igual según la sesión.
  let delta = 0;
  if (opts.inline) {
    const s0 = wsCache.find((x) => Number(x.id) === sid);
    const room0 = Math.max(0, 100 - currentProjectPercent(s0 ? s0.project_id : 0));
    delta = readDecField((document.getElementById(`ws-change-delta-inline-${sid}`) || {}).value, room0).value || 0;
  } else {
    delta = readDecField((document.getElementById('ws-change-delta') || {}).value, wsChangeRoom).value || 0;
  }
  // El rework al que pertenece este cambio (si es que se eligió uno). Puede
  // ser uno que ya está en la sesión (por clave) o uno nuevo (por nombre).
  const rework = readWsChangeRework(sid, !!opts.inline);
  if (rework.error) {
    if (alertId) showAlert(alertId, rework.error, 'error');
    else showToast(`⚠️ ${rework.error}`);
    return;
  }
  try {
    const res = await adminFetch(API_BASE + `/ows-work-sessions/${sid}/changes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text, kind: meta.kind, custom_label: meta.custom_label, color: meta.color,
        progress_delta: delta, tz_offset: wsTzOffset(), created_by: getCurrentAdminName(),
        ...rework.body
      })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    // El % se movió al instante: se sincroniza con lo que dice el servidor.
    if (data.development) {
      const i = devProgressCache.findIndex((d) => Number(d.project_id) === Number(data.development.project_id));
      if (i >= 0) devProgressCache[i] = { ...devProgressCache[i], ...data.development };
      else devProgressCache.push(data.development);
      renderDevList();
      renderAdminProjectsList();
    }
    const n = Number(data.session?.changes_count || 0);
    // Si entró en un rework, el toast lo nombra: es el dato que identifica el
    // cambio como parte del trabajo grande (y cuántas partes lleva ya).
    const rw = data.rework || null;
    const rwTxt = rw
      ? ` 🧩 parte de "${rw.name}": ${wsCount(rw.changes_count || 0, 'cambio conectado', 'cambios conectados')}${rw.changes_delta ? ` · ${fmtPct(rw.changes_delta)}` : ''}`
      : '';
    showToast((delta
      ? `⏺ Cambio registrado (+${fmtPct(delta)} aplicado al %)${n ? ` · ${n} en esta sesión` : ''}`
      : `⏺ Cambio registrado${n ? ` (${n} en esta sesión)` : ''} — el cronómetro sigue corriendo`)
      + rwTxt);
    await loadWorkSessions();
    // Refresca lo que esté abierto sin cerrar nada.
    if (!opts.inline && wsChangeId === sid && wsModalStep === 'change') openWsChangeForm(sid);
    if (opts.inline) renderWsStopChanges(sid);
  } catch (err) {
    if (alertId) showAlert(alertId, err.message || 'No se pudo registrar el cambio.', 'error');
    else showToast(`⚠️ ${err.message}`);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '⏺ Registrar cambio'; }
  }
}

// Lista de cambios dentro del modal de detener (se repinta sin cerrar).
function renderWsStopChanges(id) {
  const s = wsCache.find((x) => Number(x.id) === Number(id));
  const box = document.getElementById('ws-stop-changes');
  if (box) box.innerHTML = wsChangesHtml(s ? s.changes : [], { empty: true, session: s || undefined });
  // El selector de rework se repinta también: al registrar un cambio nuevo
  // puede haberse creado un rework que ahora está disponible para el siguiente.
  const sel = document.getElementById(`ws-change-rework-inline-${id}`);
  if (sel && s) {
    const keep = sel.value;
    sel.innerHTML = wsReworkSelectHtml(s);
    // Si el rework elegido sigue existiendo, se deja elegido.
    sel.value = [...sel.options].some((o) => o.value === keep) ? keep : '';
    syncWsChangeReworkInline(Number(id));
  }
  // Cuánto ya aportaron los cambios: lo del cierre se suma encima.
  const hint = document.getElementById('ws-stop-changes-hint');
  if (hint) {
    const got = round2((Array.isArray(s?.changes) ? s.changes : [])
      .reduce((sum, c) => sum + (c?.applied ? (Number(c.delta) || 0) : 0), 0));
    const rwTxt = wsReworksOf(s).length
      ? ` Los grupos de esta sesión (${wsCount(wsReworksOf(s).length, WS_REWORK_1, WS_REWORK_N)}) quedan <b>pausados</b> con la pausa y <b>esperan</b> al cerrar la sesión.`
      : '';
    hint.innerHTML = (got
      ? `Los cambios ya aportaron <b>+${fmtPct(got)}</b> al proyecto. Lo que pongas en “¿Cuánto avanzó?” se suma encima al detener.`
      : 'La hora se pone sola. Queda en la sesión y en el devlog del día.') + rwTxt;
  }
}

// Muestra/oculta los campos de "rework nuevo" en la fila inline del modal de
// detener (el modal grande tiene su propia versión con más detalle).
// El selector vive oculto tras el botón 🧩: solo se muestra para trabajos muy
// grandes, no es lo primordial.
function toggleWsChangeReworkInline(id) {
  const wrap = document.getElementById(`ws-change-rework-wrap-inline-${id}`);
  const sel = document.getElementById(`ws-change-rework-inline-${id}`);
  const btn = document.getElementById(`ws-change-rework-toggle-inline-${id}`);
  if (!wrap) return;
  const show = wrap.classList.contains('hidden');
  wrap.classList.toggle('hidden', !show);
  if (btn) btn.classList.toggle('is-on', show);
  // Al volver a ocultarlo se limpia la elección para no mandar un rework
  // que ya no se ve.
  if (!show && sel) { sel.value = ''; syncWsChangeReworkInline(id); }
}
function syncWsChangeReworkInline(id) {
  const sel = document.getElementById(`ws-change-rework-inline-${id}`);
  const box = document.getElementById(`ws-change-rework-new-inline-${id}`);
  if (!sel || !box) return;
  // Si quedó un rework elegido (p. ej. tras repintar), el bloque se muestra.
  if (sel.value) {
    const wrap = document.getElementById(`ws-change-rework-wrap-inline-${id}`);
    if (wrap) wrap.classList.remove('hidden');
    const btn = document.getElementById(`ws-change-rework-toggle-inline-${id}`);
    if (btn) btn.classList.add('is-on');
  }
  const isNew = sel.value === '__new';
  box.classList.toggle('hidden', !isNew);
  if (isNew) {
    const name = document.getElementById(`ws-change-rework-name-inline-${id}`);
    if (name) name.focus();
  }
}

// Descartar la sesión en vivo sin guardarla (el trabajo no se registra).
async function discardWsRunning() {
  const s = (wsStopId && wsCache.find((x) => Number(x.id) === Number(wsStopId)))
    || wsRunning();
  if (!s) return closeWsModal();
  if (!window.confirm(`¿Descartar la sesión "${s.title}"?\n\nNo se va a registrar nada de este bloque de trabajo.`)) return;
  try {
    const res = await adminFetch(API_BASE + `/ows-work-sessions/${s.id}`, {
      method: 'DELETE', headers: adminHeaders()
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    closeWsModal();
    showToast('🗑️ Sesión descartada');
    loadWorkSessions();
    loadWsDaily();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

function openWsModal() {
  const m = document.getElementById('ws-modal');
  if (m) m.classList.remove('hidden');
  document.addEventListener('keydown', wsModalEsc);
  startWsClock();
}
function closeWsModal() {
  const m = document.getElementById('ws-modal');
  if (m) m.classList.add('hidden');
  document.removeEventListener('keydown', wsModalEsc);
}
function wsModalEsc(e) {
  if (e.key === 'Escape') closeWsModal();
}

async function loadWorkSessions(manual) {
  const box = document.getElementById('ws-timeline');
  if (!box) return;
  if (!(await requireAuth())) return;
  if (!wsDay) wsDay = wsTodayKey();
  syncWsDayInputs();
  try {
    const res = await adminFetch(API_BASE + `/ows-work-sessions?limit=300&tz_offset=${wsTzOffset()}`);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    wsCache = Array.isArray(data.sessions) ? data.sessions : [];
    // El índice de reworks se arma desde las sesiones recién cargadas.
    wsInvalidateReworkIndex();
    // La barra en vivo se reconstruye desde el servidor: si la sesión quedó
    // abierta, vuelve a aparecer aunque se haya recargado la página.
    renderWsLiveBar();
    // El % pudo moverse al cerrar sesiones: la tabla de 14 días lo recoge.
    if (wsCache.some((s) => s.progress_applied)) loadProjectActivity();
    else renderProjectActivity();
    renderWsTimeline();
    // El panel de reworks junta lo de todas las sesiones: si alguna tiene
    // reworks, se piden agrupados (si no, no hace falta ni un request).
    loadWorkReworks();
    if (manual) showToast(`✔ Sesiones actualizadas: ${wsCache.length} en el historial`);
  } catch (err) {
    box.innerHTML = `<p class="loading-note">⚠️ ${escapeHtml(err.message)}</p>`;
  }
}

// ── Panel de reworks (cambios masivos) ─────────────────────────────────
// Los reworks se agrupan por nombre entre TODAS las sesiones: si el rework se
// cortó y se siguió en otra sesión, acá aparece uno solo con las partes de
// cada una. Es el lugar donde se ve "qué reworks hay, cómo van y cuáles
// están pausados esperando a que se retome la sesión".
let wsReworkCache = [];
let wsReworkCounts = { total: 0, active: 0, paused: 0, pending: 0, done: 0 };
let wsReworksShowDone = false;
let wsReworkOpenKey = '';

// Solo se pide la lista si hay algún rework en las sesiones ya cargadas.
async function loadWorkReworks() {
  const box = document.getElementById('ws-reworks');
  if (!box) return;
  const has = (Array.isArray(wsCache) ? wsCache : []).some((s) => wsReworksOf(s).length);
  if (!has) {
    wsReworkCache = [];
    wsReworkCounts = { total: 0, active: 0, paused: 0, pending: 0, done: 0 };
    box.classList.add('hidden');
    box.innerHTML = '';
    return;
  }
  try {
    const res = await adminFetch(API_BASE + `/ows-work-reworks?tz_offset=${wsTzOffset()}`);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    wsReworkCache = Array.isArray(data.reworks) ? data.reworks : [];
    wsReworkCounts = data.counts || wsReworkCounts;
    renderWsReworks();
  } catch (err) {
    box.classList.remove('hidden');
    box.innerHTML = `<p class="loading-note">⚠️ ${escapeHtml(err.message)}</p>`;
  }
}

function renderWsReworks() {
  const box = document.getElementById('ws-reworks');
  if (!box) return;
  const all = Array.isArray(wsReworkCache) ? wsReworkCache : [];
  if (!all.length) { box.classList.add('hidden'); box.innerHTML = ''; return; }
  box.classList.remove('hidden');
  const { active, paused, pending, done } = wsReworkCounts || {};
  const shown = wsReworksShowDone ? all : all.filter((r) => r.state !== 'done');
  // Resumen arriba: es la respuesta rápida a "¿qué está pausado?".
  const pills = [
    active ? `<span class="ws-rw-pill is-active" title="Grupos que se están trabajando ahora">🔄 ${active} en curso</span>` : '',
    paused ? `<span class="ws-rw-pill is-paused" title="Pausados junto con la sesión en vivo: se retoman al continuar la sesión">⏸ ${paused} pausado${paused === 1 ? '' : 's'}</span>` : '',
    pending ? `<span class="ws-rw-pill is-pending" title="La sesión se cerró y el grupo sigue abierto: falta retomarlo en otra sesión">⏳ ${pending} esperando</span>` : '',
    done ? `<span class="ws-rw-pill is-done" title="Grupos ya terminados">✅ ${wsCount(done, 'terminado', 'terminados')}</span>` : ''
  ].filter(Boolean).join('');
  box.innerHTML = `
    <div class="ws-rw-panel-head">
      <span class="ws-rw-panel-icon" aria-hidden="true">🧩</span>
      <div class="ws-rw-panel-titles">
        <b>Grupos de trabajo</b>
        <small>Los cambios que son parte del mismo trabajo grande quedan <b>conectados</b> bajo un solo nombre, con el total de cada uno. Un grupo <b>se pausa junto con la sesión en vivo</b> y se retoma con ella.</small>
      </div>
      <span class="ws-rw-pills">${pills}</span>
      <span class="ws-rw-panel-actions">
        <button type="button" class="btn btn-ghost btn-sm" data-adm-ev="click" data-adm="toggleWsReworksDone" title="Mostrar u ocultar los ya terminados">${wsReworksShowDone ? '🙈 Ocultar terminados' : `👁️ Ver terminados (${done || 0})`}</button>
        <button type="button" class="btn btn-ghost btn-sm" data-adm-ev="click" data-adm="openWsReworkForm" title="Crear un grupo nuevo">＋ Nuevo grupo</button>
      </span>
    </div>
    ${shown.length
      ? `<div class="ws-rw-grid">${shown.map((r) => wsReworkPanelCardHtml(r)).join('')}</div>`
      : `<p class="ws-rw-empty">No hay grupos abiertos. Cuando anotes un cambio y lo colgues de un grupo, aparece acá.</p>`}`;
}

// Una tarjeta por rework: nombre, estado, cuántos cambios lleva, el % que ya
// aportó, en qué sesiones está repartido y el detalle de sus cambios.
function wsReworkPanelCardHtml(r) {
  const color = wsReworkColor(r.color);
  const meta = wsReworkStateMeta(r.state);
  const kind = wsReworkKindMeta(r.kind);
  const major = r.kind === 'major';
  const open = wsReworkOpenKey === r.key;
  const sessionChips = (r.sessions || []).map((sn) => `
    <span class="ws-rw-session${sn.state === r.state ? '' : ` is-${escapeHtml(sn.state)}`}" title="${escapeHtml(sn.session_title)}${sn.local_day ? ` · ${wsShortDay(sn.local_day)}` : ''}">
      🕐 ${escapeHtml(sn.session_title || 'Sesión')}${sn.local_day ? ` · ${wsShortDay(sn.local_day)}` : ''}
      <b>${wsCount(sn.changes_count, 'cambio', 'cambios')}</b>${sn.changes_delta ? ` +${fmtPct(sn.changes_delta)}` : ''}
    </span>`).join('');
  return `
    <article class="ws-rw-card is-${escapeHtml(r.state)}${open ? ' is-open' : ''}${major ? ' is-major' : ''}" style="--rw:${color}">
      <button type="button" class="ws-rw-card-main" data-adm-ev="click" data-adm="toggleWsReworkDetail" data-adm-a0="s:${escapeHtml(r.key)}" title="${open ? 'Ocultar los cambios del grupo' : 'Ver los cambios del grupo'}">
        <span class="ws-rw-card-stripe" aria-hidden="true"></span>
        <span class="ws-rw-card-top">
          <b class="ws-rw-card-name">${escapeHtml(r.name)}</b>
          <span class="ws-rw-kind is-${major ? 'major' : 'rework'}" title="${escapeHtml(kind.title)}">${kind.icon} ${escapeHtml(kind.label)}</span>
          <span class="ws-rw-state is-${escapeHtml(r.state)}" title="${escapeHtml(meta.title)}">${meta.icon} ${escapeHtml(meta.label)}</span>
          ${r.status === 'done' ? '<span class="ws-rw-done-flag">cerrado</span>' : ''}
          <span class="ws-rw-caret" aria-hidden="true">${open ? '▲' : '▼'}</span>
        </span>
        <span class="ws-rw-card-stats">
          <span title="Cambios conectados a este grupo">🧩 ${wsCount(r.changes_count, 'cambio', 'cambios')}</span>
          <span title="Avance ya aplicado al % del proyecto por este grupo">📈 ${r.changes_delta ? `+${fmtPct(r.changes_delta)}` : '0'}</span>
          ${r.sessions_count > 1 ? `<span title="El grupo se repartió en varias sesiones">🕐 ${wsCount(r.sessions_count, 'sesión', 'sesiones')}</span>` : ''}
          ${r.last_at ? `<span title="Último cambio de este grupo">⏱ ${escapeHtml(wsClock(r.last_at))}${r.last_at !== r.first_at ? ` · desde ${escapeHtml(wsClock(r.first_at))}` : ''}</span>` : ''}
        </span>
        ${r.state === 'paused'
          ? `<span class="ws-rw-card-msg">⏸ <b>Pausado con la sesión en vivo.</b> Sus cambios quedan esperando: no se puede seguir con este grupo hasta que se retome la sesión.</span>`
          : r.state === 'pending'
            ? `<span class="ws-rw-card-msg">⏳ La sesión que lo tenía se cerró y el grupo sigue abierto: registrá un cambio en una sesión nueva con este mismo grupo para que vuelva a la cola.</span>`
            : ''}
      </button>
      <span class="ws-rw-card-actions">
        ${r.status === 'done'
          ? `<button class="btn btn-ghost btn-mini" data-adm-ev="click" data-adm="setWsReworkDone" data-adm-a0="s:${escapeHtml(r.key)}" data-adm-a1="b:0" title="Volver a abrirlo">↩️ Reabrir</button>`
          : `<button class="btn btn-ghost btn-mini" data-adm-ev="click" data-adm="setWsReworkDone" data-adm-a0="s:${escapeHtml(r.key)}" data-adm-a1="b:1" title="Marcar el grupo como terminado">✅ Terminado</button>`}
        <button class="btn btn-ghost btn-mini" data-adm-ev="click" data-adm="openWsReworkForm" data-adm-a0="s:${escapeHtml(r.key)}" title="Nombre, tipo, color y nota">✏️</button>
      </span>
      ${open ? `
      <div class="ws-rw-detail">
        ${r.note ? `<p class="ws-rw-detail-note">${escapeHtml(r.note)}</p>` : ''}
        ${sessionChips ? `<div class="ws-rw-sessions"><span class="ws-rw-detail-label">Repartido en</span>${sessionChips}</div>` : ''}
        <ol class="ws-change-list">${wsReworkDetailChangesHtml(r)}</ol>
      </div>` : ''}
    </article>`;
}

// Los cambios del rework, en orden de hora, tomando de todas las sesiones en
// las que aparece. Cada línea dice de qué sesión salió.
function wsReworkDetailChangesHtml(r) {
  const out = [];
  (Array.isArray(wsCache) ? wsCache : []).forEach((s) => {
    (Array.isArray(s.changes) ? s.changes : []).forEach((c) => {
      if (c.rework_key === r.key) out.push({ c, s });
    });
  });
  if (!out.length) return '<p class="ws-change-empty">Este grupo todavía no tiene cambios conectados.</p>';
  out.sort((a, b) => String(a.c.at).localeCompare(String(b.c.at)));
  return out.map((x, i) => `
    <li class="ws-change-item is-rw">
      <span class="ws-change-dot" style="background:${wsChangeColor(x.c.color, x.c.kind)};box-shadow:0 0 0 3px ${wsChangeColor(x.c.color, x.c.kind)}29" aria-hidden="true"></span>
      <div class="ws-change-body" style="border-left-color:${wsReworkColor(r.color)}">
        <div class="ws-change-head">
          <span class="ws-change-time">⏺ ${escapeHtml(wsClock(x.c.at))} · cambio #${i + 1}</span>
          <span class="ws-change-ago">${escapeHtml(x.s.project_name ? `🎯 ${x.s.project_name}` : '🌐 Sin proyecto')}</span>
        </div>
        <div class="ws-change-tags">
          <span class="ws-change-kind" style="color:${wsChangeColor(x.c.color, x.c.kind)};border-color:${wsChangeColor(x.c.color, x.c.kind)}88;background:${wsChangeColor(x.c.color, x.c.kind)}22">${escapeHtml(wsChangeKindLabel(x.c))}</span>
          ${x.c.applied && Number(x.c.delta) ? `<span class="ws-change-delta">+${fmtPct(round2(x.c.delta))} aplicado</span>` : ''}
          <span class="ws-change-where" title="De qué sesión salió este cambio">🕐 ${escapeHtml(x.s.title || 'Sesión')}</span>
        </div>
        <p class="ws-change-text">${escapeHtml(x.c.text || '')}</p>
        <span class="ws-change-by">👤 ${escapeHtml(x.c.author || '—')}</span>
      </div>
    </li>`).join('');
}

function toggleWsReworkDetail(key) {
  wsReworkOpenKey = wsReworkOpenKey === key ? '' : key;
  renderWsReworks();
}
function toggleWsReworksDone() {
  wsReworksShowDone = !wsReworksShowDone;
  renderWsReworks();
}

// ── Crear / editar un rework ───────────────────────────────────────────
// El rework vive en una sesión: la primera que tenga un cambio de él. Si el
// trabajo se corta y se sigue más adelante, el mismo nombre lo trae de vuelta
// a la sesión nueva, así sigue siendo UN solo rework.
let wsReworkFormKey = '';
let wsReworkFormSession = 0;
// Si el rework se abrió desde el modal de cambios, al cerrar vuelve a ese
// modal para poder seguir anotando cambios sin tener que reabrir.
let wsReworkFromChange = false;

function wsModalIsOpen() {
  const m = document.getElementById('ws-modal');
  return !!m && !m.classList.contains('hidden');
}

function wsReworkFormTargetSession() {
  const running = wsRunningList();
  // La última sesión usada solo sirve si sigue EN VIVO: si se cerró, o quedó
  // pausada mientras había otra corriendo, un grupo nuevo no se le cuelga.
  if (wsReworkFormSession && running.some((x) => Number(x.id) === Number(wsReworkFormSession))) {
    const s = wsCache.find((x) => Number(x.id) === Number(wsReworkFormSession));
    if (s) return s;
  }
  // Sin contexto (panel "＋ Nuevo grupo"): la sesión en vivo más reciente,
  // nunca "la primera que encuentre" (con dos en vivo eso elegía siempre
  // la más vieja y el grupo terminaba en el proyecto equivocado).
  if (running.length) return running[running.length - 1];
  return wsCache.find((s) => s.status !== 'done') || null;
}

function openWsReworkForm(key, sessionId) {
  // Editar: se busca el grupo en todas las sesiones (puede estar en otra) y
  // se edita en la sesión abierta donde esté, así vale para el panel.
  const rw = key ? wsReworkIndexAll().get(key) : null;
  const whereRw = rw
    ? (wsCache.find((x) => x.status !== 'done' && wsReworksOf(x).some((r) => r.key === rw.key))
      || wsCache.find((x) => wsReworksOf(x).some((r) => r.key === rw.key)) || null)
    : null;
  // El botón 🧩 de cada fila en vivo lleva SU id de sesión: el grupo se cuelga
  // de esa fila concreta, sin adivinar cuál es "la sesión actual".
  let s = null;
  if (sessionId) {
    s = wsCache.find((x) => Number(x.id) === Number(sessionId)) || null;
    if (s && s.status === 'done') s = null;
  }
  // Si se abrió desde el modal de cambios, el rework se cuelga de LA MISMA
  // sesión del cambio, no de otra que esté abierta. Ojo: el paso del modal
  // sobrevive a cerrarlo, así que hay que mirar que siga abierto y que la
  // sesión siga viva (si no, el grupo se mandaba a otra sesión o a una
  // que ya estaba cerrada).
  const fromChange = !!(wsModalStep === 'change' && wsChangeId && wsModalIsOpen());
  if (!s && fromChange) {
    const c = wsCache.find((x) => Number(x.id) === Number(wsChangeId)) || null;
    if (c && c.status !== 'done') s = c;
  }
  if (!s) s = wsReworkFormTargetSession();
  const where = whereRw || s;
  if (!where) return showToast('⚠️ No hay ninguna sesión abierta: arrancá una en vivo para poder colgarle un grupo.');
  const body = document.getElementById('ws-modal-body');
  if (!body) return;
  wsModalStep = 'rework';
  hideAlert('ws-rework-alert');
  wsReworkFormKey = rw ? rw.key : '';
  wsReworkFormSession = Number(where.id);
  // Solo tiene sentido volver al modal de cambios si el grupo quedó en la
  // misma sesión de ese cambio.
  wsReworkFromChange = fromChange && Number(wsChangeId) === Number(where.id);
  const color = rw ? wsReworkColor(rw.color) : wsNextReworkColor();
  const kind = rw ? (rw.kind === 'major' ? 'major' : 'rework') : 'major';
  body.innerHTML = `
    <div class="devmodal-head">
      <div class="devmodal-icon">🧩</div>
      <div class="devmodal-head-info">
        <h3 class="devmodal-title">${rw ? 'Editar el grupo' : 'Nuevo grupo'}</h3>
        <p class="modal-tagline">${escapeHtml(where.title)} · agrupa los cambios del mismo trabajo grande</p>
      </div>
    </div>
    <div class="wsrt-note">
      🧩 Un grupo <b>conecta</b> los cambios que son parte del mismo trabajo grande: quedan juntos bajo un
      nombre, suman su avance y se distinguen de un vistazo.
      <br>⏸ Si la sesión en vivo se pausa, <b>el grupo se pausa con ella</b> y sus cambios quedan esperando hasta
      que se retome la sesión. No hay que marcar nada a mano.
    </div>
    <div class="field-group">
      <label>¿Qué tipo de trabajo es? *</label>
      <div class="ws-kind-grid ws-rework-kind-grid">
        <label class="ws-kind${kind === 'major' ? ' is-checked' : ''}" data-kind="major" style="--kind:#f59e0b">
          <input type="radio" name="ws-rework-kind" value="major"${kind === 'major' ? ' checked' : ''} data-adm-ev="change" data-adm="syncWsReworkKind" />
          <span><i>🚀</i><b>Trabajo grande</b><small>Nuevo: se destaca por su aporte de %</small></span>
        </label>
        <label class="ws-kind${kind === 'rework' ? ' is-checked' : ''}" data-kind="rework" style="--kind:#34d399">
          <input type="radio" name="ws-rework-kind" value="rework"${kind === 'rework' ? ' checked' : ''} data-adm-ev="change" data-adm="syncWsReworkKind" />
          <span><i>♻️</i><b>Rework</b><small>Revamp o rediseño de algo que ya existe</small></span>
        </label>
      </div>
    </div>
    <div class="field-group">
      <label for="ws-rework-name">Nombre del grupo *</label>
      <input type="text" id="ws-rework-name" maxlength="80" placeholder="Ej: Menú de tiburones, Refactor del inventario…" value="${rw ? escapeHtml(rw.name) : ''}" data-adm-ev="input" data-adm="syncWsReworkPreview" autocomplete="off" />
      <p class="form-hint">Es la forma en que se va a identificar el trabajo. Con el mismo nombre se reconoce aunque el trabajo se corte y se siga en otra sesión.</p>
    </div>
    <div class="field-group">
      <label for="ws-rework-color">Color del grupo</label>
      <div class="ws-color-row">
        <input type="color" id="ws-rework-color" value="${color}" data-adm-ev="input" data-adm="syncWsReworkPreview" title="Elegí el color" />
        <span id="ws-rework-preview" class="ws-rw-chip" style="color:${color};border-color:${color}99;background:${color}22">🚀 ${escapeHtml(rw ? rw.name : 'Nuevo grupo')}</span>
      </div>
    </div>
    <div class="field-group">
      <label for="ws-rework-note">Nota <small>(opcional)</small></label>
      <input type="text" id="ws-rework-note" maxlength="300" placeholder="Qué falta, qué sigue…" value="${rw ? escapeHtml(rw.note || '') : ''}" autocomplete="off" />
    </div>
    ${rw ? `<div class="wsrt-summary">
      <div class="wsrt-sum-row"><span>Estado</span><b>${wsReworkStateMeta(rw.state).icon} ${escapeHtml(wsReworkStateMeta(rw.state).label)}</b></div>
      <div class="wsrt-sum-row"><span>Cambios conectados</span><b>${wsCount(rw.changes_count || 0, 'cambio', 'cambios')}</b></div>
      <div class="wsrt-sum-row"><span>Aportó al proyecto</span><b>${rw.changes_delta ? `+${fmtPct(rw.changes_delta)}` : '0'}</b></div>
      <div class="wsrt-sum-row"><span>Creado por</span><b>${escapeHtml(rw.created_by || '—')}</b></div>
    </div>
    <p class="form-hint">El estado <b>pausado</b> no se edita: sale de la sesión. Si marcás el grupo como terminado, deja de pedir más cambios.</p>` : ''}
    <div id="ws-rework-alert" class="alert-box hidden"></div>
    <div class="ws-step-actions">
      ${rw ? `<button type="button" class="btn btn-danger" data-adm-ev="click" data-adm="deleteWsRework" data-adm-a0="s:${escapeHtml(rw.key)}">🗑️ Deshacer grupo</button>` : ''}
      <button type="button" class="btn btn-ghost" data-adm-ev="click" data-adm="closeWsModal">Cancelar</button>
      <button type="button" class="btn ws-start-btn" id="ws-rework-go" data-adm-ev="click" data-adm="saveWsRework">🧩 ${rw ? 'Guardar' : 'Crear grupo'}</button>
    </div>`;
  openWsModal();
  syncWsReworkPreview();
  const first = document.getElementById('ws-rework-name');
  if (first && !rw) setTimeout(() => first.focus(), 40);
}

function syncWsReworkPreview() {
  const prev = document.getElementById('ws-rework-preview');
  const nameEl = document.getElementById('ws-rework-name');
  const colorEl = document.getElementById('ws-rework-color');
  if (!prev) return;
  const color = wsReworkColor(colorEl ? colorEl.value : '');
  const kind = document.querySelector('input[name="ws-rework-kind"]:checked')?.value;
  const name = (nameEl ? nameEl.value : '').trim().slice(0, 80) || 'Nuevo grupo';
  prev.textContent = `${wsReworkKindMeta(kind).icon} ${name}`;
  prev.style.color = color;
  prev.style.borderColor = `${color}99`;
  prev.style.background = `${color}22`;
}

// Marca la tarjeta de tipo elegida (trabajo grande o rework).
function syncWsReworkKind() {
  document.querySelectorAll('.ws-rework-kind-grid .ws-kind').forEach((el) => {
    const input = el.querySelector('input[name="ws-rework-kind"]');
    el.classList.toggle('is-checked', !!(input && input.checked));
  });
  syncWsReworkPreview();
}

async function saveWsRework() {
  const btn = document.getElementById('ws-rework-go');
  const name = (document.getElementById('ws-rework-name')?.value || '').trim().slice(0, 80);
  if (!name) {
    showAlert('ws-rework-alert', 'Ponéle un nombre al grupo.', 'error');
    return document.getElementById('ws-rework-name')?.focus();
  }
  const sid = wsReworkFormSession;
  if (!sid) return showAlert('ws-rework-alert', 'No hay ninguna sesión abierta para colgarle el grupo.', 'error');
  const color = document.getElementById('ws-rework-color')?.value || '';
  const kind = document.querySelector('input[name="ws-rework-kind"]:checked')?.value === 'rework' ? 'rework' : 'major';
  const note = (document.getElementById('ws-rework-note')?.value || '').trim().slice(0, 300);
  const editando = !!wsReworkFormKey;
  if (btn) { btn.disabled = true; btn.textContent = '🧩 Guardando…'; }
  try {
    // Si el nombre ya existe en otra sesión, se trae a esta: el servidor
    // reutiliza el mismo rework en vez de crear uno nuevo por error.
    const key = editando ? wsReworkFormKey : (wsReworkKey(name) || '');
    const twin = editando ? null : wsReworkIndexAll().get(key);
    const res = await adminFetch(API_BASE + `/ows-work-sessions/${sid}/reworks`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        key, name, color, kind, note, tz_offset: wsTzOffset(), created_by: getCurrentAdminName()
      })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    closeWsModal();
    await loadWorkSessions();
    const kindLabel = kind === 'major' ? '🚀 Trabajo grande' : '♻️ Rework';
    showToast(twin
      ? `🧩 El grupo "${name}" ya existía en otra sesión: ahora queda también en esta.`
      : `🧩 ${editando ? 'Grupo guardado' : `${kindLabel} creado`}: "${name}"${data.rework && data.rework.changes_count ? ` · ${wsCount(data.rework.changes_count, 'cambio conectado', 'cambios conectados')}` : ' · ya podés colgarle cambios'}`);
    // Si se venía desde el modal de cambios, se vuelve a ese modal para poder
    // seguir anotando cambios sin tener que reabrir.
    if (wsReworkFromChange && wsChangeId) {
      wsReworkFromChange = false;
      openWsChangeForm(wsChangeId);
    }
  } catch (err) {
    showAlert('ws-rework-alert', err.message || 'No se pudo guardar el grupo.', 'error');
    if (btn) { btn.disabled = false; btn.textContent = '🧩 Guardar'; }
  }
}

// Marcar el rework como terminado (o reabrirlo). Se hace sobre la sesión en
// la que vive; si está en varias, alcanza con una.
async function setWsReworkDone(key, done) {
  const rw = wsReworkIndexAll().get(key);
  if (!rw) return showToast('⚠️ Ese grupo ya no existe.');
  if (!done && !window.confirm(`¿Reabrir el grupo "${rw.name}"?\n\nVuelve a quedar esperando más cambios.`)) return;
  // El mismo rework puede estar en varias sesiones (si el trabajo se cortó y
  // se siguió en otra): se marca en TODAS, así no queda a medias en ninguna.
  const hosts = (Array.isArray(wsCache) ? wsCache : [])
    .filter((s) => wsReworksOf(s).some((r) => r.key === key));
  if (!hosts.length) return showToast('⚠️ No se encontró la sesión del grupo.');
  try {
    for (const host of hosts) {
      // eslint-disable-next-line no-await-in-loop
      const res = await adminFetch(API_BASE + `/ows-work-sessions/${host.id}/reworks/${encodeURIComponent(key)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          status: done ? 'done' : 'open',
          tz_offset: wsTzOffset(),
          created_by: getCurrentAdminName()
        })
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    }
    await loadWorkSessions();
    showToast(done
      ? `✅ Grupo terminado: "${rw.name}" (${wsCount(rw.changes_count || 0, 'cambio', 'cambios')} queda${(rw.changes_count || 0) === 1 ? '' : 'n'} guardado${(rw.changes_count || 0) === 1 ? '' : 's'} como historia del grupo)`
      : `↩️ Grupo reabierto: "${rw.name}" vuelve a esperar cambios.`);
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

// Deshacer un rework: los cambios NO se pierden, quedan sueltos.
async function deleteWsRework(key) {
  const rw = wsReworkIndexAll().get(key);
  if (!rw) return showToast('⚠️ Ese grupo ya no existe.');
  const n = rw.changes_count || 0;
  if (!window.confirm(`¿Deshacer el grupo "${rw.name}"?\n\nLos ${n} cambios NO se borran: quedan como cambios sueltos.`)) return;
  const hosts = (Array.isArray(wsCache) ? wsCache : [])
    .filter((s) => wsReworksOf(s).some((r) => r.key === key));
  if (!hosts.length) return showToast('⚠️ No se encontró la sesión del grupo.');
  try {
    for (const host of hosts) {
      // eslint-disable-next-line no-await-in-loop
      const res = await adminFetch(API_BASE + `/ows-work-sessions/${host.id}/reworks/${encodeURIComponent(key)}?tz_offset=${wsTzOffset()}`, {
        method: 'DELETE', headers: adminHeaders()
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    }
    closeWsModal();
    await loadWorkSessions();
    showToast(`🧩 Grupo deshecho: ${wsCount(n, 'cambio quedó', 'cambios quedaron')} sueltos.`);
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

// ── Pausas del formulario manual ──
// En vez de pedir N tramos, se piden las PAUSAS (desde/hasta + motivo): es lo
// que el admin tiene en la cabeza ("corté de 12:55 a 15:00") y lo que después
// se convierte en los tramos que guarda el servidor.
// Estado en memoria mientras el formulario está abierto.
let wsBreaks = [];

// Las pausas se guardan como 'YYYY-MM-DDTHH:MM' local (lo que da el input);
// ISO → 'YYYY-MM-DDTHH:MM' local para pintarlas.
function wsIsoToBreakInput(iso) {
  return iso ? wsToLocalInput(iso) : '';
}

// Agrega una pausa. Si ya hay alguna sin completar, se ordena sola.
function addWsBreak(from, to, reason) {
  const s = wsToLocalInput(from || new Date());
  wsBreaks.push({ from, to, reason: reason || '' });
  if (!from && !to) {
    // Nueva pausa: se propone cortar en el medio del rato ya escrito.
    const endRaw = (document.getElementById('ws-end') || {}).value;
    const startRaw = (document.getElementById('ws-start') || {}).value;
    if (startRaw && endRaw) {
      const a = new Date(startRaw).getTime();
      const b = new Date(endRaw).getTime();
      if (b > a) {
        const mid = new Date(a + Math.round((b - a) / 2));
        wsBreaks[wsBreaks.length - 1].from = wsToLocalInput(mid);
        wsBreaks[wsBreaks.length - 1].to = wsToLocalInput(new Date(mid.getTime() + 30 * 60000));
      }
    }
  }
  renderWsBreaks();
}

function removeWsBreak(i) {
  wsBreaks.splice(i, 1);
  renderWsBreaks();
}

function onWsBreakChange(i, field, value) {
  if (!wsBreaks[i]) return;
  wsBreaks[i][field] = value;
  if (field === 'reason') return;
  // Si el "hasta" quedó antes o junto al "desde", la pausa no serviría: se
  // estira 30 min para que sea válida en vez de romper el guardado.
  const b = wsBreaks[i];
  if (b.from && b.to && new Date(b.to) <= new Date(b.from)) {
    b.to = wsToLocalInput(new Date(new Date(b.from).getTime() + 30 * 60000));
    renderWsBreaks();
  }
}

function renderWsBreaks() {
  const box = document.getElementById('ws-breaks');
  if (!box) return;
  if (!wsBreaks.length) {
    box.innerHTML = '<p class="ws-breaks-empty">Sin pausas: la sesión es un solo bloque corrido.</p>';
    return;
  }
  box.innerHTML = wsBreaks.map((b, i) => `
    <div class="ws-break" data-ws-break="${i}">
      <span class="ws-break-icon" title="Pausa: el trabajo se cortó acá">⏸</span>
      <div class="ws-break-times">
        <input type="datetime-local" value="${wsIsoToBreakInput(b.from)}"
          data-adm-ev="change" data-adm="onWsBreakChange" data-adm-a0="r:${i}" data-adm-a1="s:from" data-adm-a2="thp:value" title="Se cortó a esta hora" />
        <span class="ws-break-arrow">→</span>
        <input type="datetime-local" value="${wsIsoToBreakInput(b.to)}"
          data-adm-ev="change" data-adm="onWsBreakChange" data-adm-a0="r:${i}" data-adm-a1="s:to" data-adm-a2="thp:value" title="Se continuó a esta hora" />
      </div>
      <input type="text" class="ws-break-reason" maxlength="300" value="${escapeHtml(b.reason || '')}"
        placeholder="¿Por qué se cortó?" data-adm-ev="input" data-adm="onWsBreakChange" data-adm-a0="r:${i}" data-adm-a1="s:reason" data-adm-a2="thp:value" />
      <button type="button" class="btn btn-danger btn-mini" data-adm-ev="click" data-adm="removeWsBreak" data-adm-a0="r:${i}" title="Quitar esta pausa">🗑️</button>
    </div>`).join('');
}

// Lee las pausas y las pasa a TRAMOS (lo que guarda el servidor): el rato
//[start, pausa1.desde], la pausa, el rato [pausa1.hasta, pausa2.desde], …
// El último tramo llega hasta el final. Devuelve { parts } o { error }.
function readWsParts(startIso, endIso) {
  const start = new Date(startIso);
  if (!endIso) {
    // Sin hora de fin la sesión sigue abierta: un solo tramo abierto.
    return { parts: [{ from: start.toISOString(), to: null, reason: '' }] };
  }
  const end = new Date(endIso);
  if (Number.isNaN(end.getTime())) return { error: 'La hora de fin no es válida.' };
  if (end.getTime() < start.getTime()) return { error: 'La sesión no puede terminar antes de empezar.' };
  // Pausas ordenadas y recortadas a lo que está dentro de la sesión.
  const gaps = wsBreaks
    .map((b) => ({ from: new Date(b.from), to: new Date(b.to), reason: String(b.reason || '').trim().slice(0, 300) }))
    .filter((g) => !Number.isNaN(g.from.getTime()) && !Number.isNaN(g.to.getTime()) && g.to > g.from)
    .sort((a, b) => a.from - b.from);
  const inside = [];
  gaps.forEach((g) => {
    const from = new Date(Math.max(g.from.getTime(), start.getTime()));
    const to = new Date(Math.min(g.to.getTime(), end.getTime()));
    if (to > from) inside.push({ from, to, reason: g.reason });
  });
  if (gaps.length && inside.length !== gaps.length) {
    return { error: 'Alguna pausa queda fuera de la sesión (después de empezar o antes de terminar).' };
  }
  if (!inside.length) {
    return { parts: [{ from: start.toISOString(), to: end.toISOString(), reason: '' }] };
  }
  // Un tramo por cada hueco entre pausas. El motivo de cada pausa va en el
  // tramo que la TERMINA (el que quedó interrumpido), que es de donde el
  // servidor lee el motivo de cada corte.
  const parts = [];
  let cursor = start;
  inside.forEach((g) => {
    if (g.from > cursor) parts.push({ from: cursor.toISOString(), to: g.from.toISOString(), reason: g.reason });
    cursor = g.to;
  });
  parts.push({ from: cursor.toISOString(), to: end.toISOString(), reason: '' });
  return { parts: parts.filter((p) => new Date(p.to) > new Date(p.from)) };
}

// ── Formulario ──
// 'YYYY-MM-DDTHH:MM' en hora local: es lo que espera <input type="datetime-local">.
// Si el valor guardado no se puede leer, se cae a la hora actual: en un
// formulario es más útil una hora aproximada que un campo en blanco.
function wsToLocalInput(iso) {
  const d = iso ? new Date(iso) : new Date();
  const use = Number.isNaN(d.getTime()) ? new Date() : d;
  const p = (n) => String(n).padStart(2, '0');
  return `${use.getFullYear()}-${p(use.getMonth() + 1)}-${p(use.getDate())}T${p(use.getHours())}:${p(use.getMinutes())}`;
}

function openWsForm(id, mode) {
  const form = document.getElementById('ws-form');
  if (!form) return;
  wsEditingId = id ? Number(id) : null;
  const s = id ? wsCache.find((x) => Number(x.id) === wsEditingId) : null;
  const now = new Date();
  const pid = s ? (s.project_id ?? '') : '';
  const projSel = document.getElementById('ws-project');
  if (projSel) {
    projSel.innerHTML = devlogProjectOptions(pid);
    projSel.value = pid == null ? '' : String(pid);
  }
  const set = (elId, v) => { const el = document.getElementById(elId); if (el) el.value = v; };
  set('ws-title', s ? s.title : '');
  set('ws-details', s ? s.details : '');
  // Al crear: empieza ahora y sigue abierta. Al editar: lo que ya había.
  set('ws-start', wsToLocalInput(s ? s.started_at : now));
  set('ws-end', s ? (s.ended_at ? wsToLocalInput(s.ended_at) : '') : '');
  // Las pausas: si la sesión ya fue interrumpida, se cargan las que tuvo para
  // que se puedan corregir o quitar.
  wsBreaks = (s && Array.isArray(s.interrupts) ? s.interrupts : []).map((c) => ({
    from: wsIsoToBreakInput(c.at),
    to: wsIsoToBreakInput(c.resumed_at),
    reason: String(c.reason || '')
  }));
  renderWsBreaks();
  const room = s ? Math.max(0, 100 - currentProjectPercent(pid)) : 100;
  const delta = s ? round2(s.progress_delta) : 0;
  const range = document.getElementById('ws-delta-range');
  if (range) { range.max = String(room); range.value = String(Math.min(delta, room)); }
  set('ws-delta-num', String(round2(Math.min(delta, room))));
  onWsProjectChange();
  // La sección de "incompleta" también se puede corregir después: el campo
  // se arma con lo que ya tenía la sesión.
  const compField = document.getElementById('ws-comp-field');
  if (compField) compField.innerHTML = wsCompletionHtml('ws', s);
  hideAlert('ws-alert');
  const title = document.getElementById('ws-form-title');
  if (title) title.textContent = s ? 'Editar sesión' : 'Nueva sesión de trabajo';
  const tag = document.getElementById('ws-form-tag');
  if (tag) {
    const kind = wsKindOf(s);
    const paused = kind === 'paused' || (s && s.status === 'paused');
    const open = !s || s.status === 'active';
    tag.textContent = paused ? 'pausada' : (open ? 'en curso' : 'cerrada');
    tag.className = `opt-tag ${paused ? 'ws-tag-paused' : (open ? 'ws-tag-open' : 'ws-tag-done')}`;
  }
  form.classList.remove('hidden');
  const first = document.getElementById('ws-title');
  if (first) setTimeout(() => first.focus(), 40);
  if (mode === 'active' && !s) form.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// % actual de un proyecto (sirve para acotar cuánto puede avanzar la sesión).
function currentProjectPercent(projectId) {
  const pid = Number(projectId || 0);
  if (!pid) return 0;
  const d = devProgressCache.find((x) => Number(x.project_id) === pid);
  return d ? round2(d.percent) : 0;
}

// Al cambiar de proyecto, el avance de la sesión no puede pasar del % que
// le queda disponible: el rango se ajusta al tope real.
function onWsProjectChange() {
  const sel = document.getElementById('ws-project');
  const room = Math.max(0, 100 - currentProjectPercent(sel ? sel.value : ''));
  const range = document.getElementById('ws-delta-range');
  if (range) range.max = String(room);
  const hint = document.getElementById('ws-delta-hint');
  if (hint) {
    hint.innerHTML = sel && sel.value
      ? `Queda <b>${fmtPct(currentProjectPercent(sel.value))}</b> de este proyecto, así que la sesión puede mover hasta <b>${fmtPct(room)}</b>. Se aplica al <b>cierre</b> de la sesión, no al abrirla.`
      : 'Se aplica al <b>cierre</b> de la sesión, no al abrirla. Si es 0, la sesión solo queda registrada.';
  }
  syncWsDelta();
}

function syncWsDelta(fromNum) {
  const range = document.getElementById('ws-delta-range');
  const num = document.getElementById('ws-delta-num');
  if (!range || !num) return;
  const max = Number(range.max || 100);
  // Mismo criterio que el resto del panel: se normaliza siempre el texto y el
  // valor, así escribir 999 con tope 58 se recorta solo mientras se teclea.
  const { text, value } = fromNum
    ? readDecField(num.value, max)
    : readDecField(range.value, max);
  if (num.value !== text) num.value = text;
  range.value = String(value);
}

async function saveWsSession() {
  if (!(await requireAuth())) return;
  const titleEl = document.getElementById('ws-title');
  const title = titleEl ? titleEl.value.trim() : '';
  if (!title) return showAlert('ws-alert', 'Escribí qué hiciste en la sesión.', 'error');
  const projSel = document.getElementById('ws-project');
  const pid = projSel && projSel.value ? Number(projSel.value) : null;
  const startRaw = (document.getElementById('ws-start') || {}).value;
  const endRaw = (document.getElementById('ws-end') || {}).value;
  if (!startRaw) return showAlert('ws-alert', 'Indicá cuándo empezó la sesión.', 'error');
  const start = new Date(startRaw);
  if (Number.isNaN(start.getTime())) return showAlert('ws-alert', 'La hora de inicio no es válida.', 'error');
  const end = endRaw ? new Date(endRaw) : null;
  if (end && Number.isNaN(end.getTime())) return showAlert('ws-alert', 'La hora de fin no es válida.', 'error');
  if (end && end.getTime() < start.getTime()) {
    return showAlert('ws-alert', 'La sesión no puede terminar antes de empezar.', 'error');
  }
  const delta = (readDecField((document.getElementById('ws-delta-num') || {}).value, 100).value) || 0;
  const comp = readWsCompletion('ws');
  if (comp.completion !== 'complete' && !comp.incomplete_reason) {
    const msg = comp.completion === 'paused'
      ? 'Marcá por qué la interrumpiste: elegí un motivo o escribí uno.'
      : 'Marcá por qué quedó incompleta: elegí un motivo o escribí uno.';
    return showAlert('ws-alert', msg, 'error');
  }
  // Las pausas escritas se convierten en los tramos que se guardan.
  const built = readWsParts(start.toISOString(), end ? end.toISOString() : '');
  if (built.error) return showAlert('ws-alert', built.error, 'error');
  if (built.parts.length > 1 && !end) {
    return showAlert('ws-alert', 'Para anotar pausas necesitás la hora de fin de la sesión.', 'error');
  }
  // Sin hora de fin la sesión queda abierta: es el "minidevlog del momento".
  const status = comp.completion === 'paused' ? 'paused' : (end ? 'done' : 'active');
  const body = {
    project_id: pid,
    title,
    details: (document.getElementById('ws-details') || {}).value || '',
    parts: built.parts,
    started_at: start.toISOString(),
    ended_at: end ? end.toISOString() : null,
    status,
    progress_delta: delta,
    completion: comp.completion,
    incomplete_reason: comp.incomplete_reason,
    tz_offset: wsTzOffset(),
    created_by: getCurrentAdminName()
  };
  const btn = document.getElementById('ws-save');
  if (btn) { btn.disabled = true; btn.textContent = '💾 Guardando…'; }
  try {
    const res = await adminFetch(API_BASE + (wsEditingId ? `/ows-work-sessions/${wsEditingId}` : '/ows-work-sessions'), {
      method: wsEditingId ? 'PATCH' : 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    closeWsForm();
    // El % pudo cambiar: se sincroniza el % real con lo que dice el servidor.
    if (data.development) {
      const i = devProgressCache.findIndex((d) => Number(d.project_id) === Number(data.development.project_id));
      if (i >= 0) devProgressCache[i] = { ...devProgressCache[i], ...data.development };
      else devProgressCache.push(data.development);
      renderDevList();
      renderAdminProjectsList();
    }
    // Si la sesión cruzó la medianoche, el día visible deja de ser el último.
    const s = data.session;
    const cuts = s && Array.isArray(s.interrupts) ? s.interrupts : [];
    if (s && s.crosses_midnight && s.local_day && s.end_local_day) {
      setWsDayKey(s.end_local_day);
      const cut = cuts[0];
      showToast(`🌙 Sesión de ${wsMinutes(s.duration_minutes)}${cuts.length ? ` en ${wsCount(s.parts_count, 'tramo', 'tramos')}` : ''}: empezó el ${wsShortDay(s.local_day)} y terminó el ${wsShortDay(s.end_local_day)} — se repartió entre los dos días.${cut ? ` Se interrumpió a las ${wsClock(cut.at)} y se continuó a las ${wsClock(cut.resumed_at)}.` : ''}`);
    } else {
      const day = s ? (wsTouchesDay(s, wsActiveDay()) ? wsActiveDay() : s.local_day) : wsActiveDay();
      if (day) setWsDayKey(day);
      if (status === 'paused') {
        // Los reworks abiertos se van con la sesión: nombra cuáles son para que
        // quede claro que ese cambio masivo también está en pausa.
        const openRw = wsReworksSorted(s || {}).filter((r) => r.status !== 'done');
        showToast(`⏸ Sesión pausada: ${wsMinutes(s ? s.duration_minutes : 0)} de trabajo${cuts.length ? ` en ${wsCount(s.parts_count, 'tramo', 'tramos')}` : ''}. `
          + `Queda esperando: cuando quieras seguir, tocá "▶ Continuar ahora".`
          + (openRw.length
            ? ` 🧩 ${wsCount(openRw.length, 'grupo pausado también', 'grupos pausados también')}: ${openRw.map((r) => r.name).join(', ')}.`
            : ''));
      } else if (status === 'active') {
        showToast('🟢 Sesión abierta');
      } else if (cuts.length && s && s.outcome === 'resumed_done') {
        showToast(`✅ Guardada: se interrumpió a las ${wsClock(cuts[0].at)}${cuts[0].reason ? ` (${cuts[0].reason})` : ''}, `
          + `se continuó a las ${wsClock(cuts[0].resumed_at)} y se finalizó con éxito · ${wsMinutes(s.duration_minutes)} en ${wsCount(s.parts_count, 'tramo', 'tramos')}`);
      } else if (cuts.length) {
        showToast(`✅ Guardada: ${wsCount(s.parts_count, 'tramo trabajado', 'tramos trabajados')} · ${wsMinutes(s.duration_minutes)}${s.paused_minutes ? ` · ${wsMinutes(s.paused_minutes)} en pausa` : ''}`);
      } else {
        showToast('✅ Sesión guardada');
      }
    }
    startWsClock();
  } catch (err) {
    showAlert('ws-alert', err.message || 'No se pudo guardar la sesión.', 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '💾 Guardar sesión'; }
  }
}

function closeWsForm() {
  wsEditingId = null;
  wsBreaks = [];
  const form = document.getElementById('ws-form');
  if (form) form.classList.add('hidden');
  const box = document.getElementById('ws-breaks');
  if (box) box.innerHTML = '';
  hideAlert('ws-alert');
}

async function closeWorkSession(id) {
  if (!(await requireAuth())) return;
  const s = wsCache.find((x) => Number(x.id) === Number(id));
  if (!s) return;
  const now = new Date();
  const delta = round2(s.progress_delta || 0);
  const changesDelta = round2(s.changes_delta || 0);
  const name = s.title || 'la sesión';
  // Confirmación con el % que se va a sumar al proyecto (los cambios ya
  // aportaron lo suyo al registrarlos).
  const extra = changesDelta ? ` Los cambios ya aportaron +${fmtPct(changesDelta)}.` : '';
  if (delta && !window.confirm(
    `¿Cerrar "${name}"?\n\nSe sumará ${fmtDelta(delta)} al porcentaje del proyecto.${extra}`
  )) return;
  try {
    const res = await adminFetch(API_BASE + `/ows-work-sessions/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        status: 'done',
        ended_at: now.toISOString(),
        tz_offset: wsTzOffset(),
        created_by: getCurrentAdminName()
      })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    if (data.development) {
      const i = devProgressCache.findIndex((d) => Number(d.project_id) === Number(data.development.project_id));
      if (i >= 0) devProgressCache[i] = { ...devProgressCache[i], ...data.development };
      else devProgressCache.push(data.development);
      renderDevList();
      renderAdminProjectsList();
    }
    const ss = data.session;
    if (ss && ss.crosses_midnight && wsActiveDay() !== ss.end_local_day) {
      setWsDayKey(ss.end_local_day);
      showToast(`🌙 Cerrada cruzando la medianoche: el trabajo se repartió entre el ${wsShortDay(ss.local_day)} y el ${wsShortDay(ss.end_local_day)}.`);
    } else if (ss && ss.interrupt_count && ss.outcome === 'resumed_done') {
      const cut = ss.interrupts[0];
      setWsDayKey(wsTouchesDay(ss, wsActiveDay()) ? wsActiveDay() : ss.local_day);
      showToast(`✅ Se interrumpió a las ${wsClock(cut.at)}${cut.reason ? ` (${cut.reason})` : ''}, `
        + `se continuó a las ${wsClock(cut.resumed_at)} y se finalizó con éxito · ${wsMinutes(ss.duration_minutes)}`
        + (delta ? ` · ${fmtDelta(delta)} sumados al %` : ''));
    } else {
      showToast(delta ? `✅ Sesión cerrada · ${fmtDelta(delta)} sumados al %` : '✅ Sesión cerrada');
    }
    loadWorkSessions();
    loadWsDaily();
    startWsClock();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

async function deleteWorkSession(id) {
  if (!(await requireAuth())) return;
  const s = wsCache.find((x) => Number(x.id) === Number(id));
  if (!s) return;
  const warn = s.progress_applied
    ? `\n\nOjo: sus ${fmtDelta(s.progress_delta)} ya están en el % del proyecto. Si los querés sacar, ajustá el % desde Gestión.`
    : '';
  if (!window.confirm(`¿Borrar la sesión "${s.title}"?${warn}`)) return;
  try {
    const res = await adminFetch(API_BASE + `/ows-work-sessions/${id}`, { method: 'DELETE', headers: adminHeaders() });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    showToast('🗑️ Sesión borrada');
    loadWorkSessions();
    loadWsDaily();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

// ── Reloj en vivo ──
// Muestra la hora actual, mantiene el cronómetro de la sesión en vivo y, si
// está abierto el modal de detener, el tiempo y la hora de fin proyectada.
// Se refresca cada segundo y no hace nada si la sub-sección no está a la vista.
// Cada 60s, si hay una sesión en vivo, se releen del servidor sus tramos:
// así los minutos suben solos y, al cruzar la medianoche, la barra avisa.
function startWsClock() {
  if (wsClockTimer) return;
  let ticks = 0;
  wsClockTimer = setInterval(() => {
    const clock = document.getElementById('ws-clock');
    if (!clock) return;
    const pane = document.getElementById('manage-sub-devlog');
    if (pane && pane.classList.contains('hidden')) return;
    const d = new Date();
    clock.textContent = `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`;
    // Barra de la sesión en vivo
    renderWsLiveBar();
    // Contadores de cada sesión abierta de la línea de tiempo
    document.querySelectorAll('[data-ws-elapsed]').forEach((el) => {
      const s = wsCache.find((x) => Number(x.id) === Number(el.getAttribute('data-ws-elapsed')));
      if (s && s.status === 'active') el.textContent = wsStopwatch(wsElapsedSeconds(s));
    });
    // Modal de detener: el tiempo sigue corriendo mientras se decide el %
    // (usa la sesión del modal, no la primera en vivo: puede haber varias).
    const ms = (wsModalStep === 'stop' && wsStopId)
      ? wsCache.find((x) => Number(x.id) === Number(wsStopId))
      : null;
    if (ms && wsModalStep === 'stop') {
      const el = document.getElementById('wsrt-elapsed');
      if (el) el.textContent = wsStopwatch(wsElapsedSeconds(ms));
      const end = document.getElementById('wsrt-end');
      if (end) end.textContent = wsClock(new Date().toISOString());
    }
    // Las sesiones en vivo se releen del servidor una vez por minuto: sus
    // tramos (y el cruce de medianoche) se calculan allá.
    ticks += 1;
    if (wsRunning() && ticks % 60 === 0) loadWorkSessions();
  }, 1000);
}

// ── La historia de una sesión interrumpida ──
// Cuando una sesión se corta y después se retoma, el panel lo dice siempre:
// dónde se interrumpió, a qué hora se continuó y cómo terminó. Es lo que
// convierte "40 min + 90 min sueltos" en "se interrumpió a las 12:55, se
// continuó a las 15:00 y se finalizó con éxito".
//   open: despliega el detalle tramo por tramo (modal) o lo deja plegado (fila).
function wsStoryHtml(s, open) {
  const cuts = Array.isArray(s.interrupts) ? s.interrupts : [];
  const paused = s.status === 'paused';
  // Sin cortes y sin pausa no hay historia que contar.
  if (!cuts.length && !paused) return '';

  // 1 · Los tres hitos, siempre a la vista: dónde se cortó, dónde se volvió y cómo terminó.
  const chips = [];
  cuts.forEach((c) => {
    chips.push(`<span class="ws-story-chip is-pause" title="El trabajo se cortó a las ${wsClock(c.at)}${c.reason ? `: ${escapeHtml(c.reason)}` : ''}">⏸ interrumpida ${wsClock(c.at)}</span>`);
    chips.push(`<span class="ws-story-chip is-resume" title="Se volvió al trabajo a las ${wsClock(c.resumed_at)}">▶ se continuó ${wsClock(c.resumed_at)}</span>`);
  });
  if (paused) {
    chips.push('<span class="ws-story-chip is-wait" title="Queda esperando: se puede retomar cuando quieras">⏳ esperando continuar</span>');
  } else if (s.status === 'active') {
    chips.push('<span class="ws-story-chip is-live" title="El tramo de ahora está corriendo">⏱ trabajando ahora</span>');
  } else if (s.outcome === 'resumed_done') {
    chips.push(`<span class="ws-story-chip is-done" title="Después de la pausa, la sesión se cerró con éxito">✅ se retomó y se finalizó con éxito</span>`);
  } else if (s.completion === 'incomplete') {
    chips.push(`<span class="ws-story-chip is-inc">⚠️ quedó a medias${s.incomplete_reason ? `: ${escapeHtml(s.incomplete_reason)}` : ''}</span>`);
  } else {
    chips.push('<span class="ws-story-chip is-done">✅ se cerró</span>');
  }

  // 2 · El detalle: qué se trabajó, cuánto y qué pasó entre medio.
  const parts = Array.isArray(s.parts) ? s.parts : [];
  const items = [];
  parts.forEach((p, i) => {
    const cut = cuts[i] || null;
    const last = i === parts.length - 1;
    let state;
    if (p.open) state = '⏱ en curso';
    else if (cut) state = `⏸ se interrumpió${cut.reason ? ` — ${cut.reason}` : ''}`;
    else if (last && paused) state = '⏸ quedó pausada acá — se puede retomar cuando quieras';
    else if (last && s.outcome === 'resumed_done') state = '✅ se finalizó con éxito';
    else if (last && s.completion === 'incomplete') state = '⚠️ quedó a medias';
    else state = '✅ terminó';
    items.push(`<li class="ws-story-part${p.resumed ? ' is-resumed' : ''}">
      <span class="ws-story-time">${wsClock(p.from)} → ${p.open ? 'ahora' : wsClock(p.to)}</span>
      <span class="ws-story-dur">${wsMinutes(p.minutes)}</span>
      <span class="ws-story-state">${escapeHtml(state)}</span>
    </li>`);
    if (cut) {
      items.push(`<li class="ws-story-gap">⏸ ${wsMinutes(cut.minutes)} en pausa antes de seguir</li>`);
    }
  });
  // El total: el tiempo de pared no es el tiempo trabajado cuando hubo pausas.
  const totals = [];
  if (parts.length > 1) totals.push(`⏱ <b>${wsMinutes(s.duration_minutes)}</b> trabajados en ${wsCount(parts.length, 'tramo', 'tramos')}`);
  if (s.paused_minutes > 0) totals.push(`⏳ <b>${wsMinutes(s.paused_minutes)}</b> en pausa (${wsMinutes(s.wall_minutes)} en total)`);
  const summary = totals.length
    ? `<p class="ws-story-totals">${totals.join(' · ')}</p>`
    : '';

  const label = parts.length === 1 ? 'Ver el tramo' : `Ver los ${wsCount(parts.length, 'tramo', 'tramos')}`;
  return `<div class="ws-story">
    <div class="ws-story-chips">${chips.join('')}</div>
    <details class="ws-story-more"${open ? ' open' : ''}>
      <summary>${label}</summary>
      <ul class="ws-story-list">${items.join('')}</ul>
      ${summary}
    </details>
  </div>`;
}

// Aviso arriba de la lista: qué está pasando con las sesiones del día.
function wsBannerHtml(day) {
  const list = wsDaySessions(day);
  if (!list.length) return '';
  const open = list.filter((s) => s.status === 'active');
  const cross = list.filter((s) => s.crosses_midnight);
  const fromPrev = list.filter((s) => wsSegmentOf(s, day)?.part === 'end');
  const toNext = list.filter((s) => wsSegmentOf(s, day)?.part === 'start' && s.crosses_midnight);
  const totalMin = list.reduce((sum, s) => sum + wsDayMinutesOf(s, day), 0);
  const parts = [];
  parts.push(`<b>${list.length}</b> ${list.length === 1 ? WS_SESSION_1 : WS_SESSION_N} · <b>${wsMinutes(totalMin)}</b> de trabajo`);
  const live = list.filter((s) => s.status === 'active' && s.realtime);
  if (live.length) parts.push(`⏱ ${live.length} en vivo`);
  const paused = list.filter((s) => s.status === 'paused');
  if (paused.length) parts.push(`⏸ ${paused.length} pausada${paused.length === 1 ? '' : 's'}`);
  const resumed = list.filter((s) => s.interrupt_count > 0);
  if (resumed.length) {
    const done = resumed.filter((s) => s.outcome === 'resumed_done').length;
    parts.push(`🔁 ${resumed.length} interrumpida${resumed.length === 1 ? '' : 's'}`
      + (done ? ` · ${done} retomada${done === 1 ? '' : 's'} y completada${done === 1 ? '' : 's'}` : ''));
  }
  const inc = list.filter((s) => s.completion === 'incomplete');
  if (inc.length) parts.push(`⚠️ ${inc.length} incompleta${inc.length === 1 ? '' : 's'}`);
  if (open.length) parts.push(`🟢 ${open.length} abierta${open.length === 1 ? '' : 's'}`);
  if (fromPrev.length) parts.push(`🌙 ${fromPrev.length} continuación${fromPrev.length === 1 ? '' : 'es'} del día anterior`);
  if (toNext.length) parts.push(`⏭ ${toNext.length} arrastra${toNext.length === 1 ? '' : 'n'} al día siguiente`);
  if (cross.length && !fromPrev.length && !toNext.length) parts.push(`🌙 ${cross.length} cruzaron la medianoche`);
  return `<span class="ws-banner-icon">🕐</span><span>${parts.join(' · ')}</span>`;
}

function wsSessionRowHtml(s, day) {
  const range = wsDayRangeOf(s, day);
  const seg = wsSegmentOf(s, day);
  // Todos los minutos del día, no solo los del primer tramo: una sesión
  // interrumpida y retomada el mismo día aporta varios bloques.
  const minutes = wsDayMinutesOf(s, day);
  const isOpen = s.status === 'active';
  const isLive = isOpen && s.realtime === true;
  const isPaused = s.status === 'paused';
  const part = seg ? seg.part : 'whole';
  // Etiquetas del cruce de medianoche: de dónde viene y a dónde va.
  const marks = [];
  if (part === 'end') marks.push('<span class="ws-mark is-cont" title="La sesión empezó el día anterior">🌙 continuación</span>');
  if (part === 'start' && s.crosses_midnight) marks.push('<span class="ws-mark is-roll" title="La sesión sigue después de las 00:00">⏭ continúa al día siguiente</span>');
  if (isPaused) {
    marks.push(`<span class="ws-mark is-paused" title="Interrumpida y esperando ser retomada${s.incomplete_reason ? ': ' + escapeHtml(s.incomplete_reason) : ''}">⏸ pausada${s.incomplete_reason ? ': ' + escapeHtml(s.incomplete_reason) : ''}</span>`);
  }
  if (s.completion === 'incomplete') {
    marks.push(`<span class="ws-mark is-incomplete" title="${escapeHtml(s.incomplete_reason || 'Quedó a medias')}${s.incomplete_reason ? ' (podés corregirla con ✏️)' : ''}">⚠️ incompleta${s.incomplete_reason ? `: ${escapeHtml(s.incomplete_reason)}` : ''}</span>`);
  }
  if (s.published_devlog_id) marks.push(`<span class="ws-mark is-shipped" title="Ya está incluida en un devlog del día">📦 en devlog #${s.published_devlog_id}</span>`);
  const timeRange = range
    ? (range.count > 1
      ? `${wsClock(range.from)} → ${wsClock(range.to)} <small>(${wsCount(range.count, 'tramo', 'tramos')} en el día)</small>`
      : `${wsClock(range.from)} → ${wsClock(range.to)}`)
    : `${wsClock(s.started_at)}${s.ended_at ? ` → ${wsClock(s.ended_at)}` : ''}`;
  const range2 = s.crosses_midnight
    ? `${timeRange} <small>(día completo ${wsClock(s.started_at)} → ${wsClock(s.ended_at || new Date())})</small>`
    : timeRange;
  // Total de la sesión: lo ya aportado por los cambios + lo que se suma al
  // cerrar. Antes solo se veía lo del cierre y parecía que el aporte del
  // cambio no se había sumado.
  const closeDelta = round2(s.progress_delta || 0);
  const changesDelta = round2(s.changes_delta || 0);
  const delta = round2(closeDelta + changesDelta);
  const deltaTitle = changesDelta && closeDelta
    ? `Ya aplicado por los cambios: +${fmtPct(changesDelta)}. Al cerrar se suma +${fmtPct(closeDelta)}.`
    : changesDelta
      ? 'El avance ya está aplicado al porcentaje del proyecto y en su historial (aportado por los cambios).'
      : (s.progress_applied
        ? 'El avance ya está aplicado al porcentaje del proyecto y en su historial.'
        : 'Se aplicará al porcentaje cuando cierres la sesión.');
  // El % se aplicó al cerrar: se aclara en qué día quedó contabilizado.
  const deltaNote = delta
    ? `<span class="ws-delta ${delta > 0 ? 'is-up' : 'is-down'}" title="${deltaTitle}">${fmtDelta(delta)}</span>`
    : '<span class="ws-delta is-none">sin avance</span>';
  // La historia va siempre que hubo una interrupción: es el dato que explica
  // por qué el trabajo está partido en varios bloques.
  const story = wsStoryHtml(s, false);
  // Los reworks de la sesión: qué cambio masivo se está trabajando y si está
  // pausado. Con la sesión pausada, el rework también.
  const reworks = wsReworksStripHtml(s);
  return `
    <li data-sid="${s.id}" class="ws-item${isOpen ? ' is-open' : ''}${isPaused ? ' is-paused' : ''}${s.crosses_midnight ? ' is-cross' : ''}${isLive ? ' is-live' : ''}${s.completion === 'incomplete' ? ' is-incomplete' : ''}${s.interrupt_count ? ' is-resumed' : ''}">
      <div class="ws-item-rail"><span class="ws-item-dot"></span></div>
      <div class="ws-item-body">
        <div class="ws-item-head">
          <span class="ws-item-time">🕐 ${range2}</span>
          <span class="ws-item-dur">⏱ ${wsMinutes(minutes)}</span>
          ${isLive
            ? `<span class="ws-item-live" title="Sesión en vivo: el cronómetro corre">⏱ EN VIVO <b data-ws-elapsed="${s.id}">${wsStopwatch(wsElapsedSeconds(s))}</b></span>`
            : isOpen
              ? `<span class="ws-item-live" title="Sesión abierta">● en curso <b data-ws-elapsed="${s.id}">${wsStopwatch(wsElapsedSeconds(s))}</b></span>`
              : ''}
          ${marks.join('')}
        </div>
        <div class="ws-item-title">${escapeHtml(s.title)}</div>
        ${s.details ? `<div class="ws-item-desc">${escapeHtml(s.details)}</div>` : ''}
        ${story}
        ${reworks}
        ${wsChangesHtml(s.changes, { session: s })}
        <div class="ws-item-foot">
          <span class="ws-item-proj">${s.project_id
            ? `🎯 ${escapeHtml(s.project_name || ('#' + s.project_id))}`
            : '🌐 Sin proyecto'}</span>
          ${deltaNote}
          ${s.interrupt_count && s.paused_minutes
            ? `<span class="ws-item-split" title="Tiempo que estuvo pausada entre los tramos">⏳ ${wsMinutes(s.paused_minutes)} en pausa</span>` : ''}
          ${s.crosses_midnight ? `<span class="ws-item-split" title="Esta sesión se repartió entre ${escapeHtml(s.local_day)} y ${escapeHtml(s.end_local_day)}">✂️ ${wsMinutes(s.duration_minutes)} repartidas</span>` : ''}
          <span class="ws-item-by">👤 ${escapeHtml(s.created_by || '—')}</span>
          <span class="ws-item-actions">
            ${isPaused
              ? `<button class="btn btn-ws-pause btn-mini" data-adm-ev="click" data-adm="resumeWsSession" data-adm-a0="r:${s.id}" title="Abrir un tramo nuevo y arrancar el cronómetro de nuevo">▶ Continuar</button>`
              : ''}
            <button class="btn btn-ghost btn-mini" data-adm-ev="click" data-adm="openWsForm" data-adm-a0="r:${s.id}" title="Editar">✏️</button>
            ${isLive
              ? `<button class="btn ws-stop-btn btn-mini" data-adm-ev="click" data-adm="openWsStopForm" data-adm-a0="r:${s.id}" title="Detener el cronómetro">⏹ Detener</button>`
              : isOpen
                ? `<button class="btn btn-primary btn-mini" data-adm-ev="click" data-adm="closeWorkSession" data-adm-a0="r:${s.id}" title="Cerrar la sesión y aplicar el avance">✅ Cerrar</button>`
                : ''}
            <button class="btn btn-danger btn-mini" data-adm-ev="click" data-adm="deleteWorkSession" data-adm-a0="r:${s.id}" title="Borrar">🗑️</button>
          </span>
        </div>
      </div>
    </li>`;
}

// Grupos por proyecto de un día (reusado en vista simple y por día).
function wsProjectGroupsHtml(list, day) {
  const groups = new Map();
  list.forEach((s) => {
    const key = s.project_id != null ? String(s.project_id) : '0';
    if (!groups.has(key)) groups.set(key, { name: s.project_id ? (s.project_name || `#${s.project_id}`) : 'Sin proyecto', items: [] });
    groups.get(key).items.push(s);
  });
  const ordered = [...groups.values()].sort((a, b) => b.items.length - a.items.length);
  return ordered.map((g) => `
    <div class="ws-group">
      <div class="ws-group-head">${g.items[0].project_id ? '🎯' : '🌐'} ${escapeHtml(g.name)}
        <small>${wsCount(g.items.length, WS_SESSION_1, WS_SESSION_N)}</small>
      </div>
      <ul class="ws-list">${g.items.map((s) => wsSessionRowHtml(s, day)).join('')}</ul>
    </div>`).join('');
}

// Una sección de día: cabecera con fecha + resumen, aviso del día y grupos.
function wsDaySectionHtml(day) {
  const list = wsDaySessions(day);
  const totalMin = list.reduce((sum, s) => sum + wsDayMinutesOf(s, day), 0);
  const banner = wsBannerHtml(day);
  const isToday = day === wsTodayKey();
  return `
    <section class="ws-day${isToday ? ' is-today' : ''}" id="ws-day-${day}">
      <div class="ws-day-head">
        <span class="ws-day-icon">📅</span>
        <div class="ws-day-titles">
          <b class="ws-day-title">${escapeHtml(wsDayTitle(day))}</b>
          <small class="ws-day-sub">${wsCount(list.length, WS_SESSION_1, WS_SESSION_N)} · ${wsMinutes(totalMin)} de trabajo</small>
        </div>
        <button type="button" class="btn btn-ghost btn-mini" data-adm-ev="click" data-adm="setWsDayKey" data-adm-a0="s:${day}" data-adm-a1="b:1" title="Ver solo este día y su devlog">📓 Ver día</button>
      </div>
      ${banner ? `<div class="ws-banner is-inline">${banner}</div>` : ''}
      ${wsProjectGroupsHtml(list, day)}
    </section>`;
}

function renderWsTimeline() {
  const box = document.getElementById('ws-timeline');
  if (!box) return;
  syncWsTimelineModeUI();
  // ── Vista categorizada por día (por defecto) ──
  if (wsTimelineMode !== 'day') {
    const banner = document.getElementById('ws-banner');
    if (banner) { banner.innerHTML = ''; banner.classList.add('hidden'); }
    const days = wsAllDays(WS_TIMELINE_DAYS_LIMIT);
    if (!days.length) {
      box.innerHTML = `<div class="ws-empty">
        <span class="ws-empty-icon">🕐</span>
        <p class="ws-empty-title">Todavía no hay sesiones</p>
        <p class="ws-empty-sub">Contá qué vas a hacer y el reloj toma solo la hora de inicio y de fin. Al final del día, todas las sesiones se combinan en el devlog del día.</p>
        <button class="btn ws-start-btn btn-sm" data-adm-ev="click" data-adm="openWsRealtimeForm">⏱ Iniciar en tiempo real</button>
        <button class="btn btn-ghost btn-sm" data-adm-ev="click" data-adm="openWsForm" data-adm-a0="x:" data-adm-a1="s:active">✍️ Cargar a mano</button>
      </div>`;
      return;
    }
    const active = wsActiveDay();
    // El día activo primero para que lo último trabajado quede arriba,
    // el resto en orden de más nuevo a más viejo.
    const ordered = [active, ...days.filter((d) => d !== active)].filter((d, i, a) => a.indexOf(d) === i);
    const withData = ordered.filter((d) => wsDaySessions(d).length);
    const html = withData.map((d) => wsDaySectionHtml(d)).join('');
    const hiddenCount = (wsCache || []).length
      ? Math.max(0, new Set((wsCache || []).flatMap((s) => (s.segments || []).map((g) => g.day))).size - withData.length)
      : 0;
    box.innerHTML = html + (hiddenCount > 0
      ? `<p class="ws-more">… y ${hiddenCount} día${hiddenCount === 1 ? '' : 's'} más atrás (se muestran los últimos ${WS_TIMELINE_DAYS_LIMIT}).</p>`
      : '');
    renderWsLiveBar();
    startWsClock();
    return;
  }
  // ── Vista de un solo día ──
  const day = wsActiveDay();
  const banner = document.getElementById('ws-banner');
  if (banner) {
    const html = wsBannerHtml(day);
    banner.innerHTML = html;
    banner.classList.toggle('hidden', !html);
  }
  const list = wsDaySessions(day);
  if (!list.length) {
    const isToday = day === wsTodayKey();
    box.innerHTML = `<div class="ws-empty">
      <span class="ws-empty-icon">🕐</span>
      <p class="ws-empty-title">${isToday ? 'Todavía no hay sesiones hoy' : `Sin sesiones el ${day.slice(8)}/${day.slice(5, 7)}`}</p>
      <p class="ws-empty-sub">Contá qué vas a hacer y el reloj toma solo la hora de inicio y de fin. Al final del día, todas las sesiones se combinan en el devlog del día.</p>
      <button class="btn ws-start-btn btn-sm" data-adm-ev="click" data-adm="openWsRealtimeForm">⏱ Iniciar en tiempo real</button>
      <button class="btn btn-ghost btn-sm" data-adm-ev="click" data-adm="openWsForm" data-adm-a0="x:" data-adm-a1="s:active">✍️ Cargar a mano</button>
    </div>`;
    return;
  }
  // Agrupar por proyecto: primero los que tienen % o sesiones abiertas.
  box.innerHTML = wsProjectGroupsHtml(list, day);
  renderWsLiveBar();
  startWsClock();
}

// ── Devlog del día ──
// Vista previa: lo que se crearía al publicar. El backend arma el texto.
async function loadWsDaily() {
  const box = document.getElementById('ws-daily');
  if (!box) return;
  if (!(await requireAuth())) return;
  const day = wsActiveDay();
  const label = document.getElementById('ws-daily-label');
  if (label) label.textContent = day === wsTodayKey() ? 'hoy' : `${day.slice(8)}/${day.slice(5, 7)}/${day.slice(0, 4)}`;
  try {
    const res = await adminFetch(API_BASE + `/ows-work-sessions/daily?date=${encodeURIComponent(day)}&tz_offset=${wsTzOffset()}`);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    wsDailyCache = data;
    renderWsDaily();
  } catch (err) {
    box.innerHTML = `<p class="loading-note">⚠️ ${escapeHtml(err.message)}</p>`;
  }
}

// Días anteriores a hoy con sesiones cerradas sin publicar en ningún devlog.
// Es lo que permite recuperar días que quedaron sin publicar: cada chip salta
// a ese día para publicarlo con su fecha real (publicarlo "hoy" quedaría
// técnicamente mal atribuido).
function wsPendingPublishDays() {
  const today = wsTodayKey();
  const map = new Map();
  (Array.isArray(wsCache) ? wsCache : []).forEach((s) => {
    if (s.published_devlog_id) return;
    if (s.status !== 'done') return;
    (Array.isArray(s.segments) ? s.segments : []).forEach((g) => {
      if (!g.day || g.day >= today) return;
      if (!map.has(g.day)) map.set(g.day, new Set());
      map.get(g.day).add(s.id);
    });
  });
  return [...map.entries()]
    .map(([day, ids]) => ({ day, count: ids.size }))
    .sort((a, b) => b.day.localeCompare(a.day))
    .slice(0, 7);
}
function wsFmtShortDay(day) {
  return `${day.slice(8)}/${day.slice(5, 7)}`;
}
function renderWsDaily() {
  const box = document.getElementById('ws-daily');
  if (!box) return;
  const day = wsActiveDay();
  const groups = (wsDailyCache && Array.isArray(wsDailyCache.groups)) ? wsDailyCache.groups : [];
  // Aviso de días anteriores sin publicar (distintos al que se está mirando).
  const pendingDays = wsPendingPublishDays().filter((d) => d.day !== day);
  const pendingHtml = pendingDays.length
    ? `<div class="ws-daily-pending">⚠️ <b>Sin publicar de otros días:</b> ${pendingDays.map((d) =>
      `<button type="button" class="ws-daily-pending-chip" data-adm-ev="click" data-adm="setWsDayKey" data-adm-a0="s:${d.day}" data-adm-a1="b:1" title="Ver el ${wsFmtShortDay(d.day)} y publicarlo con su fecha">📅 ${wsFmtShortDay(d.day)} · ${wsCount(d.count, 'sesión', 'sesiones')}</button>`
    ).join('')}</div>`
    : '';
  if (!groups.length) {
    box.innerHTML = `${pendingHtml}<div class="ws-empty">
      <span class="ws-empty-icon">🗓️</span>
      <p class="ws-empty-title">Nada que combinar</p>
      <p class="ws-empty-sub">Cuando tenga sesiones de ese día, acá aparece el devlog armado listo para publicar.</p>
    </div>`;
    return;
  }
  box.innerHTML = pendingHtml + groups.map((g) => {
    const pending = g.pending || 0;
    const done = pending === 0;
    const p = g.payload || {};
    // La lista de sesiones tal como va a quedar escrita en el devlog.
      const lines = (g.items || []).slice()
        .sort((a, b) => String(a.seg.from).localeCompare(String(b.seg.from)))
        .map(({ session: s, seg, is_last: isLast }) => {
          const notes = [];
          // Igual que arma el backend: si la sesión tuvo varios tramos, la
          // línea lo repite para que se vea aunque se lea suelta.
          const multi = s.parts_count > 1
            ? ` <span class="ws-line-tramos">${s.parts_count} tramos · ${wsMinutes(s.paused_minutes)} en pausa</span>`
            : '';
          if (seg.part === 'end') notes.push('continuación del día anterior');
          if (s.crosses_midnight && seg.part === 'start') notes.push('continúa al día siguiente');
          if (seg.chunk > 0) notes.push(`se continuó a las ${wsClock(seg.from)} tras la pausa`);
          if (seg.paused_after != null) {
            notes.push(`se interrumpió a las ${wsClock(seg.to)}`
              + (seg.pause_reason ? ` (${seg.pause_reason})` : '')
              + (seg.paused_after ? ` · pausa de ${wsMinutes(seg.paused_after)}` : ''));
          }
          if (s.status === 'active') notes.push(s.realtime ? 'sigue abierta EN VIVO ⏱' : 'sigue abierta');
          if (s.status === 'paused') {
            notes.push(`quedó pausada${s.incomplete_reason ? `: ${s.incomplete_reason}` : ''} — se puede continuar más tarde`);
          }
          if (s.completion === 'incomplete') {
            notes.push(`quedó incompleta${s.incomplete_reason ? `: ${s.incomplete_reason}` : ''}`);
          }
          if (isLast && s.outcome === 'resumed_done') notes.push('se retomó y se finalizó con éxito ✅');
          return `<li class="${wsLineClass(s, seg)}"><span class="ws-line-time">${wsClock(seg.from)}–${wsClock(seg.to)}</span>
          <span class="ws-line-dur">${wsMinutes(seg.minutes)}</span>
          <span class="ws-line-title">${escapeHtml(s.title)}${multi}</span>
          ${notes.length ? `<span class="ws-line-mark">${escapeHtml(notes.join(' · '))}</span>` : ''}</li>`;
        }).join('');
    const delta = round2(g.delta || 0);
    const inc = Number(g.incomplete || 0);
    const paused = Number(g.paused || 0);
    const resumes = Number(g.resumes || 0);
    const done2 = Number(g.resumes_done || 0);
    const tramos = Number(g.tramos || 0);
    const pauseMin = Number(g.paused_minutes || 0);
    return `
      <div class="ws-daily-item${done ? ' is-done' : ''}${inc ? ' has-incomplete' : ''}${paused || resumes ? ' has-story' : ''}">
        <div class="ws-daily-head">
          <span class="ws-daily-proj">${g.project_id ? '🎯' : '🌐'} ${escapeHtml(g.project_name || 'Sin proyecto')}</span>
          <span class="ws-daily-stats">
            <span title="Sesiones que tocan este día">🕐 ${wsCount(g.session_count, WS_SESSION_1, WS_SESSION_N)}</span>
            <span title="Tiempo del día">⏱ ${wsMinutes(g.minutes)}</span>
            ${paused ? `<span class="ws-daily-pause" title="${escapeHtml((g.paused_reasons || []).join('; '))}">⏸ ${paused} pausada${paused === 1 ? '' : 's'}</span>` : ''}
            ${tramos > 1 ? `<span class="ws-daily-tramos" title="El trabajo del día se repartió en varios tramos, con pausas en el medio">⏱ ${tramos} tramo${tramos === 1 ? '' : 's'}${pauseMin ? ` · ${wsMinutes(pauseMin)} en pausa` : ''}</span>` : ''}
            ${resumes ? `<span class="ws-daily-resume" title="Sesiones que se cortaron y se volvieron a tomar">🔁 ${resumes} retomada${resumes === 1 ? '' : 's'}${done2 ? ` · ${done2} completada${done2 === 1 ? '' : 's'}` : ''}</span>` : ''}
            ${inc ? `<span class="ws-daily-inc" title="${escapeHtml((g.incomplete_reasons || []).join('; '))}">⚠️ ${inc} a medias</span>` : ''}
            ${delta ? `<span class="ws-delta ${delta > 0 ? 'is-up' : 'is-down'}">${fmtDelta(delta)}</span>` : ''}
          </span>
          ${done
            ? '<span class="ws-daily-badge is-done">📦 Publicado</span>'
            : `<button class="btn btn-primary btn-sm" data-adm-ev="click" data-adm="publishDailyDevlog" data-adm-a0="r:${g.project_id == null ? -1 : g.project_id}">📤 Publicar (${pending})</button>`}
        </div>
        <div class="ws-daily-preview">
          <div class="ws-preview-block">
            <span class="ws-preview-label">Título</span>
            <span class="ws-preview-val">${escapeHtml(p.title || '')}</span>
          </div>
          <div class="ws-preview-block">
            <span class="ws-preview-label">Por qué</span>
            <span class="ws-preview-val">${escapeHtml(p.reason || '')}</span>
          </div>
          <ul class="ws-daily-lines">${lines}</ul>
        </div>
      </div>`;
  }).join('');
}

// Clase de una línea de la vista previa: en vivo, pausada, retomada o a medias.
function wsLineClass(s, seg) {
  if (s.status === 'active' && s.realtime) return 'is-live';
  if (s.status === 'paused') return 'is-paused';
  if (seg && seg.chunk > 0) return 'is-resumed';
  if (s.completion === 'incomplete') return 'is-incomplete';
  return '';
}

// Publica el devlog del día. El % NO se vuelve a sumar (ya se aplicó al
// cerrar cada sesión): acá solo se arma el registro narrativo.
// projectId: 0 = todos los proyectos · -1 = solo los que no tienen proyecto.
async function publishDailyDevlog(projectId) {
  if (!(await requireAuth())) return;
  const day = wsActiveDay();
  const pid = Number(projectId || 0);
  const target = pid
    ? (wsDailyCache?.groups || []).find((g) => (pid === -1 ? g.project_id == null : Number(g.project_id) === pid))
    : null;
  const what = pid === 0 ? 'todos los proyectos' : (target ? `"${target.project_name}"` : 'ese proyecto');
  if (!window.confirm(`¿Publicar el devlog del día ${day} de ${what}?\n\nEl porcentaje ya está aplicado: no se va a sumar de nuevo.`)) return;
  try {
    const res = await adminFetch(API_BASE + '/ows-work-sessions/daily', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ date: day, tz_offset: wsTzOffset(), project_id: pid, created_by: getCurrentAdminName() })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    const n = Array.isArray(data.created) ? data.created.length : 0;
    if (!n) {
      showToast(`ℹ️ ${data.message || 'No había nada nuevo para publicar'}`);
    } else {
      const parts = data.created.map((d) => `“${d.title}” (${d.session_count} sesiones, ${wsMinutes(d.day_minutes)})`);
      showToast(`📤 Devlog del día publicado: ${parts.join(' · ')}`);
    }
    closeWsForm();
    await loadDevlogs();
    await loadWorkSessions();
    await loadWsDaily();
    // El devlog nuevo es un evento más en la bitácora de 14 días.
    loadProjectActivity();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

// =======================================================
// ACTIVIDAD 14 DÍAS — bitácora diaria autogenerada
// =======================================================
// Una fila por proyecto y una columna por día (DIA/MES), empezando por HOY y
// retrocediendo PAX_DAYS días. Cada celda resume qué pasó ese día en ese
// proyecto, y la ventana se recalcula sola: al cambiar la fecha entra una
// columna nueva y sale la más vieja, sin tocar nada.
//
// No hay tabla nueva en la base: se arma con lo que ya existe y ya se pedía
// en otras secciones del panel.
//   · GET /ows-project-development/history → movimientos de % (con nota)
//   · GET /ows-devlogs                     → entradas del devlog
//   · GET /ows-project-development         → % actual (devProgressCache)
//   · GET /ows-launch-projects?include_hidden=1 → ficha del proyecto
// El delta de % se cuenta SOLO desde el historial: un devlog que aplicó avance
// no suma dos veces, porque el chip 📝 y el ▲ son el mismo movimiento.
// =======================================================

// Días que cubre la tabla (hoy + los 13 anteriores).
const PAX_DAYS = 14;
// Cada cuánto se refresca sola si la sub-sección está a la vista.
const PAX_REFRESH_MS = 5 * 60 * 1000;
// Fila de los devlogs que no afectan a ningún proyecto.
const PAX_GENERAL_PID = 0;
// Columnas reales de la tabla: proyecto + % actual + 14 días + total.
const PAX_COLSPAN = PAX_DAYS + 3;

// Historial de avances (movimientos de %) y marca del último refresco.
let paxHistoryCache = [];
let paxLoadedAt = null;
// Celdas desplegadas: "proyectoId|YYYY-MM-DD" (0 = sin proyecto).
let paxOpenCells = new Set();
// Timer de refresco automático (se crea la primera vez).
let paxAutoTimer = null;
// Último "hoy" pintado: si cambia, la ventana se regenera al instante.
let paxTodayKey = '';

// Tipos de evento y cómo se ven en la celda. Una sola fuente de verdad para
// los chips, la leyenda y el detalle.
const PAX_CHIP_META = {
  devlog:  { icon: '📝', label: 'Devlog' },
  up:      { icon: '▲', label: 'Avance' },
  down:    { icon: '▼', label: 'Retroceso' },
  note:    { icon: '💬', label: 'Nota' },
  new:     { icon: '🆕', label: 'Alta del proyecto' },
  edit:    { icon: '✏️', label: 'Edición' },
  launch:  { icon: '🚀', label: 'Lanzamiento' },
  due:     { icon: '🎯', label: 'Fecha prevista' },
  done:    { icon: '🎉', label: 'Llegó al 100%' },
  session: { icon: '🔧', label: 'Sesión de trabajo' },
  cont:    { icon: '🌙', label: 'Continuación (cruza 00:00)' },
  roll:    { icon: '⏭', label: 'Sigue al día siguiente' },
  shipped: { icon: '📦', label: 'Ya publicado en el devlog' },
  incomplete: { icon: '⚠️', label: 'Sesión incompleta' },
  pause:   { icon: '⏸', label: 'Interrumpida: la sesión quedó pausada' },
  resume:  { icon: '🔁', label: 'Se retomó después de la pausa' },
  tramos:  { icon: '⏱', label: 'Sesión trabajada en varios tramos (hubo una pausa)' }
};

// ── Fechas ──
// Todo se agrupa por día LOCAL: la bitácora la mira una persona en su
// huso, no un servidor en el suyo.
function paxKeyFromDate(d) {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}
function paxKeyOf(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '' : paxKeyFromDate(d);
}
// "2026-09-28" → parte la clave sin construir una fecha (evita el shift de zona).
function paxKeyParts(key) {
  const [y, m, d] = String(key || '').split('-').map(Number);
  return { y, m, d };
}
function paxKeyOfDateField(v) {
  // Las columnas DATE de Postgres llegan como 'YYYY-MM-DD' o
  // 'YYYY-MM-DDTHH:MM:SS.mmmZ': se toma solo la parte de la fecha.
  const s = String(v || '').trim();
  return /^\d{4}-\d{2}-\d{2}/.test(s) ? s.slice(0, 10) : '';
}
// Ventana de días: hoy primero, retrocediendo.
function paxRange() {
  const now = new Date();
  const out = [];
  for (let i = 0; i < PAX_DAYS; i++) {
    const d = new Date(now.getFullYear(), now.getMonth(), now.getDate() - i);
    out.push({ key: paxKeyFromDate(d), date: d, isToday: i === 0 });
  }
  return out;
}
function paxDayMonth(key) {
  const { d, m } = paxKeyParts(key);
  return `${String(d).padStart(2, '0')}/${String(m).padStart(2, '0')}`;
}
function paxWeekday(key) {
  const { y, m, d } = paxKeyParts(key);
  if (!y || !m || !d) return '';
  return new Date(y, m - 1, d).toLocaleDateString('es-ES', { weekday: 'short' }).replace('.', '');
}
function paxDayLong(key) {
  const { y, m, d } = paxKeyParts(key);
  if (!y || !m || !d) return '—';
  const dt = new Date(y, m - 1, d);
  const wd = dt.toLocaleDateString('es-ES', { weekday: 'long' });
  return `${wd.charAt(0).toUpperCase()}${wd.slice(1)} ${d}/${String(m).padStart(2, '0')}/${y}`;
}

// ── Datos base ──
// % actual por proyecto (viene de /ows-project-development).
function paxDevFor(pid) {
  return devProgressCache.find((d) => Number(d.project_id) === Number(pid)) || null;
}
// Proyectos de la tabla: primero los de Gestión (traen admin_only), y si
// algún movimiento del historial apunta a uno que no está en la lista, se
// agrega para que ese día nunca se pierda.
function paxProjects() {
  const seen = new Map();
  const add = (id, extra) => {
    const pid = Number(id || 0);
    if (!Number.isFinite(pid) || pid <= 0 || seen.has(pid)) return;
    seen.set(pid, { id: pid, name: `#${pid}`, icon_url: '', ...extra });
  };
  [...(manageProjectsCache || []), ...(projectsCache || [])].forEach((p) => {
    if (!p) return;
    add(p.id, {
      name: p.name || p.slug || `#${p.id}`,
      icon_url: p.icon_url || p.iconUrl || '',
      status: p.status,
      admin_only: isAdminOnlyProject(p),
      created_at: p.created_at,
      updated_at: p.updated_at,
      expected_date: p.expected_date,
      confirmed_date: p.confirmed_date
    });
  });
  paxHistoryCache.forEach((h) => add(h.project_id, {
    name: h.project_name || `#${h.project_id}`,
    icon_url: h.project_icon_url || '',
    admin_only: h.admin_only === true
  }));
  devlogsCache.forEach((d) => add(d.project_id, { name: d.project_name || '' }));
  return [...seen.values()].sort((a, b) => a.name.localeCompare(b.name, 'es'));
}

// ── Agregación: proyecto + día → eventos ──
// Solo se guardan los días que están dentro de la ventana: así la tabla no
// depende de que el llamador filtre bien y no se arrastra historial viejo.
function paxBuildEvents(dayKeys) {
  const inWindow = new Set(dayKeys || []);
  const inside = (key) => !!key && (!inWindow.size || inWindow.has(key));
  const map = new Map();
  const push = (pid, key, ev) => {
    if (!inside(key)) return;
    const k = `${pid}|${key}`;
    if (!map.has(k)) map.set(k, []);
    map.get(k).push(ev);
  };

  // 1 · Movimientos de % (historial de avances).
  paxHistoryCache.forEach((h) => {
    const key = paxKeyOf(h.created_at);
    const delta = round2(h.delta || 0);
    const note = String(h.note || '').trim();
    if (!key || (!delta && !note)) return;
    const before = round2(h.percent_before);
    const after = round2(h.percent_after);
    const chips = [];
    if (delta > 0) chips.push('up');
    else if (delta < 0) chips.push('down');
    if (note) chips.push('note');
    // Llegar a 100% es un hito: se marca aunque el movimiento sea del devlog.
    if (after >= 100 && before < 100) chips.push('done');
    push(Number(h.project_id || 0), key, {
      chips,
      delta,
      icon: delta > 0 ? '▲' : delta < 0 ? '▼' : '💬',
      title: [
        delta ? `${delta > 0 ? 'Avanzó' : 'Retrocedió'} el porcentaje: ${fmtPct(before)} → ${fmtPct(after)} (${fmtDelta(delta)})` : 'Ajuste de porcentaje',
        h.mode === 'total' ? 'Ajuste total' : 'Avance del día',
        note ? `Nota: ${note}` : '',
        `👤 ${h.created_by || '—'} · ${formatDevAgo(h.created_at)}`
      ].filter(Boolean).join(' · '),
      devlogId: null
    });
  });

  // 2 · Devlogs (el registro narrativo). No suman delta: el % ya viene del
  //     historial, así un devlog con avance no cuenta dos veces.
  devlogsCache.forEach((d) => {
    const key = paxKeyOf(d.created_at);
    if (!key) return;
    const pid = d.affects_project ? Number(d.project_id || 0) : PAX_GENERAL_PID;
    const reason = String(d.reason || '').trim();
    push(pid, key, {
      chips: ['devlog'],
      delta: 0,
      icon: '📝',
      title: [
        `Devlog: ${d.title || 'sin título'}`,
        reason ? (reason.length > 140 ? reason.slice(0, 140) + '…' : reason) : '',
        `👤 ${d.created_by || '—'} · ${formatDevAgo(d.created_at)}`
      ].filter(Boolean).join(' · '),
      devlogId: Number(d.id || 0) || null
    });
  });

  // 3 · Hechos de la ficha del proyecto que no viven en el historial:
  //     alta, edición, fecha de lanzamiento y fecha prevista.
  paxProjects().forEach((p) => {
    const created = paxKeyOf(p.created_at);
    const updated = paxKeyOf(p.updated_at);
    if (created) {
      push(p.id, created, {
        chips: ['new'], delta: 0, icon: '🆕', devlogId: null,
        title: `Proyecto dado de alta · ${formatDevAgo(p.created_at)}`
      });
    }
    // El alta también "edita" el registro: no se duplica el chip.
    if (updated && updated !== created) {
      const meta = launchStatusMeta(p.status);
      push(p.id, updated, {
        chips: ['edit'], delta: 0, icon: '✏️', devlogId: null,
        title: `Se editó el proyecto (estado: ${meta.label}) · ${formatDevAgo(p.updated_at)}`
      });
    }
    const confirmed = paxKeyOfDateField(p.confirmed_date);
    if (confirmed) {
      push(p.id, confirmed, {
        chips: ['launch'], delta: 0, icon: '🚀', devlogId: null,
        title: `Fecha de lanzamiento: ${paxDayLong(confirmed)}`
      });
    }
    const expected = paxKeyOfDateField(p.expected_date);
    if (expected) {
      push(p.id, expected, {
        chips: ['due'], delta: 0, icon: '🎯', devlogId: null,
        title: `Fecha prevista de lanzamiento: ${paxDayLong(expected)}`
      });
    }
  });

  // 4 · Sesiones de trabajo. Cada sesión llega del backend ya partida por
  //     día (segments), así que una sesión que cayó después de las 00:00
  //     aparece en LOS DOS días con sus minutos y la marca de continuación.
  //     El delta NO se suma al neto de la celda: el % ya se aplicó al
  //     cerrar la sesión y quedó en el historial (paso 1). Acá va el 🕐 de
  //     cuándo se hizo el trabajo, que es lo que la tabla no tenía.
  //
  //     Los tramos de una MISMA sesión en un mismo día se agrupan en un solo
  //     evento: si se interrumpió y se retomó, la fila lo cuenta como una
  //     sesión de N tramos en vez de duplicarla en dos renglones sueltos.
  (typeof wsCache !== 'undefined' ? wsCache : []).forEach((s) => {
    const pid = s.project_id != null ? Number(s.project_id) : PAX_GENERAL_PID;
    // Un renglón por (sesión, día), con todos sus tramos juntos.
    const byDay = new Map();
    (s.segments || []).forEach((seg) => {
      if (!byDay.has(seg.day)) byDay.set(seg.day, []);
      byDay.get(seg.day).push(seg);
    });
    byDay.forEach((segs, day) => {
      const first = segs[0];
      const last = segs[segs.length - 1];
      const minutes = segs.reduce((n, x) => n + (x.minutes || 0), 0);
      const chunks = new Set(segs.map((x) => x.chunk)).size;
      const chips = ['session'];
      // Cruzó la medianoche: la fila sigue siendo la misma sesión en dos días.
      if (segs.some((x) => x.part === 'end')) chips.push('cont');
      if (first.part === 'start' && s.crosses_midnight) chips.push('roll');
      // Se trabajó en varios tramos (por una pausa): es el dato que explica
      // por qué el tiempo de la sesión no es el del reloj.
      if (chunks > 1) chips.push('tramos');
      if (s.published_devlog_id) chips.push('shipped');
      if (s.completion === 'incomplete') chips.push('incomplete');
      if (s.status === 'paused') chips.push('pause');
      if (segs.some((x) => x.chunk > 0)) chips.push('resume');
      const notes = [
        chunks > 1
          ? `${wsClock(first.from)} → ${wsClock(last.to)} (${wsMinutes(minutes)}) en ${wsCount(chunks, 'tramo', 'tramos')}`
          : `${wsClock(first.from)} → ${wsClock(last.to)} (${wsMinutes(minutes)})`,
        // Cada tramo, para que se vea dónde estuvo la pausa.
        chunks > 1
          ? segs.map((x, i) => `tramo ${i + 1}: ${wsClock(x.from)}–${wsClock(x.to)} (${wsMinutes(x.minutes)})`).join(' · ')
          : '',
        s.details ? s.details.replace(/\s+/g, ' ').trim() : '',
        // La historia de las pausas, para que el detalle diga por qué el
        // trabajo quedó partido en varios bloques.
        (s.interrupts || []).map((c) => `Se interrumpió a las ${wsClock(c.at)}${c.reason ? ` (${c.reason})` : ''} y se continuó a las ${wsClock(c.resumed_at)} — ${wsMinutes(c.minutes)} en pausa`).join(' · '),
        chunks > 1 ? `Total de la sesión: ${wsMinutes(s.duration_minutes)} trabajados en ${wsCount(s.parts_count, 'tramo', 'tramos')}${s.paused_minutes ? `, con ${wsMinutes(s.paused_minutes)} en pausa` : ''}` : '',
        s.status === 'paused'
          ? `Quedó pausada${s.incomplete_reason ? `: ${s.incomplete_reason}` : ''}, se puede continuar más tarde`
          : '',
        s.outcome === 'resumed_done' ? 'Se retomó y se finalizó con éxito' : '',
        s.completion === 'incomplete'
          ? `Quedó incompleta${s.incomplete_reason ? `: ${s.incomplete_reason}` : ' (sin motivo anotado)'}`
          : '',
        `👤 ${s.created_by || '—'}`,
        s.status === 'active' ? 'sigue abierta' : ''
      ].filter(Boolean).join(' · ');
      // Si cruza la medianoche se aclara que el % se contabilizó al cerrar.
      const splitNote = s.crosses_midnight
        ? ` · El trabajo se repartió entre ${s.local_day} y ${s.end_local_day}; el avance de ${fmtDelta(s.progress_delta)} quedó aplicado el día que se cerró (${s.end_local_day}).`
        : '';
      push(pid, day, {
        chips,
        delta: 0,          // el % no se cuenta dos veces: ya está en el paso 1
        minutes,
        icon: s.status === 'paused' ? '⏸' : (chunks > 1 ? '🔁' : (s.crosses_midnight ? (first.part === 'end' ? '🌙' : '⏭') : '🔧')),
        title: `Sesión de trabajo: ${s.title} · ${notes}${splitNote}`,
        devlogId: null,
        sessionId: Number(s.id || 0) || null
      });
    });
  });

  return map;
}

// Neto de % de un proyecto+día (Σ de los movimientos registrados).
function paxNetOf(map, pid, key) {
  const evs = map.get(`${pid}|${key}`);
  if (!evs) return 0;
  return round2(evs.reduce((s, e) => s + (e.delta || 0), 0));
}

// Fila visible según los filtros de la barra de herramientas.
function paxVisibleProjects(map, days) {
  const sel = document.getElementById('pax-filter-project');
  const onlyActive = document.getElementById('pax-only-active');
  const want = sel ? String(sel.value || '') : '';
  const only = !!(onlyActive && onlyActive.checked);

  let list = paxProjects();
  if (want) list = list.filter((p) => String(p.id) === want);
  if (only) {
    list = list.filter((p) => days.some((d) => (map.get(`${p.id}|${d.key}`) || []).length));
  }
  return list;
}

// Datos de la tabla: filas + totales por día (se calculan una sola vez y se
// usan para el pie, las píldoras y la franja de días).
function paxBuild(days) {
  const map = paxBuildEvents(days.map((d) => d.key));
  const rows = paxVisibleProjects(map, days).map((p) => {
    const cells = days.map((d) => {
      const evs = map.get(`${p.id}|${d.key}`) || [];
      return { key: d.key, isToday: d.isToday, events: evs, net: paxNetOf(map, p.id, d.key) };
    });
    const active = cells.filter((c) => c.events.length);
    // Las sesiones se cuentan por id y no por evento: una sesión que cruza la
    // medianoche o que se interrumpió y se retomó genera varios eventos, pero
    // sigue siendo UNA sesión.
    const sessionIds = new Set();
    const incompleteIds = new Set();
    const pausedIds = new Set();
    const resumedIds = new Set();
    const tramoIds = new Set();
    cells.forEach((c) => c.events.forEach((e) => {
      if (!e.chips.includes('session')) return;
      const id = e.sessionId || `${c.key}|${e.title}`;
      sessionIds.add(id);
      if (e.chips.includes('incomplete')) incompleteIds.add(id);
      if (e.chips.includes('pause')) pausedIds.add(id);
      if (e.chips.includes('resume')) resumedIds.add(id);
      if (e.chips.includes('tramos')) tramoIds.add(id);
    }));
    return {
      project: p,
      cells,
      devlogs: cells.reduce((s, c) => s + c.events.filter((e) => e.devlogId).length, 0),
      sessions: sessionIds.size,
      incomplete: incompleteIds.size,
      paused: pausedIds.size,
      resumed: resumedIds.size,
      tramos: tramoIds.size,
      minutes: cells.reduce((s, c) => s + c.events.reduce((x, e) => x + (e.minutes || 0), 0), 0),
      net: round2(cells.reduce((s, c) => s + c.net, 0)),
      activeDays: active.length
    };
  });
  const dayTotals = days.map((d) => {
    const net = round2(rows.reduce((s, r) => s + (r.cells.find((c) => c.key === d.key)?.net || 0), 0));
    const events = rows.reduce((s, r) => s + (r.cells.find((c) => c.key === d.key)?.events.length || 0), 0);
    const minutes = rows.reduce((s, r) => s + (r.cells.find((c) => c.key === d.key)?.events || [])
      .reduce((x, e) => x + (e.minutes || 0), 0), 0);
    return { key: d.key, isToday: d.isToday, net, events, minutes };
  });
  return { rows, dayTotals, map };
}

// ── Render ──
function paxChipHtml(type, count) {
  const meta = PAX_CHIP_META[type];
  if (!meta) return '';
  const label = count > 1 ? `${meta.icon} ${count}` : meta.icon;
  return `<span class="pax-chip pax-chip-${type}" title="${escapeHtml(meta.label)}">${label}</span>`;
}

function paxCellHtml(pid, cell, name) {
  const k = `${pid}|${cell.key}`;
  if (!cell.events.length) {
    return `<td class="pax-cell is-empty" data-day="${cell.key}"><span class="pax-none">—</span></td>`;
  }
  // Un chip por tipo, con contador cuando hay más de uno (varios devlogs).
  const counts = {};
  cell.events.forEach((e) => e.chips.forEach((c) => { counts[c] = (counts[c] || 0) + 1; }));
  const chips = Object.keys(counts).map((c) => paxChipHtml(c, counts[c])).join('');
  const net = cell.net;
  const netHtml = net
    ? `<span class="pax-net ${net > 0 ? 'is-up' : 'is-down'}">${fmtDelta(net)}</span>`
    : '';
  // Tiempo de trabajo del día (suma de los tramos de sesión que lo tocan).
  const minutes = cell.events.reduce((s, e) => s + (e.minutes || 0), 0);
  const minHtml = minutes
    ? `<span class="pax-min" title="Tiempo de trabajo registrado ese día">⏱ ${wsMinutes(minutes)}</span>`
    : '';
  const tip = cell.events.map((e) => e.title).join('\n');
  const open = paxOpenCells.has(k);
  const lv = Math.min(3, 1 + Math.floor(cell.events.length / 2));
  return `<td class="pax-cell is-active lv-${lv}${cell.isToday ? ' is-today' : ''}${open ? ' is-open' : ''}"
    data-day="${cell.key}" tabindex="0" role="button"
    title="${escapeHtml(`${name} · ${paxDayLong(cell.key)}\n${tip}`)}"
    data-adm-ev="click" data-adm="togglePaxCell" data-adm-a0="r:${pid}" data-adm-a1="s:${cell.key}"
    data-adm-ev="keydown" data-adm-key="Enter|Space" data-adm="togglePaxCell" data-adm-a0="r:${pid}" data-adm-a1="s:${cell.key}">
    <div class="pax-chips">${chips}${netHtml}${minHtml}</div>
  </td>`;
}

// Fila de detalle desplegada bajo la fila del proyecto.
function paxDetailHtml(pid, cell, name) {
  const evs = cell.events.slice().sort((a, b) => (a.devlogId ? 1 : 0) - (b.devlogId ? 1 : 0));
  const items = evs.map((e) => `
    <li class="pax-detail-item">
      <span class="pax-detail-icon">${e.icon}</span>
      <div class="pax-detail-body">
        <div class="pax-detail-title">${escapeHtml(e.title)}</div>
        <div class="pax-detail-meta">
          ${PAX_CHIP_META[(e.chips[0] || 'note')] ? escapeHtml(PAX_CHIP_META[e.chips[0]].label) : 'Detalle'}
          ${e.delta ? ` · ${fmtDelta(e.delta)}` : ''}
          ${e.minutes ? ` · ⏱ ${wsMinutes(e.minutes)}` : ''}
        </div>
      </div>
      ${e.devlogId ? `<button class="btn btn-ghost btn-mini" data-adm-ev="click" data-adm="viewDevlog" data-adm-a0="r:${e.devlogId}">👁️ Ver devlog</button>` : ''}
    </li>`).join('');
  return `<tr class="pax-detail-row" data-detail-for="${pid}|${cell.key}">
    <td colspan="${PAX_COLSPAN}">
      <div class="pax-detail-box">
        <div class="pax-detail-head">
          <span>📅 ${escapeHtml(paxDayLong(cell.key))}</span>
          <b>${escapeHtml(name)}</b>
          ${cell.net ? `<span class="pax-net ${cell.net > 0 ? 'is-up' : 'is-down'}">${fmtDelta(cell.net)} en el día</span>` : ''}
          <button class="btn btn-ghost btn-mini pax-detail-close" data-adm-ev="click" data-adm="togglePaxCell" data-adm-a0="r:${pid}" data-adm-a1="s:${cell.key}">✕ Cerrar</button>
        </div>
        <ul class="pax-detail-list">${items}</ul>
      </div>
    </td>
  </tr>`;
}

function paxRowHtml(row) {
  const p = row.project;
  const pid = Number(p.id);
  const dev = paxDevFor(pid);
  const pct = dev ? round2(dev.percent) : null;
  const meta = launchStatusMeta(p.status);
  const badge = p.admin_only
    ? '<span class="status-pill status-admin-only">🔒 Solo-admin</span>'
    : '<span class="status-pill status-from-projects">📁 De Proyectos</span>';
  const progCell = pct == null
    ? '<span class="pax-no-prog">sin %</span>'
    : `<div class="dev-cell-prog">
         <div class="dev-bar" title="${fmtPct(pct)} completado"><div class="dev-fill" style="width:${pct}%"></div></div>
         <span class="dev-pct">${fmtPct(pct)}</span>
       </div>`;
  const total = row.net
    ? `<span class="pax-net ${row.net > 0 ? 'is-up' : 'is-down'}">${fmtDelta(row.net)}</span>`
    : '<span class="pax-net is-none">sin cambios</span>';
  // Cada celda va seguida de su fila de detalle si está desplegada, para que
  // el bloque quede justo debajo de la celda que lo abrió.
  const cellsAndDetails = row.cells.map((c) => (
    paxCellHtml(pid, c, p.name)
    + (paxOpenCells.has(`${pid}|${c.key}`) ? paxDetailHtml(pid, c, p.name) : '')
  )).join('');
  return `
    <tr class="pax-tr${row.activeDays ? ' has-activity' : ' is-quiet'}">
      <td class="pax-td-proj" data-label="Proyecto">
        <div class="dev-cell-proj">
          <div class="admin-item-thumb project-icon-wrap dev-thumb">🚧${p.icon_url ? `<img src="${escapeHtml(p.icon_url)}" alt="" data-adm-err="rm" />` : ''}</div>
          <div class="dev-cell-proj-info">
            <strong>${escapeHtml(p.name)}</strong>
            ${badge} <span class="status-pill ${meta.cls}">${escapeHtml(meta.label)}</span>
            ${row.devlogs ? `<span class="pax-row-tag">📝 ${row.devlogs} devlog${row.devlogs === 1 ? '' : 's'}</span>` : ''}
            ${row.sessions ? `<span class="pax-row-tag">🔧 ${wsCount(row.sessions, WS_SESSION_1, WS_SESSION_N)}</span>` : ''}
            ${row.paused ? `<span class="pax-row-tag is-pause">⏸ ${row.paused} pausada${row.paused === 1 ? '' : 's'}</span>` : ''}
            ${row.tramos ? `<span class="pax-row-tag is-tramos" title="Sesiones que se trabajaron en varios tramos, con pausas en el medio">⏱ ${row.tramos} por tramos</span>` : ''}
            ${row.resumed ? `<span class="pax-row-tag is-resume">🔁 ${row.resumed} retomada${row.resumed === 1 ? '' : 's'}</span>` : ''}
            ${row.incomplete ? `<span class="pax-row-tag is-warn">⚠️ ${row.incomplete} a medias</span>` : ''}
            ${row.minutes ? `<span class="pax-row-tag">⏱ ${wsMinutes(row.minutes)}</span>` : ''}
            ${row.activeDays ? `<span class="pax-row-tag">🗓️ ${row.activeDays} día${row.activeDays === 1 ? '' : 's'}</span>` : ''}
          </div>
        </div>
      </td>
      <td class="pax-td-prog" data-label="Progreso">${progCell}</td>
      ${cellsAndDetails}
      <td class="pax-td-total" data-label="Total 14 días">${total}</td>
    </tr>`;
}

// Fila de los devlogs que no afectan a ningún proyecto.
function paxGeneralRowHtml(map, days) {
  const hide = document.getElementById('pax-hide-general');
  if (hide && hide.checked) return '';
  const cells = days.map((d) => {
    const evs = map.get(`${PAX_GENERAL_PID}|${d.key}`) || [];
    const cell = { key: d.key, isToday: d.isToday, events: evs, net: 0 };
    return { cell, detail: paxOpenCells.has(`${PAX_GENERAL_PID}|${d.key}`) ? paxDetailHtml(PAX_GENERAL_PID, cell, 'Sin proyecto') : '' };
  });
  if (!cells.some((c) => c.cell.events.length)) return '';
  const html = cells.map((c) => paxCellHtml(PAX_GENERAL_PID, c.cell, 'Sin proyecto') + c.detail).join('');
  return `
    <tr class="pax-tr pax-tr-general">
      <td class="pax-td-proj" data-label="Proyecto">
        <div class="dev-cell-proj">
          <div class="admin-item-thumb project-icon-wrap dev-thumb">🌐</div>
          <div class="dev-cell-proj-info">
            <strong>Sin proyecto</strong>
            <span class="pax-row-tag">Devlogs generales del equipo</span>
          </div>
        </div>
      </td>
      <td class="pax-td-prog" data-label="Progreso"><span class="pax-no-prog">—</span></td>
      ${html}
      <td class="pax-td-total" data-label="Total 14 días"><span class="pax-net is-none">—</span></td>
    </tr>`;
}

function paxHeadHtml(days) {
  const heads = days.map((d) => `<th class="pax-th-day${d.isToday ? ' is-today' : ''}" data-day="${d.key}"
      title="${escapeHtml(paxDayLong(d.key))}">${escapeHtml(paxDayMonth(d.key))}<small>${escapeHtml(paxWeekday(d.key))}</small></th>`).join('');
  return `
    <th class="pax-th-proj">Proyecto</th>
    <th class="pax-th-prog">% actual</th>
    ${heads}
    <th class="pax-th-total" title="Suma de los avances de los 14 días">Total 14 d</th>`;
}

function paxFootHtml(totals) {
  const ev = totals.map((t) => `<td class="pax-td-foot" data-day="${t.key}">${t.events ? `<span class="pax-foot-ev${t.isToday ? ' is-today' : ''}">${t.events}</span>` : '<span class="pax-none">·</span>'}</td>`).join('');
  const min = totals.map((t) => `<td class="pax-td-foot" data-day="${t.key}">${t.minutes ? `<span class="pax-foot-min">⏱ ${wsMinutes(t.minutes)}</span>` : '<span class="pax-none">·</span>'}</td>`).join('');
  const net = totals.map((t) => `<td class="pax-td-foot" data-day="${t.key}">${t.net ? `<span class="pax-net ${t.net > 0 ? 'is-up' : 'is-down'}">${fmtDelta(t.net)}</span>` : '<span class="pax-none">·</span>'}</td>`).join('');
  const grand = round2(totals.reduce((s, t) => s + t.net, 0));
  const blank = '<th class="pax-td-foot-label is-second"><span class="hidden">—</span></th>';
  return {
    ev: `<th class="pax-td-foot-label">⚡ Eventos</th>${blank}${ev}<th class="pax-td-foot-label">${totals.reduce((s, t) => s + t.events, 0)}</th>`,
    min: `<th class="pax-td-foot-label">⏱ Tiempo</th>${blank}${min}<th class="pax-td-foot-label">${wsMinutes(totals.reduce((s, t) => s + t.minutes, 0))}</th>`,
    net: `<th class="pax-td-foot-label">📈 Neto</th>${blank}${net}<th class="pax-td-foot-label">${grand ? `<span class="pax-net ${grand > 0 ? 'is-up' : 'is-down'}">${fmtDelta(grand)}</span>` : '<span class="pax-none">·</span>'}</th>`
  };
}

// Franja resumen de los 14 días: una pastilla por día con su actividad.
// Al hacer clic se resalta esa columna en toda la tabla.
function paxDayStripHtml(totals) {
  return totals.map((t) => {
    const lv = t.events === 0 ? 0 : t.events === 1 ? 1 : t.events <= 3 ? 2 : 3;
    const extra = t.minutes ? ` · ⏱ ${wsMinutes(t.minutes)}` : '';
    return `<button type="button" class="pax-day${t.isToday ? ' is-today' : ''} lv-${lv}" data-day="${t.key}"
      title="${escapeHtml(`${paxDayLong(t.key)} · ${t.events} evento${t.events === 1 ? '' : 's'}${t.net ? ` · ${fmtDelta(t.net)}` : ''}${extra}`)}"
      data-adm-ev="click" data-adm="togglePaxDayFocus" data-adm-a0="s:${t.key}">
      <span class="pax-day-wd">${escapeHtml(paxWeekday(t.key))}</span>
      <span class="pax-day-num">${escapeHtml(paxDayMonth(t.key))}</span>
      <span class="pax-day-ev">${t.minutes ? `⏱ ${escapeHtml(wsMinutes(t.minutes))}` : (t.events ? `${t.events} ⚡` : '·')}</span>
    </button>`;
  }).join('');
}

function paxLegendHtml() {
  const order = ['devlog', 'session', 'cont', 'roll', 'up', 'down', 'note', 'incomplete', 'new', 'edit', 'launch', 'due', 'done', 'shipped'];
  return order.map((k) => {
    const m = PAX_CHIP_META[k];
    return `<span class="pax-legend-item" title="${escapeHtml(m.label)}">${m.icon}<small>${escapeHtml(m.label)}</small></span>`;
  }).join('');
}

// Opciones del <select> de proyectos (se reconstruye en cada render para
// recoger los proyectos que aparecieron en el historial).
function paxSyncFilterOptions() {
  const sel = document.getElementById('pax-filter-project');
  if (!sel) return;
  const prev = sel.value;
  const list = paxProjects();
  sel.innerHTML = '<option value="">Todos los proyectos</option>' + list.map((p) => {
    const tag = p.admin_only ? '🔒' : '📁';
    return `<option value="${p.id}">${tag} ${escapeHtml(p.name)}</option>`;
  }).join('');
  if (list.some((p) => String(p.id) === prev)) sel.value = prev;
}

function renderProjectActivity() {
  const head = document.getElementById('pax-head-row');
  const body = document.getElementById('pax-table-body');
  const empty = document.getElementById('pax-empty');
  const wrap = document.getElementById('pax-table-wrap');
  const table = document.getElementById('pax-table');
  if (!head || !body) return; // la sub-sección no existe en este documento

  const days = paxRange();
  paxTodayKey = days[0].key;
  const { rows, dayTotals, map } = paxBuild(days);

  // ── Píldoras del encabezado ──
  const last = days[days.length - 1];
  const setBadge = (id, text) => { const el = document.getElementById(id); if (el) el.textContent = text; };
  setBadge('pax-range-badge', `📅 ${paxDayMonth(last.key)} → ${paxDayMonth(days[0].key)}`);
  const totalEvents = dayTotals.reduce((s, t) => s + t.events, 0);
  const totalNet = round2(dayTotals.reduce((s, t) => s + t.net, 0));
  const totalMin = dayTotals.reduce((s, t) => s + t.minutes, 0);
  setBadge('pax-events-badge', `⚡ ${totalEvents} ${totalEvents === 1 ? 'evento' : 'eventos'}`);
  if (totalMin) setBadge('pax-time-badge', `⏱ ${wsMinutes(totalMin)}`);
  setBadge('pax-projects-badge', `🚧 ${rows.length} ${rows.length === 1 ? 'proyecto' : 'proyectos'}`);
  const netBadge = document.getElementById('pax-net-badge');
  if (netBadge) {
    netBadge.textContent = totalNet ? `📈 ${fmtDelta(totalNet)} en 14 días` : '📈 sin cambios';
    netBadge.className = 'status-pill ' + (totalNet > 0 ? 'status-on' : totalNet < 0 ? 'status-off' : 'status-off');
  }
  const syncBadge = document.getElementById('pax-sync-badge');
  if (syncBadge) syncBadge.textContent = paxLoadedAt ? `↻ ${formatDevAgo(paxLoadedAt)}` : '↻ —';

  // ── Toolbar ──
  paxSyncFilterOptions();
  const legend = document.getElementById('pax-legend');
  if (legend) legend.innerHTML = paxLegendHtml();
  const strip = document.getElementById('pax-daystrip');
  if (strip) strip.innerHTML = paxDayStripHtml(dayTotals);

  // ── Tabla ──
  head.innerHTML = paxHeadHtml(days);
  const foot = paxFootHtml(dayTotals);
  const footEvents = document.getElementById('pax-foot-events');
  const footMin = document.getElementById('pax-foot-min');
  const footNet = document.getElementById('pax-foot-net');
  if (footEvents) footEvents.innerHTML = foot.ev;
  if (footMin) footMin.innerHTML = foot.min;
  if (footNet) footNet.innerHTML = foot.net;
  // La píldora de tiempo se oculta cuando no hay sesiones registradas.
  const timeBadge = document.getElementById('pax-time-badge');
  if (timeBadge) timeBadge.classList.toggle('hidden', !totalMin);

  const bodyHtml = rows.map((r) => paxRowHtml(r)).join('')
    + paxGeneralRowHtml(map, days);
  body.innerHTML = bodyHtml;
  if (rows.length) {
    if (wrap) wrap.classList.remove('is-empty');
    if (empty) empty.classList.add('hidden');
  } else {
    if (wrap) wrap.classList.add('is-empty');
    if (empty) empty.classList.remove('hidden');
  }
  // Reaplica el resaltado de columna si había uno abierto.
  const focus = table && table.dataset.focus;
  if (focus) applyPaxDayFocus(focus);
}

// ── Interacción ──
// Despliega/oculta el detalle de una celda. Se repinta la tabla entera para
// mantener el orden de filas y el detalle justo debajo de la suya.
function togglePaxCell(pid, key) {
  const k = `${pid}|${key}`;
  if (paxOpenCells.has(k)) paxOpenCells.delete(k);
  else paxOpenCells.add(k);
  renderProjectActivity();
}

// Resalta una columna completa (franja de días ↔ tabla).
function togglePaxDayFocus(key) {
  const table = document.getElementById('pax-table');
  if (!table) return;
  if (table.dataset.focus === key) {
    delete table.dataset.focus;
    applyPaxDayFocus('');
  } else {
    table.dataset.focus = key;
    applyPaxDayFocus(key);
  }
}
function applyPaxDayFocus(key) {
  const table = document.getElementById('pax-table');
  if (!table) return;
  table.querySelectorAll('[data-day]').forEach((el) => {
    el.classList.toggle('is-focus', !!key && el.dataset.day === key);
  });
  const strip = document.getElementById('pax-daystrip');
  if (strip) {
    strip.querySelectorAll('.pax-day').forEach((b) => {
      b.classList.toggle('is-focus', !!key && b.dataset.day === key);
    });
  }
}

function onPaxFilterChange() {
  // Al cambiar el filtro se limpian los desplegados: si no, quedarían
  // detalles de proyectos que ya no se ven.
  paxOpenCells.clear();
  renderProjectActivity();
}

// ── Carga ──
// El % actual y los devlogs ya los traen loadProjectDevelopment() y
// loadDevlogs() (se reutilizan sus cachés); acá solo se pide el historial de
// avances, que hasta ahora nadie consumía.
// =======================================================
// ANALYTICS — TOPs y gráfica por rango (7 / 14 / 30 días)
// Se arma desde wsCache (sesiones, segmentos por día, cambios) y muestra:
// qué día se trabajó más (y qué admin), qué día hubo más cambios, quién
// trabajó más, quién registró más cambios, qué proyecto movió más y qué
// tipo de cambio más se usa. La gráfica es de barras hecha con divs.
// =======================================================
let analyticsDays = 14;
let analyticsTop = 'dayMinutes';

function setAnalyticsTop(id) {
  analyticsTop = id || 'dayMinutes';
  const sel = document.getElementById('an-top-select');
  if (sel && sel.value !== analyticsTop) sel.value = analyticsTop;
  renderWsAnalytics();
}

function setAnalyticsRange(days) {
  analyticsDays = [7, 14, 30].includes(Number(days)) ? Number(days) : 14;
  document.querySelectorAll('#an-range-btns .btn').forEach((b) =>
    b.classList.toggle('is-on', Number(b.dataset.days) === analyticsDays));
  renderWsAnalytics();
}

// Día local (YYYY-MM-DD) de una fecha ISO: para contar cambios por día.
function anDayKey(iso) {
  const d = new Date(iso);
  if (!Number.isFinite(d.getTime())) return '';
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

function anLastDays(n) {
  const out = [];
  const now = new Date();
  for (let i = n - 1; i >= 0; i--) {
    const d = new Date(now.getFullYear(), now.getMonth(), now.getDate() - i);
    out.push(`${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`);
  }
  return out;
}

// Junta todo: minutos por día/admin/proyecto y cantidad de cambios por
// día/autor/tipo dentro del rango. Devuelve estructuras listas para pintar.
function computeWsAnalytics(days) {
  const keys = anLastDays(days);
  const inRange = new Set(keys);
  const perDay = new Map(keys.map((k) => [k, { minutes: 0, changes: 0, admins: new Map() }]));
  const adminMinutes = new Map();   // admin → minutos
  const adminChanges = new Map();   // admin → cambios
  const projectMinutes = new Map(); // proyecto → minutos
  const kindChanges = new Map();    // tipo → cambios
  const reworkChanges = new Map();  // rework → cambios
  let sessions = 0;
  let totalChanges = 0;
  (wsCache || []).forEach((s) => {
    let touched = false;
    (s.segments || []).forEach((g) => {
      if (!g || !inRange.has(g.day)) return;
      touched = true;
      const m = Number(g.minutes) || 0;
      const row = perDay.get(g.day);
      row.minutes += m;
      const admin = (s.created_by || '—').trim() || '—';
      row.admins.set(admin, (row.admins.get(admin) || 0) + m);
      adminMinutes.set(admin, (adminMinutes.get(admin) || 0) + m);
      const proj = s.project_name || (s.project_id ? `#${s.project_id}` : 'Sin proyecto');
      projectMinutes.set(proj, (projectMinutes.get(proj) || 0) + m);
    });
    (s.changes || []).forEach((c) => {
      const k = anDayKey(c && c.at);
      if (!k || !inRange.has(k)) return;
      touched = true;
      totalChanges++;
      const row = perDay.get(k);
      row.changes++;
      const author = (c.author || '—').trim() || '—';
      adminChanges.set(author, (adminChanges.get(author) || 0) + 1);
      const label = wsChangeKindLabel(c);
      kindChanges.set(label, (kindChanges.get(label) || 0) + 1);
      if (c.rework_key) {
        const rw = (s.reworks || []).find((r) => r && r.key === c.rework_key);
        const rwName = (rw && rw.name) || c.rework_key;
        reworkChanges.set(rwName, (reworkChanges.get(rwName) || 0) + 1);
      }
    });
    if (touched) sessions++;
  });
  const bump = (map) => [...map.entries()].sort((a, b) => b[1] - a[1]);
  const dayMinutes = keys.map((k) => ({ day: k, ...perDay.get(k) }));
  const topDayMinutes = [...dayMinutes].sort((a, b) => b.minutes - a.minutes)[0];
  const topDayChanges = [...dayMinutes].sort((a, b) => b.changes - a.changes)[0];
  const topAdminOfDay = (row) => (row && row.admins.size)
    ? [...row.admins.entries()].sort((a, b) => b[1] - a[1])[0]
    : null;
  return {
    keys, dayMinutes, sessions, totalChanges,
    topDayMinutes, topDayChanges, topAdminOfDay,
    adminsByMinutes: bump(adminMinutes),
    adminsByChanges: bump(adminChanges),
    projectsByMinutes: bump(projectMinutes),
    kindsByChanges: bump(kindChanges),
    reworksByChanges: bump(reworkChanges),
    daysByMinutes: [...dayMinutes].sort((a, b) => b.minutes - a.minutes),
    daysByChanges: [...dayMinutes].sort((a, b) => b.changes - a.changes)
  };
}

// Tarjeta de ranking grande: ocupa todo el ancho, cada fila lleva una barra
// proporcional al líder, puesto con medallas. Sin datos → "Sin Información".
function anRankBoard(rows, fmt) {
  if (!rows.length) return `<p class="an-rank-empty">Sin Información</p>`;
  const max = Math.max(1, ...rows.map(([, v]) => Number(v) || 0));
  return `<ol class="an-board">${rows.slice(0, 12).map(([name, val], i) => {
    const pct = Math.max(4, Math.round(((Number(val) || 0) / max) * 100));
    const medal = i === 0 ? '🥇' : i === 1 ? '🥈' : i === 2 ? '🥉' : `${i + 1}.`;
    return `<li>
      <span class="an-board-pos">${medal}</span>
      <div class="an-board-main">
        <div class="an-board-row">
          <span class="an-board-name" title="${escapeHtml(String(name))}">${escapeHtml(String(name))}</span>
          <b class="an-board-val">${escapeHtml(fmt(val))}</b>
        </div>
        <div class="an-board-track"><i style="width:${pct}%"></i></div>
      </div>
    </li>`;
  }).join('')}</ol>`;
}

function anTipShow(e, html) {
  const tip = document.getElementById('an-tip');
  if (!tip) return;
  // glass-card usa backdrop-filter, que rompe el position:fixed: el tooltip
  // tiene que vivir directo en <body>.
  if (tip.parentElement !== document.body) document.body.appendChild(tip);
  tip.innerHTML = html;
  tip.classList.remove('hidden');
  let x = e.clientX + 14;
  let y = e.clientY - tip.offsetHeight - 12;
  if (x + tip.offsetWidth > window.innerWidth - 8) x = e.clientX - tip.offsetWidth - 14;
  if (y < 8) y = e.clientY + 18;
  tip.style.left = `${x}px`;
  tip.style.top = `${y}px`;
}
function anTipHide() {
  const tip = document.getElementById('an-tip');
  if (tip) tip.classList.add('hidden');
}

function renderWsAnalytics(reload) {
  const chart = document.getElementById('an-chart');
  const board = document.getElementById('an-top-single');
  if (!chart || !board) return;
  if (reload) loadWorkSessions();
  const a = computeWsAnalytics(analyticsDays);
  const maxMin = Math.max(1, ...a.dayMinutes.map((d) => d.minutes));
  const maxChg = Math.max(1, ...a.dayMinutes.map((d) => d.changes));
  chart.innerHTML = `<div class="an-bars">${a.dayMinutes.map((d) => `
      <div class="an-col" onmousemove="anTipShow(event,'${wsShortDay(d.day)} · <b>${wsMinutes(d.minutes)}</b> · ${d.changes} cambio${d.changes === 1 ? '' : 's'}')" onmouseleave="anTipHide()">
        <div class="an-col-bars">
          <i class="an-bar an-bar-min" style="height:${Math.round((d.minutes / maxMin) * 100)}%"></i>
          <i class="an-bar an-bar-chg" style="height:${Math.round((d.changes / maxChg) * 100)}%"></i>
        </div>
        <span class="an-col-day">${escapeHtml(wsShortDay(d.day))}</span>
      </div>`).join('')}</div>`;
  const range = document.getElementById('an-range-badge');
  if (range) range.textContent = `📅 Últimos ${analyticsDays} días`;
  const sb = document.getElementById('an-sessions-badge');
  if (sb) sb.textContent = `⏱ ${a.sessions} sesión${a.sessions === 1 ? '' : 'es'}`;
  const cb = document.getElementById('an-changes-badge');
  if (cb) cb.textContent = `⏺ ${a.totalChanges} cambio${a.totalChanges === 1 ? '' : 's'}`;
  const dayMinRows = a.daysByMinutes.filter((d) => d.minutes > 0).map((d) => {
    const topAdm = a.topAdminOfDay(d);
    return [wsShortDay(d.day) + (topAdm ? ` · ${topAdm[0]}` : ''), d.minutes];
  });
  const dayChgRows = a.daysByChanges.filter((d) => d.changes > 0).map((d) => [wsShortDay(d.day), d.changes]);
  const boards = {
    dayMinutes: [dayMinRows, (m) => `⏱ ${wsMinutes(m)}`],
    dayChanges: [dayChgRows, (n) => `${n} cambio${n === 1 ? '' : 's'}`],
    adminMinutes: [a.adminsByMinutes, (m) => `⏱ ${wsMinutes(m)}`],
    adminChanges: [a.adminsByChanges, (n) => `⏺ ${n} cambio${n === 1 ? '' : 's'}`],
    projects: [a.projectsByMinutes, (m) => `⏱ ${wsMinutes(m)}`],
    kinds: [a.kindsByChanges, (n) => `⏺ ${n} registro${n === 1 ? '' : 's'}`],
    reworks: [a.reworksByChanges, (n) => `⏺ ${n} cambio${n === 1 ? '' : 's'}`]
  };
  const b = boards[analyticsTop] || boards.dayMinutes;
  board.innerHTML = anRankBoard(b[0], b[1]);
  try { renderAnalyticsEffort(); } catch (_) {}
}

// =======================================================
// ANALYTICS — HISTÓRICO DE SUBIDAS DE % + ESFUERZO POR ADMIN
// Apartado por proyecto con TODOS los días en los que subió el %,
// sin recorte a 7/14/30 días. Fuente: paxHistoryCache (movimientos de %)
// + wsCache (minutos/sesiones/cambios) + devlogsCache + devProgressCache.
// El puntaje de esfuerzo por admin (0-100) combina:
//   40% % aportado · 25% tiempo · 15% sesiones · 10% cambios+devlogs
//   · 10% constancia (días distintos con aporte/trabajo).
// =======================================================
let analyticsEffortPid = '';

function setAnalyticsEffortProject(pid) {
  analyticsEffortPid = String(pid || '');
  const sel = document.getElementById('an-effort-project');
  if (sel && sel.value !== analyticsEffortPid) sel.value = analyticsEffortPid;
  renderAnalyticsEffort();
}

async function reloadAnalyticsEffort() {
  const chart = document.getElementById('an-effort-chart');
  if (chart) chart.innerHTML = '<p class="loading-note">Cargando historial completo…</p>';
  try { if (!paxHistoryCache.length) await loadProjectActivity(false); } catch (_) {}
  try { if (!wsCache.length) await loadWorkSessions(); } catch (_) {}
  try { if (!devlogsCache.length) await loadDevlogs(); } catch (_) {}
  try { if (!devProgressCache.length) await loadProjectDevelopment(); } catch (_) {}
  // Si el selector sigue vacío, se elige el proyecto con más subida acumulada.
  if (!analyticsEffortPid) {
    const best = analyticsEffortTopProject();
    if (best) analyticsEffortPid = String(best);
  }
  renderAnalyticsEffort();
  showToast('✔ Histórico de subidas actualizado');
}

// Proyectos conocidos (Gestión + públicos + historial + desarrollo): para el selector.
function analyticsEffortProjects() {
  const seen = new Map();
  const add = (id, extra) => {
    const pid = Number(id || 0);
    if (!Number.isFinite(pid) || pid <= 0 || seen.has(pid)) return;
    seen.set(pid, { id: pid, name: `#${pid}`, ...extra });
  };
  (manageProjectsCache || []).forEach((p) => {
    if (!p) return;
    add(p.id, { name: p.name || p.slug || `#${p.id}`, admin_only: isAdminOnlyProject(p) });
  });
  (projectsCache || []).forEach((p) => {
    if (!p) return;
    add(p.id, { name: p.name || p.slug || `#${p.id}`, admin_only: isAdminOnlyProject(p) });
  });
  (devProgressCache || []).forEach((d) => add(d.project_id, {
    name: d.name || d.slug || `#${d.project_id}`, admin_only: !!d.admin_only
  }));
  (paxHistoryCache || []).forEach((h) => add(h.project_id, {
    name: h.project_name || `#${h.project_id}`, admin_only: h.admin_only === true
  }));
  return [...seen.values()].sort((a, b) => String(a.name).localeCompare(String(b.name), 'es'));
}

// Día local YYYY-MM-DD de un ISO (misma convención que la bitácora).
function anEffortDayKey(iso) {
  try {
    if (typeof paxKeyOf === 'function') {
      const k = paxKeyOf(iso);
      if (k) return k;
    }
  } catch (_) {}
  return anDayKey(iso);
}

function anEffortLongDay(key) {
  try {
    if (typeof paxDayLong === 'function') return paxDayLong(key);
  } catch (_) {}
  const m = String(key || '').match(/^(\d{4})-(\d{2})-(\d{2})$/);
  return m ? `${m[3]}/${m[2]}/${m[1]}` : String(key || '—');
}

// Proyecto con más % acumulado en subidas (para preseleccionar algo útil).
function analyticsEffortTopProject() {
  const acc = new Map();
  (paxHistoryCache || []).forEach((h) => {
    const d = round2(h.delta || 0);
    if (d <= 0) return;
    const pid = Number(h.project_id || 0);
    if (!pid) return;
    acc.set(pid, (acc.get(pid) || 0) + d);
  });
  let best = 0;
  let bestPid = 0;
  acc.forEach((v, k) => { if (v > best) { best = v; bestPid = k; } });
  if (bestPid) return bestPid;
  const list = analyticsEffortProjects();
  return list.length ? list[0].id : 0;
}

function anEffortLevelOf(score) {
  const n = Number(score) || 0;
  if (n >= 80) return { icon: '🔥', label: 'Esfuerzo excepcional', cls: 'is-fire' };
  if (n >= 60) return { icon: '💪', label: 'Esfuerzo alto', cls: 'is-high' };
  if (n >= 40) return { icon: '👍', label: 'Esfuerzo medio', cls: 'is-mid' };
  if (n >= 20) return { icon: '🌱', label: 'Esfuerzo bajo', cls: 'is-low' };
  if (n > 0) return { icon: '💤', label: 'Esfuerzo mínimo', cls: 'is-min' };
  return { icon: '▫️', label: 'Sin aporte', cls: 'is-none' };
}

// Cálculo central: días con subida + métricas por admin + nivel global.
// Solo entran los movimientos con delta > 0 (días en los que realmente subió).
function computeAnalyticsEffort(pid) {
  const id = Number(pid || 0);
  const moves = (paxHistoryCache || []).filter((h) => Number(h.project_id || 0) === id && round2(h.delta || 0) > 0);
  const byDay = new Map();
  moves.forEach((h) => {
    const key = anEffortDayKey(h.created_at);
    if (!key) return;
    if (!byDay.has(key)) byDay.set(key, { key, total: 0, moves: [] });
    const row = byDay.get(key);
    const d = round2(h.delta || 0);
    row.total = round2(row.total + d);
    row.moves.push(h);
  });
  const days = [...byDay.values()].sort((a, b) => a.key.localeCompare(b.key));
  const totalUp = round2(days.reduce((s, d) => s + d.total, 0));
  const bestDay = days.slice().sort((a, b) => b.total - a.total)[0] || null;

  // Métricas por admin dentro de ESTE proyecto.
  const admins = new Map();
  const adm = (name) => {
    const n = String(name || '—').trim() || '—';
    if (!admins.has(n)) admins.set(n, {
      name: n, pct: 0, minutes: 0, sessions: 0, changes: 0, devlogs: 0, days: new Set()
    });
    return admins.get(n);
  };
  moves.forEach((h) => {
    const a = adm(h.created_by);
    const d = round2(h.delta || 0);
    a.pct = round2(a.pct + d);
    const k = anEffortDayKey(h.created_at);
    if (k) a.days.add(k);
  });
  (wsCache || []).forEach((s) => {
    if (Number(s.project_id || 0) !== id) return;
    const who = String(s.created_by || '—').trim() || '—';
    const a = adm(who);
    a.sessions += 1;
    (s.segments || []).forEach((g) => {
      if (!g || !g.day) return;
      a.minutes += Number(g.minutes) || 0;
      a.days.add(g.day);
    });
    (s.changes || []).forEach((c) => {
      const author = String((c && c.author) || who).trim() || '—';
      const ax = adm(author);
      ax.changes += 1;
      const k = anEffortDayKey(c && c.at);
      if (k) ax.days.add(k);
    });
  });
  (devlogsCache || []).forEach((d) => {
    if (!d || !d.affects_project) return;
    if (Number(d.project_id || 0) !== id) return;
    const who = String(d.created_by || '—').trim() || '—';
    const a = adm(who);
    a.devlogs += 1;
    const k = anEffortDayKey(d.created_at);
    if (k) a.days.add(k);
  });

  const rows = [...admins.values()].map((a) => ({ ...a, contrib: a.changes + a.devlogs, daysCount: a.days.size }));
  const maxPct = Math.max(0, ...rows.map((r) => r.pct));
  const maxMin = Math.max(0, ...rows.map((r) => r.minutes));
  const maxSes = Math.max(0, ...rows.map((r) => r.sessions));
  const maxCon = Math.max(0, ...rows.map((r) => r.contrib));
  const maxDay = Math.max(0, ...rows.map((r) => r.daysCount));
  const scored = rows.map((r) => {
    const sPct = maxPct ? (r.pct / maxPct) * 40 : 0;
    const sMin = maxMin ? (r.minutes / maxMin) * 25 : 0;
    const sSes = maxSes ? (r.sessions / maxSes) * 15 : 0;
    const sCon = maxCon ? (r.contrib / maxCon) * 10 : 0;
    const sDay = maxDay ? (r.daysCount / maxDay) * 10 : 0;
    const score = Math.round((sPct + sMin + sSes + sCon + sDay) * 10) / 10;
    return { ...r, score, level: anEffortLevelOf(score) };
  }).sort((a, b) => b.score - a.score || b.pct - a.pct || b.minutes - a.minutes);

  // Nivel global del proyecto: combina avance total, constancia, tiempo y sesiones.
  const dev = (devProgressCache || []).find((d) => Number(d.project_id) === id) || null;
  const currentPct = dev ? round2(dev.percent) : null;
  const minutesTotal = rows.reduce((s, r) => s + r.minutes, 0);
  const sessionsTotal = rows.reduce((s, r) => s + r.sessions, 0);
  const projScore = Math.round((
    Math.min(1, totalUp / 100) * 50 +
    Math.min(1, days.length / 15) * 20 +
    Math.min(1, minutesTotal / 2000) * 15 +
    Math.min(1, sessionsTotal / 30) * 15
  ) * 10) / 10;
  return {
    pid: id, days, totalUp, bestDay,
    activeDays: days.length, movesCount: moves.length,
    perAdmin: scored, minutesTotal, sessionsTotal,
    changesTotal: rows.reduce((s, r) => s + r.changes, 0),
    devlogsTotal: rows.reduce((s, r) => s + r.devlogs, 0),
    currentPct, projScore, projLevel: anEffortLevelOf(projScore)
  };
}

function syncEffortProjectOptions() {
  const sel = document.getElementById('an-effort-project');
  if (!sel) return;
  const list = analyticsEffortProjects();
  const prev = analyticsEffortPid || sel.value || '';
  sel.innerHTML = '<option value="">— Elegí un proyecto —</option>' + list.map((p) => {
    const tag = p.admin_only ? '🔒' : '📁';
    return `<option value="${p.id}">${tag} ${escapeHtml(p.name)}</option>`;
  }).join('');
  if (prev && list.some((p) => String(p.id) === String(prev))) {
    sel.value = String(prev);
    analyticsEffortPid = String(prev);
  }
}

function renderAnalyticsEffort() {
  const chart = document.getElementById('an-effort-chart');
  const daysBox = document.getElementById('an-effort-days');
  const board = document.getElementById('an-effort-board');
  const badges = document.getElementById('an-effort-badges');
  const levelBox = document.getElementById('an-effort-project-level');
  if (!chart || !board) return;
  syncEffortProjectOptions();
  let pid = Number(analyticsEffortPid || 0);
  // Sin selección pero con historial: se preselecciona el proyecto con más
  // subida acumulada para que la gráfica no quede vacía al entrar.
  if (!pid && (paxHistoryCache || []).length) {
    const best = analyticsEffortTopProject();
    if (best) {
      analyticsEffortPid = String(best);
      syncEffortProjectOptions();
      pid = Number(analyticsEffortPid || 0);
    }
  }
  if (!pid) {
    if (badges) badges.innerHTML = '<span class="status-pill status-off">📈 Sin proyecto seleccionado</span>';
    chart.innerHTML = '<p class="loading-note">Elegí un proyecto para ver su histórico de subidas…</p>';
    if (daysBox) daysBox.innerHTML = '';
    board.innerHTML = '<p class="an-rank-empty">Sin Información</p>';
    if (levelBox) levelBox.innerHTML = '';
    return;
  }
  const r = computeAnalyticsEffort(pid);
  const projName = (analyticsEffortProjects().find((p) => Number(p.id) === pid) || {}).name || `#${pid}`;

  if (badges) {
    badges.innerHTML = [
      `<span class="status-pill status-admin-only">🎯 ${escapeHtml(projName)}</span>`,
      `<span class="status-pill status-on">📈 ${fmtDelta(r.totalUp)} acumulado en subidas</span>`,
      `<span class="status-pill status-off">🗓️ ${r.activeDays} día${r.activeDays === 1 ? '' : 's'} con subida</span>`,
      r.currentPct == null ? '<span class="status-pill status-off">% actual: —</span>' : `<span class="status-pill status-off">% actual: ${fmtPct(r.currentPct)}</span>`,
      r.bestDay ? `<span class="status-pill status-off">🔥 Mejor día: ${escapeHtml(wsShortDay(r.bestDay.key))} (${fmtDelta(r.bestDay.total)})</span>` : ''
    ].filter(Boolean).join('');
  }

  if (!r.days.length) {
    chart.innerHTML = '<p class="loading-note">Este proyecto todavía no tiene días con subida de %. Cuando se registre un avance con delta positivo aparece acá.</p>';
    if (daysBox) daysBox.innerHTML = '';
  } else {
    const max = Math.max(0.01, ...r.days.map((d) => d.total));
    chart.innerHTML = `<div class="an-bars an-effort-bars">${r.days.map((d) => {
      const h = Math.max(4, Math.round((d.total / max) * 100));
      const who = [...new Set(d.moves.map((m) => m.created_by || '—'))].join(', ');
      const tip = `${anEffortLongDay(d.key)} · ${fmtDelta(d.total)} por ${who}`;
      return `<div class="an-col" title="${escapeHtml(tip)}">
        <div class="an-col-bars"><i class="an-bar an-bar-up" style="height:${h}%"></i></div>
        <span class="an-col-day">${escapeHtml(wsShortDay(d.key))}</span>
        <span class="an-col-val">+${escapeHtml(String(round2(d.total)))}%</span>
      </div>`;
    }).join('')}</div>`;
    if (daysBox) {
      const desc = r.days.slice().reverse();
      daysBox.innerHTML = `<table class="an-effort-table">
        <thead><tr><th>Día</th><th>Subió</th><th>De → A</th><th>Quién</th><th>Nota / modo</th></tr></thead>
        <tbody>${desc.map((d) => {
          const who = [...new Set(d.moves.map((m) => String(m.created_by || '—')))].map(escapeHtml).join(', ');
          const range = d.moves.map((m) => `${fmtPct(m.percent_before)} → ${fmtPct(m.percent_after)}`).map(escapeHtml).join('<br>');
          const notes = d.moves.map((m) => {
            const note = String(m.note || '').trim();
            const mode = m.mode === 'total' ? '🎯 total' : '📅 día';
            return escapeHtml(note ? `${mode} · ${note}` : mode);
          }).join('<br>');
          return `<tr>
            <td data-label="Día"><b>${escapeHtml(anEffortLongDay(d.key))}</b></td>
            <td data-label="Subió"><span class="pax-net is-up">${fmtDelta(d.total)}</span></td>
            <td data-label="De → A">${range}</td>
            <td data-label="Quién">👤 ${who}</td>
            <td data-label="Nota">${notes}</td>
          </tr>`;
        }).join('')}</tbody>
      </table>
      <p class="form-hint">Histórico completo: ${r.movesCount} subida${r.movesCount === 1 ? '' : 's'} en ${r.activeDays} día${r.activeDays === 1 ? '' : 's'} (hasta 300 movimientos recientes según el servidor).</p>`;
    }
  }

  if (!r.perAdmin.length) {
    board.innerHTML = '<p class="an-rank-empty">Sin Información</p>';
  } else {
    const max = Math.max(1, ...r.perAdmin.map((a) => a.score));
    board.innerHTML = `<ol class="an-board an-effort-board">${r.perAdmin.map((a, i) => {
      const medal = i === 0 ? '🥇' : i === 1 ? '🥈' : i === 2 ? '🥉' : `${i + 1}.`;
      const w = Math.max(4, Math.round((a.score / max) * 100));
      return `<li class="an-effort-row ${a.level.cls}">
        <span class="an-board-pos">${medal}</span>
        <div class="an-board-main">
          <div class="an-board-row">
            <span class="an-board-name" title="${escapeHtml(a.name)}">👤 ${escapeHtml(a.name)}</span>
            <b class="an-board-val">${a.level.icon} ${escapeHtml(a.level.label)} · ${a.score} pts</b>
          </div>
          <div class="an-board-track"><i style="width:${w}%"></i></div>
          <div class="an-effort-meta">
            <span title="Suma de deltas positivos registrados por este admin">📈 ${fmtDelta(a.pct)} aportado</span>
            <span title="Minutos en sesiones de este proyecto">⏱ ${wsMinutes(a.minutes)}</span>
            <span title="Sesiones de este proyecto">🔧 ${a.sessions} ${a.sessions === 1 ? 'sesión' : 'sesiones'}</span>
            <span title="Cambios en sesiones + entradas de devlog">📝 ${a.contrib} (${a.changes} cambios + ${a.devlogs} devlogs)</span>
            <span title="Días distintos con aporte o trabajo">🗓️ ${a.daysCount} ${a.daysCount === 1 ? 'día' : 'días'}</span>
          </div>
        </div>
      </li>`;
    }).join('')}</ol>`;
  }

  if (levelBox) {
    levelBox.innerHTML = `<div class="an-effort-level ${r.projLevel.cls}">
      <span class="an-effort-level-icon">${r.projLevel.icon}</span>
      <div>
        <b>Nivel global del proyecto: ${escapeHtml(r.projLevel.label)} (${r.projScore} pts)</b>
        <p>Según cuánto subió en general (${fmtDelta(r.totalUp)} en ${r.activeDays} día${r.activeDays === 1 ? '' : 's'}) + ${wsMinutes(r.minutesTotal)} en ${r.sessionsTotal} ${r.sessionsTotal === 1 ? 'sesión' : 'sesiones'} + ${r.changesTotal} cambios + ${r.devlogsTotal} devlogs. Fórmula global: 50% avance total (sobre 100%) · 20% constancia (sobre 15 días) · 15% tiempo (sobre ~33 h) · 15% sesiones (sobre 30).</p>
      </div>
    </div>`;
  }
}

async function loadProjectActivity(manual) {
  if (!document.getElementById('pax-table-body')) return;
  if (!(await requireAuth())) return;
  const empty = document.getElementById('pax-empty');
  try {
    const res = await adminFetch(API_BASE + `/ows-project-development/history?limit=300`);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Error (${res.status})`);
    paxHistoryCache = Array.isArray(data.history) ? data.history : [];
    paxLoadedAt = new Date().toISOString();
    renderProjectActivity();
    startPaxAutoRefresh();
    if (manual) {
      const n = paxHistoryCache.length;
      showToast(`✔ Bitácora actualizada: ${n} ${n === 1 ? 'movimiento' : 'movimientos'} en el historial`);
    }
  } catch (err) {
    const body = document.getElementById('pax-table-body');
    if (body) body.innerHTML = '';
    const head = document.getElementById('pax-head-row');
    if (head) head.innerHTML = '';
    if (empty) {
      empty.classList.remove('hidden');
      const t = empty.querySelector('.news-empty-title');
      const s = empty.querySelector('.news-empty-sub');
      if (t) t.textContent = 'No se pudo cargar la bitácora';
      if (s) s.textContent = err.message || 'Revisá tu conexión.';
    }
  }
}

// Refresco automático: la tabla se mantiene al día sola mientras la
// sub-sección esté a la vista (si no, no se gastan pedidos).
function startPaxAutoRefresh() {
  if (paxAutoTimer) return;
  paxAutoTimer = setInterval(() => {
    const pane = document.getElementById('manage-sub-activity');
    if (!pane || pane.classList.contains('hidden')) return;
    loadProjectActivity(false);
  }, PAX_REFRESH_MS);
}

// Cambio de día: al pasar la medianoche la ventana debe correrse sola
// (entra la columna de hoy y sale la del día 14). Se revisa cada minuto,
// que es lo que tarda como mucho en notarse.
if (!window._paxDayTimer) {
  window._paxDayTimer = setInterval(() => {
    const k = paxKeyFromDate(new Date());
    if (paxTodayKey && k !== paxTodayKey) {
      paxTodayKey = k;
      // Se limpian los desplegados porque las claves de día ya no coinciden.
      paxOpenCells.clear();
      renderProjectActivity();
    }
  }, 60000);
}

// =======================================================
// INIT
// =======================================================

document.addEventListener('DOMContentLoaded', async () => {
  setupEventImagePreview();
  setupNewsImagePreview();
  setupNewsFormShortcuts();
  setupProjectImageInputs();
  // Sesiones de trabajo: el campo de % admite decimales y el reloj arranca
  // aunque la sub-sección esté oculta (solo pinta si está a la vista).
  bindDecBlur('ws-delta-num', 100);
  wsDay = wsTodayKey();
  try { syncWsDayInputs(); } catch (_) {}
  try { syncWsTimelineModeUI(); } catch (_) {}
  try {
    const vis = document.getElementById('event-visible');
    if (vis && !vis.dataset.bound) {
      vis.dataset.bound = '1';
      vis.addEventListener('change', updateEventLivePreview);
    }
    updateEventLivePreview();
  } catch (_) {}
  // Puerta del panel: sin una sesión de administración válida en este
  // navegador, el panel ni siquiera se muestra: vuelve al dashboard.
  if (!isAdminPanelSession()) {
    showToast('⛔ Acceso restringido: se requiere una sesión de administración para abrir el panel.');
    setTimeout(() => { window.location.href = '../index.html'; }, 1200);
    return;
  }
  // 1) Token aún vigente — entrar directo, SIN pedir nada ni tocar la red.
  //    Esto es lo que evita que se pida login en cada recarga.
  if (adminToken && isAdminJwtValid(adminToken)) {
    openPanel();
    return;
  }
  // 2) Token ausente o vencido — intentar restaurar en silencio con el
  //    dispositivo de confianza (30 días, ventana deslizante). Solo si hay
  //    trust_token guardado se hace la petición; si no, ni se intenta.
  if (getTrustToken()) {
    // Ocultar el login mientras se restaura para no parpadear el formulario
    document.getElementById('admin-login').classList.add('hidden');
    const restored = await tryLoginWithDevice();
    if (restored) {
      openPanel();
      return;
    }
  }
  // 3) Sin token válido ni confianza: login manual de 3 pasos (una sola vez).
  adminToken = '';
  localStorage.removeItem(ADMIN_TOKEN_KEY);
  showLoginView();
});

/* ═══════════════════════════════════════════════════════════════
   ADMIN — dispatcher centralizado (sin inline handlers: el WebView
   de Tauri no compila atributos on*). Los templates usan
   data-adm="fn" + data-adm-a0..an con valores codificados:
     ev | th | thp:value|checked|dataset.X | n:123 | b:1/0 | x:
     o:inline | s:texto | r:valor-runtime (numérico→Number)
   + data-adm-ev="click|submit|change|input|keydown"
   + data-adm-key="Enter|Space" (filtro de teclas en keydown)
   + data-adm-stop / data-adm-href / data-adm-drop / data-adm-overlay-*
   + data-adm-err="rm|closest:SEL|CLS" (imágenes rotas)
   ═══════════════════════════════════════════════════════════════ */

function coerceAdmArg(raw, el, e) {
  if (raw === 'ev') return e;
  if (raw === 'th') return el;
  if (raw.indexOf('thp:') === 0) {
    const p = raw.slice(4);
    if (p === 'value') return el.value;
    if (p === 'checked') return el.checked;
    if (p.indexOf('dataset.') === 0) return el.dataset ? el.dataset[p.slice(8)] : undefined;
    return undefined;
  }
  if (raw.indexOf('n:') === 0) return Number(raw.slice(2));
  if (raw.indexOf('b:') === 0) return raw.slice(2) === '1';
  if (raw.indexOf('x:') === 0) return null;
  if (raw.indexOf('o:inline') === 0) return { inline: true };
  if (raw.indexOf('s:') === 0) return raw.slice(2);
  if (raw.indexOf('r:') === 0) {
    const v = raw.slice(2);
    if (/^-?\d+(\.\d+)?$/.test(v)) return Number(v);
    return v;
  }
  return raw;
}

function dispatchAdm(el, e) {
  if (!el) return;
  if (el.hasAttribute('data-adm-stop')) { e.stopPropagation(); return; }
  if (el.hasAttribute('data-adm-href')) { window.location.href = el.getAttribute('data-adm-href'); return; }
  if (el.hasAttribute('data-adm-drop')) {
    const notId = el.getAttribute('data-adm-drop-not');
    if (e.target && e.target.id !== notId) {
      const t = document.getElementById(el.getAttribute('data-adm-drop'));
      if (t) t.click();
    }
    return;
  }
  if (el.hasAttribute('data-adm-overlay-fn')) {
    if (e.target && e.target.id === el.getAttribute('data-adm-overlay-id')) {
      const f = window[el.getAttribute('data-adm-overlay-fn')];
      if (typeof f === 'function') f.call(el, e);
    }
    return;
  }
  const fnName = el.getAttribute('data-adm');
  if (!fnName) return;
  const fn = window[fnName];
  if (typeof fn !== 'function') return;
  const args = [];
  for (let i = 0; ; i++) {
    const a = el.getAttribute('data-adm-a' + i);
    if (a === null) break;
    args.push(coerceAdmArg(a, el, e));
  }
  fn.apply(el, args);
}

function bindAdminDispatch() {
  ['click', 'submit', 'change', 'input', 'keydown'].forEach((t) => {
    document.addEventListener(t, (e) => {
      const el = e.target && e.target.closest
        ? e.target.closest('[data-adm],[data-adm-stop],[data-adm-href],[data-adm-drop],[data-adm-overlay-fn]')
        : null;
      if (!el || !document.contains(el)) return;
      // Un mismo elemento puede escuchar varios eventos: "input|keydown".
      const want = el.getAttribute('data-adm-ev');
      if (want && want.split('|').indexOf(t) === -1) return;
      if (t === 'keydown' && el.hasAttribute('data-adm-key')) {
        const keys = el.getAttribute('data-adm-key').split('|');
        if (keys.indexOf(e.key) === -1 && keys.indexOf(e.code) === -1) return;
        e.preventDefault();
      }
      dispatchAdm(el, e);
    });
  });
  // Imágenes rotas en contenido generado
  document.addEventListener('error', (e) => {
    const t = e.target;
    if (!t || t.tagName !== 'IMG') return;
    const mode = t.getAttribute && t.getAttribute('data-adm-err');
    if (!mode) return;
    if (mode === 'rm') { t.remove(); return; }
    const m = /^closest:(.+)\|(.+)$/.exec(mode);
    if (m) {
      const c = t.closest(m[1]);
      if (c) c.classList.add(m[2]);
      t.remove();
    }
  }, true);
}

// Wrappers para llamadas multi-sentencia / expresiones no triviales
function admUpdateNewsCountersAndPreview() { updateNewsCounters(); updateNewsPreview(); }
function admReloadManage() { loadAdminManage(); loadProjectDevelopment(true); }
function admSetWsDayToday() { setWsDayKey(paxKeyFromDate(new Date()), true); }
function admCloseWsAndRealtime() { closeWsForm(); openWsRealtimeForm(); }
function admCloseDevlogAndDelete(id) { closeDevlogModal(); deleteDevlog(id); }
function admCloseIncidentAndReopen(id) { closeIncidentModal(); reopenIncident(id); }
function admCloseReportAndReopen(id) { closeReportModal(); reopenReport(id); }
function admClearWsPresetInline(sid) {
  const p = document.getElementById('ws-change-preset-inline-' + sid);
  if (p && this.value !== 'custom') p.value = '';
}

document.addEventListener('DOMContentLoaded', bindAdminDispatch);

/* ═══════════════════════════════════════════════════════════════
   FORM-MODAL genérico: los [data-mform] viven ocultos en su grilla
   y se mudan a #form-modal-body al crear/editar. Al cerrar vuelven
   a su lugar. Se usa en Noticias, Eventos, Modales, Presets,
   Proyectos, Gestión, Incidentes, Informes y Usuarios.
   ═══════════════════════════════════════════════════════════════ */

const ADM_FORM_MODAL = {
  news:     { eyebrow: 'Noticias · Formulario', focus: 'news-title', titleSel: '#news-form-title' },
  quicknews:{ eyebrow: 'Noticias Rápidas · Formulario', focus: 'qnews-text', titleSel: '#qnews-form-title' },
  event:    { eyebrow: 'Eventos · Formulario', focus: 'event-title', titleSel: '#event-form-title' },
  popup:    { eyebrow: 'Modales · Formulario', focus: 'popup-title', titleSel: '#popup-form-title' },
  preset:   { eyebrow: 'Presets · Formulario', focus: 'preset-name', titleSel: '#preset-form-title' },
  project:  { eyebrow: 'Proyectos · Formulario', focus: 'proj-slug', titleSel: '[data-mform="project"] > h3.form-title' },
  manage:   { eyebrow: 'Gestión · Formulario', focus: 'mproj-slug', titleSel: '#manage-form-title' },
  incident: { eyebrow: 'Incidentes · Formulario', focus: 'inc-title', titleSel: '#inc-form-title', extraPreview: 'inc-preview' },
  report:   { eyebrow: 'Informes · Formulario', focus: 'rep-title', titleSel: '#rep-form-title', extraPreview: 'rep-preview' },
  user:     { eyebrow: 'Usuarios · Formulario', focus: 'new-username', titleSel: '#user-form-title' },
};
let admFormModalHome = null;
let admFormModalKey = '';

function openFormModal(key) {
  const cfg = ADM_FORM_MODAL[key];
  const overlay = document.getElementById('form-modal');
  const body = document.getElementById('form-modal-body');
  if (!cfg || !overlay || !body) return;
  if (admFormModalKey && admFormModalKey !== key) closeFormModal();
  if (!admFormModalHome) {
    const form = document.querySelector(`[data-mform="${key}"]`);
    if (!form) return;
    admFormModalHome = { form, parent: form.parentNode, next: form.nextSibling, extras: [] };
    if (cfg.extraPreview) {
      const prev = document.getElementById(cfg.extraPreview);
      const card = prev ? prev.closest('.glass-card') : null;
      if (card) admFormModalHome.extras.push({ el: card, parent: card.parentNode, next: card.nextSibling });
    }
    body.appendChild(form);
    admFormModalHome.extras.forEach((x) => body.appendChild(x.el));
  }
  admFormModalKey = key;
  const eb = document.getElementById('form-modal-eyebrow');
  if (eb) eb.textContent = cfg.eyebrow;
  // El título del modal refleja el estado del form (Nuevo / Editando: …)
  try {
    const src = cfg.titleSel ? document.querySelector(cfg.titleSel) : null;
    const mt = document.getElementById('form-modal-title');
    if (mt) mt.textContent = src ? src.textContent.trim().replace(/^[✨✏️🚨📋➕🔒💾🛡️]+\s*/u, '') : 'Formulario';
  } catch (_) {}
  overlay.classList.remove('hidden');
  try { document.body.style.overflow = 'hidden'; } catch (_) {}
  setTimeout(() => {
    const f = cfg.focus ? document.getElementById(cfg.focus) : null;
    if (f && !f.disabled) { try { f.focus({ preventScroll: true }); } catch (_) { try { f.focus(); } catch (_) {} } }
  }, 90);
}

function closeFormModal() {
  const overlay = document.getElementById('form-modal');
  const h = admFormModalHome;
  if (h) {
    try { if (h.parent) h.parent.insertBefore(h.form, h.next); } catch (_) {}
    h.extras.forEach((x) => { try { if (x.parent) x.parent.insertBefore(x.el, x.next); } catch (_) {} });
    admFormModalHome = null;
  }
  admFormModalKey = '';
  if (overlay) overlay.classList.add('hidden');
  if (!h) return;
  try { document.body.style.overflow = ''; } catch (_) {}
}

// Atajos de "nuevo" para las secciones cuyo héroe no tenía botón
function openNewsForm() { resetNewsForm(); openFormModal('news'); }
function openPresetForm() { resetPresetForm(); openFormModal('preset'); }
function openProjectForm() { resetProjectForm(); openFormModal('project'); }
function openManageForm() { resetManageProjectForm(); openFormModal('manage'); }
function openUserForm() { resetAdminUserForm(); openFormModal('user'); }

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && admFormModalKey) closeFormModal();
});

// =======================================================
// Devlog en movil: secciones plegables (cerradas al inicio).
// Solo actua con pantalla <=640px; en escritorio todo sigue abierto.
// El estado abierto/cerrado se recuerda entre repintados.
// =======================================================
(function mobileFolds() {
  const mq = window.matchMedia ? window.matchMedia('(max-width: 640px)') : null;
  if (!mq) return;
  const state = new Map();
  const SEL = '.m-fold-card, #ws-timeline .ws-day, #ws-timeline .ws-item[data-sid], #ws-daily .ws-daily-item';
  const HEAD = '.m-fold-card > .card-head, .ws-day > .ws-day-head, .ws-item .ws-item-head, .ws-item .ws-item-title, .ws-daily-item > .ws-daily-head';
  function keyOf(el) {
    if (el.dataset.fold) return el.dataset.fold;
    if (el.classList.contains('ws-day')) return el.id;
    if (el.classList.contains('ws-item')) return 's' + el.dataset.sid;
    const n = el.querySelector('.ws-daily-proj');
    return 'd' + (n ? n.textContent.trim() : '');
  }
  function isOpenByDefault(el) {
    return el.classList.contains('ws-day') && el.classList.contains('is-today');
  }
  function apply(root) {
    (root || document).querySelectorAll(SEL).forEach((el) => {
      const k = keyOf(el);
      const open = state.has(k) ? state.get(k) : isOpenByDefault(el);
      el.classList.toggle('m-open', !!open);
    });
  }
  document.addEventListener('click', (e) => {
    if (!mq.matches) return;
    const h = e.target.closest(HEAD);
    if (!h || !h.closest('#manage-sub-devlog')) return;
    if (e.target.closest('button, a, input, select, textarea, label')) return;
    const host = h.closest(SEL);
    if (!host) return;
    const k = keyOf(host);
    const next = !host.classList.contains('m-open');
    state.set(k, next);
    host.classList.toggle('m-open', next);
  });
  function boot() {
    const pane = document.getElementById('manage-sub-devlog');
    if (!pane) return;
    apply(pane);
    let queued = false;
    new MutationObserver(() => {
      if (queued) return;
      queued = true;
      requestAnimationFrame(() => { queued = false; apply(pane); });
    }).observe(pane, { childList: true, subtree: true });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();