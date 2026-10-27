// Surface — billetera del ecosistema OWS (antes Ocean Pay).
// Mismo backend, misma sesión y mismo token que el resto de OWS: el login es
// compartido (SSO) y por eso se conservan las claves de localStorage.
//
// Backend REAL: siempre server.js en Render (producción).
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

// Claves compartidas con Ocean Pay / OWS Hub: cambiarlas rompería el SSO.
const TOKEN_KEY = 'ocean_pay_token';
const USER_KEY  = 'ocean_pay_user';

let currentUser = null;
let userCards = [];
let selectedCardIndex = 0;
let cardDataVisible = false;   // número y CVV ocultos por defecto

let currentBalances = { tides: 0, gambits: 0, usd: 0 };

// Historial completo en memoria
let allTransactionsList = [];

// Pago pendiente de confirmar
let pendingTransferPayload = null;

// Verificación de destinatario
let isRecipientValid = false;
let verifiedRecipientUser = null;
let recipientCheckTimeout = null;

// Preferencias de Surface (solo locales: no tocan la sesión ni el backend)
const LAYOUT_KEY = 'ocean_pay_layout_mode';
const VIEW_KEY = 'ocean_pay_last_section';
const ANIM_KEY = 'ocean_pay_pref_animations';
const DEFAULT_CURRENCY_KEY = 'ocean_pay_pref_currency';
const LAYOUT_MODES = ['left', 'right', 'top', 'bottom'];
const SURFACE_VIEWS = ['overview', 'transfer', 'tides', 'card', 'history', 'management', 'settings'];

// Compra de Tides con Mercado Pago: el retorno se guarda en sessionStorage
// para poder confirmar el pago aunque la URL se limpie o haya que iniciar sesión.
// Se conserva como respaldo: el checkout activo es PayPal.
const TIDES_RETURN_KEY = 'surface_tides_return';

// Interruptor de la tienda de Tides. El cobro activo es PayPal (USD).
const TIDES_SHOP_ENABLED = true;

const PAYPAL_SDK_ID = 'surface-paypal-sdk';

let tidesPackages = [];
let selectedTidesPackageId = '';
let tidesPackagesLoading = false;
let tidesPackagesLoaded = false;
let tidesCheckoutBusy = false;
let tidesReturnProcessing = false;

// PayPal: config pública, SDK y botones montados una sola vez por sesión.
let tidesPayPalConfig = null;
let tidesPayPalConfigPromise = null;
let tidesPayPalSdkPromise = null;
let tidesPayPalButtonsMounted = false;
let tidesPayPalPendingPackageId = '';

// Añadir crédito: monto libre en USD, mismas credenciales que Tides.
let creditConfig = null;
let creditConfigPromise = null;
let creditButtonsMounted = false;
let creditCheckoutBusy = false;
let creditLimits = { minUsd: 1, maxUsd: 500 };

let currentView = 'overview';

// Gestión: los ajustes son locales de cada cuenta (clave por usuario).
let mgTab = 'summary';
const mgSessionNotices = {};
let mgSuspensionTimer = null;
let mgCardSelectionTouched = false;
let pendingLimitScopeContext = null;
let pendingLimitSnoozeContext = null;
let mgWarningDraft = 80;
let mgWarningDraftTouched = false;

// Resumen de actividad (gastos e ingresos de cualquier juego del ecosistema)
let overviewData = null;
let overviewLoading = false;
let gamesCurrencyFilter = 'all';

function el(id) { return document.getElementById(id); }

// =========================================
// FEE ENGINE — reglas de comisión OWS
// =========================================

const FEE_CONFIG = {
  gambits: { threshold: 1000, baseRate: 0.02,  minRate: 0.005, label: 'GAMBITS' },
  tides:   { threshold: 500,  baseRate: 0.01,  minRate: 0.002, label: 'TIDES'   },
};

// Envíos sin comisión por mes (global para todas las divisas)
const FREE_TRANSFERS_PER_MONTH = 5;
const TX_COUNTER_KEY = 'ocean_pay_global_monthly_tx';

function getMonthlyTxData() {
  const today = new Date();
  const monthKey = today.getFullYear() + '-' + String(today.getMonth() + 1).padStart(2, '0');
  try {
    const raw = localStorage.getItem(TX_COUNTER_KEY);
    const parsed = raw ? JSON.parse(raw) : null;
    if (parsed && parsed.month === monthKey) return parsed;
  } catch (_) {}
  return { month: monthKey, count: 0, volume: 0 };
}

function saveMonthlyTxData(data) {
  try { localStorage.setItem(TX_COUNTER_KEY, JSON.stringify(data)); } catch (_) {}
}

function recordTransferInCounter(currency, amount) {
  const data = getMonthlyTxData();
  data.count  += 1;
  data.volume += amount;
  saveMonthlyTxData(data);
  updateFreeQuotaUI();
}

/* Tiempo restante hasta el reinicio de cuota (1º día del mes siguiente). */
function getTimeUntilMonthReset() {
  const now = new Date();
  const nextMonth = new Date(now.getFullYear(), now.getMonth() + 1, 1, 0, 0, 0);
  const diffMs = nextMonth.getTime() - now.getTime();
  const days  = Math.floor(diffMs / 86400000);
  const hours = Math.floor((diffMs % 86400000) / 3600000);
  if (days > 0) return `en ${days} ${days === 1 ? 'día' : 'días'}`;
  return `en ${hours} ${hours === 1 ? 'hora' : 'horas'}`;
}

function updateFreeQuotaUI() {
  const txData = getMonthlyTxData();
  const count = Math.min(txData.count, FREE_TRANSFERS_PER_MONTH);
  const remaining = Math.max(0, FREE_TRANSFERS_PER_MONTH - txData.count);
  const pct = Math.min(100, Math.round((txData.count / FREE_TRANSFERS_PER_MONTH) * 100));

  const usedEl = el('free-quota-used');
  const remainingEl = el('free-quota-remaining');
  const resetEl = el('free-quota-reset');
  const progressEl = el('free-quota-progress');

  if (usedEl) usedEl.textContent = `${count} / ${FREE_TRANSFERS_PER_MONTH}`;
  if (remainingEl) {
    remainingEl.textContent = remaining > 0
      ? `${remaining} ${remaining === 1 ? 'envío' : 'envíos'}`
      : 'ninguno este mes';
  }
  if (resetEl) resetEl.textContent = getTimeUntilMonthReset();
  if (progressEl) progressEl.style.width = `${pct}%`;
}

/* Descuento por actividad de los últimos 7 días (0–15%) en la misma divisa. */
function calcActivityDiscount(currency) {
  const currencyLabel = (currency === 'tides') ? 'TIDES' : 'GAMBITS';
  const now = Date.now();
  const sevenDaysMs = 7 * 24 * 60 * 60 * 1000;

  const recentTxs = allTransactionsList.filter((tx) => {
    const txTime = tx.date instanceof Date ? tx.date.getTime() : new Date(tx.date).getTime();
    return tx.currency === currencyLabel && tx.amount < 0 && (now - txTime) <= sevenDaysMs;
  });

  const count  = recentTxs.length;
  const volume = recentTxs.reduce((sum, tx) => sum + Math.abs(tx.amount), 0);
  const factor = Math.max(Math.min(count / 5, 1), Math.min(volume / 5000, 1));
  return Math.round(factor * 15);
}

/* Comisión de un envío: { fee, rate, isFree, reasons[], discountPct } */
function calculateFee(currency, amount) {
  const cfg = FEE_CONFIG[currency];
  if (!cfg) return { fee: 0, rate: 0, isFree: true, reasons: [], discountPct: 0 };

  if (amount < cfg.threshold) {
    return {
      fee: 0, rate: 0, isFree: true, discountPct: 0,
      reasons: ['Monto menor a ' + cfg.threshold.toLocaleString() + ' ' + cfg.label + ': sin comisión'],
    };
  }

  const txData = getMonthlyTxData();
  if (txData.count < FREE_TRANSFERS_PER_MONTH) {
    return {
      fee: 0, rate: 0, isFree: true, discountPct: 100,
      reasons: ['Envío gratis (' + (txData.count + 1) + '/' + FREE_TRANSFERS_PER_MONTH + ' del mes)'],
    };
  }

  const activityDiscount = calcActivityDiscount(currency);
  let effectiveRate = cfg.baseRate * (1 - activityDiscount / 100);
  effectiveRate = Math.max(effectiveRate, cfg.minRate);
  const fee = Math.ceil(amount * effectiveRate);

  const reasons = [];
  if (currency === 'tides') reasons.push('Tides: tarifa reducida por ser divisa premium');
  if (activityDiscount > 0) reasons.push('Descuento por actividad reciente: -' + activityDiscount + '%');

  return { fee, rate: effectiveRate, isFree: false, reasons, discountPct: activityDiscount, baseRate: cfg.baseRate };
}

/* Total a debitar (envío + comisión). */
function calcTotalDebit(currency, amount) {
  return amount + calculateFee(currency, amount).fee;
}

/* Mayor monto que se puede enviar sin pasarse del saldo (la comisión se suma). */
function calcMaxSendable(currency, available) {
  if (!(available > 0)) return 0;
  let amount = Math.floor(available);
  for (let i = 0; i < 5 && amount > 0; i++) {
    const over = calcTotalDebit(currency, amount) - available;
    if (over <= 0) break;
    amount -= over;
  }
  return Math.max(0, Math.floor(amount));
}

// =========================================
// ARRANQUE
// =========================================

document.addEventListener('DOMContentLoaded', function () {
  if (window.location.protocol === 'file:') {
    console.warn('[Surface] Abierto como archivo local (file://). La API sigue siendo ' + API_BASE + '.');
  }
  // Antes que nada: capturar el retorno de Mercado Pago y limpiar la URL.
  captureTidesReturnParams();
  // Preferencias antes de mostrar nada: evita el salto de layout al entrar.
  applyLayoutMode(getLayoutMode());
  applyAnimationPref();
  applyTidesShopLock();
  bindSurfaceEvents();
  restoreSession();
});

function restoreSession() {
  const token = localStorage.getItem(TOKEN_KEY);
  const storedUser = localStorage.getItem(USER_KEY);
  if (storedUser) {
    try { currentUser = JSON.parse(storedUser); } catch (_) {}
  }

  if (token) {
    showDashboard();
    loadWalletData().then(function () {
      processPendingTidesReturn();
    });
  } else {
    showAuth();
  }
}

/* Reinicia la animación de entrada de un bloque (login → billetera y vuelta). */
function replayEnter(root) {
  if (!root || !animationsEnabled()) return;
  const targets = root.querySelectorAll('.srf-anim');
  const list = targets.length ? Array.from(targets) : [root];
  list.forEach(function (node) {
    node.classList.remove('srf-anim');
    void node.offsetWidth; // reflow: fuerza reiniciar los keyframes
    node.classList.add('srf-anim');
  });
}

// ═══════════════════════════════════════════════
// EVENTOS — binding centralizado (sin onclick inline:
// el WebView de Tauri no compila atributos onclick/*)
// ═══════════════════════════════════════════════
function bindSurfaceEvents() {
  const on = (sel, ev, fn) => {
    const node = typeof sel === 'string' ? document.querySelector(sel) : sel;
    if (node) node.addEventListener(ev, fn);
  };
  const all = (sel, ev, fn) => {
    document.querySelectorAll(sel).forEach((node) => node.addEventListener(ev, fn));
  };

  // Acceso
  all('[data-optab]', 'click', (e) => switchAuthTab(e.currentTarget.getAttribute('data-optab')));
  on('#login-form', 'submit', handleLogin);
  on('#register-form', 'submit', handleRegister);

  // Barra superior
  on('#btn-back-ows', 'click', () => { window.location.href = '../index.html'; });
  on('#btn-admin-panel', 'click', openAdminModal);
  on('#btn-op-logout', 'click', handleLogout);
  on('#btn-sync-balances', 'click', () => loadWalletData({ manual: true }));
  on('#btn-account-sync', 'click', () => loadWalletData({ manual: true }));
  on('#btn-account-logout', 'click', handleLogout);
  on('#btn-account-hub', 'click', () => { window.location.href = '../index.html'; });
  on('#btn-account-admin', 'click', openAdminModal);

  // Secciones y preferencias
  all('[data-goto-view]', 'click', (e) => {
    e.preventDefault();
    goToView(e.currentTarget.getAttribute('data-goto-view'));
  });
  all('input[name="layout-mode"]', 'change', (e) => setLayoutMode(e.target.value, true));
  all('[data-set-tab]', 'click', (e) => setSettingsTab(e.currentTarget.getAttribute('data-set-tab')));
  all('[data-games-currency]', 'click', (e) => setGamesCurrencyFilter(e.currentTarget.getAttribute('data-games-currency')));
  on('#pref-animations', 'change', (e) => setAnimationsEnabled(!!e.target.checked));
  on('#pref-default-currency', 'change', (e) => setDefaultCurrency(e.target.value));

  // Gestión: topes, equivalencias y controles
  all('[data-mg-tab]', 'click', (e) => setManagementTab(e.currentTarget.getAttribute('data-mg-tab')));

  // Añadir crédito: el monto lo elige el usuario, no hay catálogo.
  on('#credit-amount', 'input', updateCreditUI);
  on('#credit-amount', 'blur', normalizeCreditInput);
  all('[data-credit-amount]', 'click', (e) => {
    const input = el('credit-amount');
    if (input) input.value = e.currentTarget.getAttribute('data-credit-amount') || '';
    updateCreditUI();
  });

  on('#mg-limits-enabled', 'change', handleLimitsEnabledChange);
  on('#btn-mg-change-scope', 'click', () => openLimitScopeModal());
  on('#btn-apply-limit-scope', 'click', applyLimitScopeModal);
  all('[data-close-limit-scope]', 'click', () => closeLimitScopeModal(true));
  on('#limit-scope-modal', 'click', (e) => { if (e.target.id === 'limit-scope-modal') closeLimitScopeModal(true); });
  all('input[name="limit-scope-radio"]', 'change', syncLimitScopeModalUI);
  on('#limit-scope-card-select', 'change', syncLimitScopeModalUI);
  on('#btn-confirm-limit-snooze', 'click', confirmLimitSnooze);
  all('[data-close-limit-snooze]', 'click', closeLimitSnoozeModal);
  on('#limit-snooze-modal', 'click', (e) => { if (e.target.id === 'limit-snooze-modal') closeLimitSnoozeModal(); });
  on('#btn-snooze-limit', 'click', () => openLimitSnoozeModal({
    currency: currentCurrency(),
    amount: parseInt(el('transfer-amount')?.value, 10) || 0
  }));

  on('#mg-period', 'change', (e) => {
    const nextPeriod = e.target.value;
    const before = loadManagement();
    const wasSuspended = mgSuspensionActive(before);
    mgUpdate(
      (s) => {
        s.limits.period = nextPeriod;
        if (s.limits.suspendedUntil) clearMgSuspensionFields(s);
      },
      'Período del límite: ' + (MG_PERIODS[nextPeriod] ? MG_PERIODS[nextPeriod].label : nextPeriod) + '.' +
        (wasSuspended ? ' El límite se reactivó al cambiar de período.' : ''),
      'limits'
    );
    mgScheduleSuspensionWake();
  });
  on('#mg-limit-gambits', 'change', (e) => {
    const value = mgInt(e.target.value);
    mgUpdate(
      (s) => { s.limits.gambits = value; },
      value > 0
        ? 'Tope en Gambits: ' + mgFormatAmount(value) + ' (' + MG_PERIODS[loadManagement().limits.period].label + ').'
        : 'Tope en Gambits desactivado.',
      'limits'
    );
  });
  on('#mg-limit-tides', 'change', (e) => {
    const value = mgInt(e.target.value);
    mgUpdate(
      (s) => { s.limits.tides = value; },
      value > 0
        ? 'Tope en Tides: ' + mgFormatAmount(value) + ' (' + MG_PERIODS[loadManagement().limits.period].label + ').'
        : 'Tope en Tides desactivado.',
      'limits'
    );
  });
  on('#mg-perop-gambits', 'change', (e) => {
    const value = mgInt(e.target.value);
    mgUpdate(
      (s) => { s.limits.perOp.gambits = value; },
      value > 0 ? 'Máximo por envío en Gambits: ' + mgFormatAmount(value) + '.' : 'Máximo por envío en Gambits desactivado.',
      'limits'
    );
  });
  on('#mg-perop-tides', 'change', (e) => {
    const value = mgInt(e.target.value);
    mgUpdate(
      (s) => { s.limits.perOp.tides = value; },
      value > 0 ? 'Máximo por envío en Tides: ' + mgFormatAmount(value) + '.' : 'Máximo por envío en Tides desactivado.',
      'limits'
    );
  });
  on('#mg-warning-range', 'input', (e) => syncMgWarningDraft(e.target.value));
  on('#btn-mg-add-warning', 'click', addMgWarning);
  on('#mg-warning-chips', 'click', (e) => {
    const btn = e.target.closest('[data-remove-warning]');
    if (!btn) return;
    removeMgWarning(parseInt(btn.getAttribute('data-remove-warning'), 10));
  });
  on('#mg-block-exceeded', 'change', (e) => mgUpdate(
    (s) => { s.limits.block = !!e.target.checked; },
    e.target.checked ? 'Bloqueo al superar el tope activado.' : 'El tope ya no bloquea: solo avisa.',
    'limits'
  ));

  on('#mg-alert-limit', 'change', (e) => mgUpdate(
    (s) => { s.controls.alertLimit = !!e.target.checked; },
    e.target.checked ? 'Aviso de límite activado.' : 'Aviso de límite desactivado.'
  ));
  on('#mg-alert-large', 'change', (e) => mgUpdate(
    (s) => { s.controls.alertLarge = !!e.target.checked; },
    e.target.checked ? 'Aviso de envíos grandes activado.' : 'Aviso de envíos grandes desactivado.'
  ));
  on('#mg-confirm-large', 'change', (e) => mgUpdate(
    (s) => { s.controls.confirmLarge = !!e.target.checked; },
    e.target.checked ? 'Confirmación extra para envíos grandes activada.' : 'Confirmación extra desactivada.'
  ));
  on('#mg-large-amount', 'change', (e) => {
    const value = mgInt(e.target.value);
    mgUpdate(
      (s) => { s.controls.largeAmount = value; },
      value > 0 ? 'Umbral de envío grande: ' + mgFormatAmount(value) + '.' : 'Umbral de envío grande desactivado.'
    );
  });
  on('#mg-pause-transfers', 'change', (e) => mgUpdate(
    (s) => { s.controls.pauseTransfers = !!e.target.checked; },
    e.target.checked ? 'Envíos pausados desde Gestión.' : 'Pausa de envíos desactivada.',
    'pause'
  ));

  on('#mg-calc-form', 'submit', (e) => { e.preventDefault(); updateMgCalculator(); });
  on('#mg-calc-currency', 'change', updateMgCalculator);
  on('#mg-calc-amount', 'input', updateMgCalculator);
  on('#mg-log-export', 'click', exportMgLog);
  on('#mg-log-clear', 'click', clearMgLog);
  on('#mg-reset', 'click', resetManagement);

  // Tarjeta: selector + revelado + copia
  on('#card-select-dropdown', 'change', (e) => handleCardSelection(e.target.value));
  on('#btn-reveal-card', 'click', toggleCardData);
  on('#card-copy-icon', 'click', copyCardNumber);

  // Saldos y divisa del envío
  all('[data-currency]', 'click', (e) => selectCurrency(e.currentTarget.getAttribute('data-currency')));

  // Envío
  on('#transfer-form', 'submit', promptTransferConfirmation);
  on('#transfer-recipient', 'input', (e) => handleRecipientInput(e.target.value));
  on('#btn-max-amount', 'click', setTransferMaxAmount);
  on('#transfer-amount', 'input', (e) => handleAmountInput(e.target.value));
  all('[data-preset]', 'click', (e) => addAmountPreset(Number(e.currentTarget.getAttribute('data-preset'))));

  // Compra de Tides (los paquetes se generan dinámicamente)
  on('#btn-buy-tides', 'click', startTidesCheckout);
  on('#tides-packages', 'click', handleTidesPackageClick);
  window.addEventListener('pageshow', function () {
    // Al volver desde Mercado Pago (o desde la caché del navegador) el botón
    // no debe quedar bloqueado en «Conectando…».
    if (!tidesCheckoutBusy) return;
    tidesCheckoutBusy = false;
    updateTidesSummary();
  });

  // Modales
  all('[data-close-confirm]', 'click', closeConfirmModal);
  all('[data-close-admin]', 'click', closeAdminModal);
  on('#btn-final-transfer', 'click', executeFinalTransfer);
  on('#confirm-modal', 'click', (e) => { if (e.target.id === 'confirm-modal') closeConfirmModal(); });
  on('#admin-modal', 'click', (e) => { if (e.target.id === 'admin-modal') closeAdminModal(); });
  on('#clear-history-confirm-modal', 'click', (e) => {
    if (e.target.id === 'clear-history-confirm-modal') closeClearHistoryModal();
  });

  // Historial
  on('#tx-search-input', 'input', filterTransactions);
  on('#tx-filter-currency', 'change', filterTransactions);
  on('#tx-auto-clear-period', 'change', (e) => handleAutoClearSettingChange(e.target.value));
  on('#btn-clear-history', 'click', promptClearHistory);
  on('#btn-reload-tx', 'click', () => loadAllTransactionsFromDB(true));
  on('#btn-cancel-clear', 'click', closeClearHistoryModal);
  on('#btn-confirm-clear-history', 'click', () => executeClearHistory(false));

  // Admin
  on('#admin-balance-form', 'submit', handleAdminBalanceSubmit);
  document.querySelectorAll('input[name="admin-mode-radio"]').forEach((radio) => {
    radio.addEventListener('change', syncAdminModeUI);
  });

  // Toast: se puede cerrar con un click
  on('#toast', 'click', hideToast);

  // Escape cierra el modal abierto de arriba hacia abajo
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    if (!el('limit-snooze-modal')?.classList.contains('hidden')) return closeLimitSnoozeModal();
    if (!el('limit-scope-modal')?.classList.contains('hidden')) return closeLimitScopeModal(true);
    if (!el('admin-modal')?.classList.contains('hidden')) return closeAdminModal();
    if (!el('clear-history-confirm-modal')?.classList.contains('hidden')) return closeClearHistoryModal();
    if (!el('confirm-modal')?.classList.contains('hidden')) return closeConfirmModal();
  });

  // El navegador puede dormir los timers en segundo plano: al volver a la
  // pestaña se revisa si el período ya se reinició y el límite debe volver.
  document.addEventListener('visibilitychange', function () {
    if (!document.hidden) mgCheckSuspensionWake();
  });
  window.addEventListener('focus', mgCheckSuspensionWake);
}

// =========================================
// VISTAS
// =========================================

function showAuth() {
  const dash = el('dashboard-section');
  const auth = el('auth-section');
  if (dash) dash.classList.add('hidden');
  if (auth) {
    auth.classList.remove('hidden');
    replayEnter(auth);
  }
}

function showDashboard() {
  const auth = el('auth-section');
  const dash = el('dashboard-section');
  if (auth) auth.classList.add('hidden');
  if (dash) {
    dash.classList.remove('hidden');
    replayEnter(dash);
  }

  // Preferencias guardadas: layout, animaciones y divisa por defecto.
  applyLayoutMode(getLayoutMode());
  applyAnimationPref();
  applyDefaultCurrency();

  updateUserUI();
  checkAdminPrivileges();
  populateCardsDropdown();
  displaySelectedCard();
  mgApplyStoredActiveCard(loadManagement());
  updateCurrencySelectionUI();
  updateTransferPreview();
  updateFreeQuotaUI();
  syncSettingsUI();
  renderManagement();
  mgScheduleSuspensionWake();

  // Arranca siempre en la última sección visitada (Overview la primera vez).
  // Si venimos de Mercado Pago, la sección de compra tiene prioridad.
  const initialView = readPendingTidesReturn()
    ? 'tides'
    : (viewFromHash() || getStoredValue(VIEW_KEY, SURFACE_VIEWS, 'overview'));
  goToView(initialView);
}

function switchAuthTab(tab) {
  const isLogin = tab === 'login';
  el('login-form')?.classList.toggle('hidden', !isLogin);
  el('register-form')?.classList.toggle('hidden', isLogin);

  const loginBtn = el('tab-login-btn');
  const regBtn = el('tab-register-btn');
  if (loginBtn) {
    loginBtn.classList.toggle('is-active', isLogin);
    loginBtn.setAttribute('aria-selected', String(isLogin));
  }
  if (regBtn) {
    regBtn.classList.toggle('is-active', !isLogin);
    regBtn.setAttribute('aria-selected', String(!isLogin));
  }
  hideAlert('auth-alert');
}

/* Nombre, avatar y titular de la tarjeta siempre desde el mismo lugar. */
function updateUserUI() {
  const name = (currentUser && (currentUser.username || currentUser.id)) || 'Jugador';
  const navUser = el('nav-user-name');
  const avatar = el('nav-user-avatar');
  const holder = el('card-holder-name');
  const holderPlain = el('card-holder-plain');
  const hello = el('srf-hello-name');
  const accountUser = el('account-username');

  if (navUser) navUser.textContent = name;
  if (avatar) avatar.textContent = String(name).charAt(0).toUpperCase();
  if (holder) holder.textContent = String(name).toUpperCase();
  if (holderPlain) holderPlain.textContent = String(name).toUpperCase();
  if (hello) hello.textContent = name;
  if (accountUser) accountUser.textContent = name;
}

function checkAdminPrivileges() {
  const adminBtn = el('btn-admin-panel');
  if (!adminBtn) return;
  const name = String((currentUser && currentUser.username) || '').trim().toLowerCase();
  adminBtn.classList.toggle('hidden', name !== 'oceanandwild');
}

// =========================================
// SESIÓN
// =========================================

async function handleLogin(e) {
  if (e && e.preventDefault) e.preventDefault();
  hideAlert('auth-alert');

  const submitBtn = el('btn-login-submit');
  const username = (el('login-username')?.value || '').trim();
  const password = (el('login-password')?.value || '').trim();

  if (!username || !password) {
    showAlert('auth-alert', 'Ingresá tu usuario y tu contraseña.', 'error');
    return;
  }

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = 'Conectando…';
  }

  try {
    const res = await fetch(API_BASE + '/surface/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || ('Error del servidor (' + res.status + ')'));
    if (!data.token) throw new Error('No se recibió token de acceso.');

    currentUser = data.user || { id: data.id, username };
    localStorage.setItem(TOKEN_KEY, data.token);
    localStorage.setItem(USER_KEY, JSON.stringify(currentUser));

    showToast('¡Bienvenido, ' + username + '!');
    showDashboard();
    await loadWalletData();
    await processPendingTidesReturn();
  } catch (err) {
    console.error('[Surface] Error de login:', err, '| API_BASE:', API_BASE);
    let msg = err.message || 'Error de conexión con el servidor.';
    if (String(err.message || '').includes('Failed to fetch') || err instanceof TypeError) {
      msg = 'No se pudo conectar con el servidor. Revisá tu internet e intentá de nuevo.';
    }
    showAlert('auth-alert', msg, 'error');
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Entrar a Surface';
    }
  }
}

async function handleRegister(e) {
  if (e && e.preventDefault) e.preventDefault();
  hideAlert('auth-alert');

  const username = (el('reg-username')?.value || '').trim();
  const password = (el('reg-password')?.value || '').trim();
  if (!username || !password) {
    showAlert('auth-alert', 'Completá todos los campos.', 'error');
    return;
  }

  try {
    const res = await fetch(API_BASE + '/surface/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || 'No se pudo crear la cuenta.');

    showAlert('auth-alert', 'Cuenta creada. Ya podés iniciar sesión.', 'success');
    switchAuthTab('login');
    const loginUser = el('login-username');
    if (loginUser) loginUser.value = username;
    const loginPass = el('login-password');
    if (loginPass) loginPass.focus();
  } catch (err) {
    showAlert('auth-alert', err.message || 'Error al conectar.', 'error');
  }
}

function handleLogout() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
  currentUser = null;
  userCards = [];
  selectedCardIndex = 0;
  cardDataVisible = false;
  allTransactionsList = [];
  isRecipientValid = false;
  verifiedRecipientUser = null;
  pendingTransferPayload = null;
  overviewData = null;
  overviewLoading = false;
  currentBalances.usd = 0;
  tidesCheckoutBusy = false;
  tidesReturnProcessing = false;
  creditCheckoutBusy = false;
  mgTab = 'summary';
  mgCardSelectionTouched = false;
  mgWarningDraft = 80;
  mgWarningDraftTouched = false;
  Object.keys(mgSessionNotices).forEach(function (key) { delete mgSessionNotices[key]; });
  if (mgSuspensionTimer) { clearTimeout(mgSuspensionTimer); mgSuspensionTimer = null; }
  mgServerReset();
  clearTidesReturn();
  resetTidesPayPalButtons();
  setTidesPayPalStatus('Iniciá sesión para comprar Tides con PayPal.', 'info');
  hideAlert('tides-shop-alert');
  resetCreditPayPalButtons();
  setCreditStatus('Iniciá sesión para cargar saldo con PayPal.', 'info');
  hideAlert('credit-alert');
  updateTidesSummary();

  closeConfirmModal();
  closeAdminModal();
  closeLimitScopeModal(false);
  closeLimitSnoozeModal();
  resetTransferForm();
  showToast('Sesión cerrada.');
  showAuth();
}

// =========================================
// BILLETERA — datos
// =========================================

async function loadWalletData(opts) {
  const manual = !!(opts && opts.manual);
  const token = localStorage.getItem(TOKEN_KEY);
  if (!token) return handleLogout();

  const syncBtn = el('btn-sync-balances');
  if (syncBtn) syncBtn.classList.add('is-busy');

  updateUserUI();
  populateCardsDropdown();
  displaySelectedCard();

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 20000);

    const res = await fetch(API_BASE + '/surface/me', {
      headers: { 'Authorization': 'Bearer ' + token },
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    if (res.status === 401) return handleLogout();

    const data = await res.json().catch(() => ({}));
    currentUser = data.user || currentUser || {};
    if (data.id && !currentUser.id) currentUser.id = data.id;
    if (currentUser.id) localStorage.setItem(USER_KEY, JSON.stringify(currentUser));

    userCards = Array.isArray(data.cards) ? data.cards : [];

    const balances = data.balances || {};
    currentBalances.tides   = Number(balances.tides   || 0);
    currentBalances.gambits = Number(balances.gambits || 0);
    currentBalances.usd     = Number(balances.usd     || 0);

    // Verificación directa de saldos (por si /me viene con datos viejos)
    try {
      const [tidesRes, gambitsRes, creditRes] = await Promise.allSettled([
        fetch(API_BASE + '/surface/tides/balance',   { headers: { 'Authorization': 'Bearer ' + token } }),
        fetch(API_BASE + '/surface/gambits/balance', { headers: { 'Authorization': 'Bearer ' + token } }),
        fetch(API_BASE + '/surface/credit/balance',  { headers: { 'Authorization': 'Bearer ' + token } })
      ]);
      if (tidesRes.status === 'fulfilled' && tidesRes.value.ok) {
        const tData = await tidesRes.value.json().catch(() => ({}));
        if (typeof tData.tides === 'number') currentBalances.tides = tData.tides;
      }
      if (gambitsRes.status === 'fulfilled' && gambitsRes.value.ok) {
        const gData = await gambitsRes.value.json().catch(() => ({}));
        if (typeof gData.gambits === 'number') currentBalances.gambits = gData.gambits;
      }
      if (creditRes.status === 'fulfilled' && creditRes.value.ok) {
        const cData = await creditRes.value.json().catch(() => ({}));
        if (typeof cData.usd === 'number') currentBalances.usd = cData.usd;
      }
    } catch (_) {}

    if (manual) showToast('Balances sincronizados.');
  } catch (err) {
    console.error('[Surface] Error cargando la billetera:', err);
    if (manual) showToast('No se pudieron sincronizar los balances.');
  } finally {
    if (syncBtn) syncBtn.classList.remove('is-busy');
    updateUserUI();
    populateCardsDropdown();
    displaySelectedCard();
    mgApplyStoredActiveCard(loadManagement());
    updateBalanceDisplay();
    updatePillsBalances();
    updateTransferPreview();
    updateFreeQuotaUI();
    updateAccountPanel();
    renderManagement();
    updateCreditUI();
    mgServerHydrate();

    // El historial es la fuente de respaldo del resumen: primero se carga
    // (si hace falta) y después se pide la actividad agregada al servidor.
    loadAllTransactionsFromDB(false)
      .then(function () { loadOverviewActivity(); })
      .catch(function () { loadOverviewActivity(); });
  }
}

function updateBalanceDisplay() {
  const tidesEl = el('balance-tides');
  const gambitsEl = el('balance-gambits');
  const shopTidesEl = el('tides-shop-balance');
  if (tidesEl) tidesEl.textContent = currentBalances.tides.toLocaleString();
  if (gambitsEl) gambitsEl.textContent = currentBalances.gambits.toLocaleString();
  if (shopTidesEl) shopTidesEl.textContent = currentBalances.tides.toLocaleString();
}

function updatePillsBalances() {
  const gBal = el('pill-gambits-bal');
  const tBal = el('pill-tides-bal');
  if (gBal) gBal.textContent = currentBalances.gambits.toLocaleString();
  if (tBal) tBal.textContent = currentBalances.tides.toLocaleString();
}

// =========================================
// TARJETA
// =========================================

function activeCard() { return userCards[selectedCardIndex] || userCards[0] || null; }

/* Número formateado en grupos de 4 (antes devolvía espacios en blanco). */
function formatCardNumber(num) {
  const clean = String(num == null ? '' : num).replace(/\D/g, '');
  if (!clean) return '';
  return clean.replace(/(\d{4})(?=\d)/g, '$1 ').trim();
}

/* Número enmascarado: solo los últimos 4 dígitos. */
function maskCardNumber(num) {
  const clean = String(num == null ? '' : num).replace(/\D/g, '');
  if (clean.length < 4) return '•••• •••• •••• ••••';
  return '•••• •••• •••• ' + clean.slice(-4);
}

function toggleCardData() {
  cardDataVisible = !cardDataVisible;
  const btn = el('btn-reveal-card');
  if (btn) {
    btn.textContent = cardDataVisible ? 'Ocultar datos' : 'Ver datos';
    btn.setAttribute('aria-pressed', String(cardDataVisible));
  }
  displaySelectedCard();
}

function copyCardNumber() {
  const card = activeCard();
  const num = card ? String(card.card_number || '').replace(/\s/g, '') : '';
  if (!num) {
    showToast('Esta tarjeta todavía no tiene número asignado.');
    return;
  }
  const fallback = () => showToast('Número de tarjeta: ' + formatCardNumber(num));
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(num).then(
      () => showToast('Número de tarjeta copiado.'),
      fallback
    );
  } else {
    fallback();
  }
}

function populateCardsDropdown() {
  const picker = document.querySelector('.srf-card-picker');
  const select = el('card-select-dropdown');
  if (!select) return;

  // Una sola tarjeta: el selector sobra.
  const multiple = userCards.length > 1;
  if (picker) picker.classList.toggle('hidden', !multiple);

  select.innerHTML = '';
  if (userCards.length === 0) {
    const opt = document.createElement('option');
    opt.value = '0';
    opt.textContent = 'Tarjeta principal';
    select.appendChild(opt);
    return;
  }

  userCards.forEach(function (card, idx) {
    const opt = document.createElement('option');
    opt.value = String(idx);
    const digits = String(card.card_number || '').replace(/\D/g, '');
    opt.textContent = (card.card_name || ('Tarjeta ' + (idx + 1)))
      + (card.is_primary ? ' · principal' : '')
      + (digits ? ' · •• ' + digits.slice(-4) : '');
    select.appendChild(opt);
  });

  if (selectedCardIndex >= userCards.length) selectedCardIndex = 0;
  select.value = String(selectedCardIndex);
}

function handleCardSelection(indexStr) {
  selectedCardIndex = parseInt(indexStr, 10) || 0;
  mgCardSelectionTouched = true;
  displaySelectedCard();
  mgSyncActiveCard();
}

function displaySelectedCard() {
  const card = activeCard();
  const nameEl = el('card-name-display');
  const numberEl = el('card-number-display');
  const expiryEl = el('card-expiry-display');
  const cvvEl = el('card-cvv-display');

  const rawNumber = card ? String(card.card_number || '') : '';
  const formatted = formatCardNumber(rawNumber);
  const shownNumber = (cardDataVisible && formatted) ? formatted : maskCardNumber(rawNumber);
  const shownExpiry = (card && card.expiry_date) || '—';
  const shownCvv = cardDataVisible ? ((card && card.cvv) || '—') : '•••';

  if (nameEl) nameEl.textContent = ((card && card.card_name) || 'SURFACE').toUpperCase();
  if (numberEl) numberEl.textContent = shownNumber;
  if (expiryEl) expiryEl.textContent = shownExpiry;
  if (cvvEl) cvvEl.textContent = shownCvv;

  // Mismos datos en la tabla de la sección Tarjeta (texto seleccionable).
  const numberPlain = el('card-number-plain');
  if (numberPlain) numberPlain.textContent = shownNumber;
  const expiryPlain = el('card-expiry-plain');
  if (expiryPlain) expiryPlain.textContent = shownExpiry;
  const cvvPlain = el('card-cvv-plain');
  if (cvvPlain) cvvPlain.textContent = shownCvv;
  const statusPlain = el('card-status-plain');
  if (statusPlain) statusPlain.textContent = card ? 'Activa' : 'Sin tarjeta';

  updateUserUI();
}

// =========================================
// DIVISA DEL ENVÍO
// =========================================

function currentCurrency() {
  return el('transfer-currency')?.value || 'gambits';
}

/* Marca la divisa activa en los saldos y en el selector del envío. */
function updateCurrencySelectionUI() {
  const currency = currentCurrency();
  document.querySelectorAll('[data-currency]').forEach((node) => {
    const isActive = node.getAttribute('data-currency') === currency;
    node.classList.toggle('is-active', isActive);
    node.setAttribute('aria-pressed', String(isActive));
  });

  const suffix = el('amount-suffix-label');
  if (suffix) suffix.textContent = currency === 'tides' ? 'TIDES' : 'GAMBITS';

  const feeLabel = el('fee-label-display');
  if (feeLabel) feeLabel.textContent = currency === 'tides' ? 'Comisión Tides' : 'Comisión Gambits';
}

/* Elegir divisa nunca interrumpe: solo cambia el destino del envío. */
function selectCurrency(currency) {
  if (currency !== 'tides' && currency !== 'gambits') return;
  const input = el('transfer-currency');
  if (input) input.value = currency;
  updateCurrencySelectionUI();
  updateTransferPreview();
}

// =========================================
// DESTINATARIO
// =========================================

function handleRecipientInput(val) {
  const clean = String(val || '').trim();

  if (recipientCheckTimeout) clearTimeout(recipientCheckTimeout);

  isRecipientValid = false;
  verifiedRecipientUser = null;
  updateTransferDetailsLock();

  if (!clean || clean.length < 2) {
    setRecipientState('idle');
    return;
  }

  if (currentUser && currentUser.username && clean.toLowerCase() === String(currentUser.username).toLowerCase()) {
    setRecipientState('self');
    return;
  }

  setRecipientState('checking');
  recipientCheckTimeout = setTimeout(() => verifyRecipientExists(clean), 400);
}

function setRecipientState(state, name) {
  const field = el('recipient-field');
  const spinner = el('recipient-spinner');
  const msg = el('recipient-feedback-msg');

  field?.classList.remove('is-ok', 'is-bad');
  if (spinner) spinner.classList.toggle('hidden', state !== 'checking');

  const texts = {
    idle:     { text: '', cls: '' },
    checking: { text: 'Verificando destinatario…', cls: '' },
    ok:       { text: 'Destinatario verificado: @' + name, cls: 'is-ok' },
    missing:  { text: 'No existe ningún jugador con ese usuario.', cls: 'is-bad' },
    self:     { text: 'No podés enviarte fondos a tu propia cuenta.', cls: 'is-bad' },
    error:    { text: 'No se pudo verificar (revisá tu conexión). Escribí de nuevo para reintentar.', cls: 'is-bad' },
  };
  const info = texts[state] || texts.idle;

  if (msg) {
    msg.textContent = info.text;
    msg.classList.toggle('hidden', !info.text);
    msg.classList.toggle('is-ok', info.cls === 'is-ok');
    msg.classList.toggle('is-bad', info.cls === 'is-bad');
    msg.setAttribute('role', 'status');
  }
  if (info.cls === 'is-ok') field?.classList.add('is-ok');
  if (info.cls === 'is-bad') field?.classList.add('is-bad');
}

async function verifyRecipientExists(username) {
  const token = localStorage.getItem(TOKEN_KEY);
  try {
    const res = await fetch(API_BASE + '/surface/api/users/check?username=' + encodeURIComponent(username), {
      headers: { 'Authorization': 'Bearer ' + (token || '') }
    });
    if (!res.ok) throw new Error('Error del servidor (' + res.status + ')');
    const data = await res.json().catch(() => ({}));

    if (data.exists && data.user) {
      const name = data.user.username || username;
      isRecipientValid = true;
      verifiedRecipientUser = { username: name };
      setRecipientState('ok', name);
      updateTransferDetailsLock();
      updateTransferPreview();

      // Al verificar, el foco pasa al monto (solo si está vacío).
      const amount = el('transfer-amount');
      if (amount && !amount.value) amount.focus();
    } else {
      isRecipientValid = false;
      verifiedRecipientUser = null;
      setRecipientState('missing');
      updateTransferDetailsLock();
      updateTransferPreview();
    }
  } catch (err) {
    console.error('[Surface] Error verificando destinatario:', err);
    isRecipientValid = false;
    verifiedRecipientUser = null;
    setRecipientState('error');
    updateTransferDetailsLock();
    updateTransferPreview();
  }
}

/* El bloque de divisa y monto se atenúa hasta tener destinatario, pero
   sigue siendo usable (antes se bloqueaba por completo). */
function updateTransferDetailsLock() {
  const details = el('transfer-details');
  if (details) details.setAttribute('data-locked', String(!isRecipientValid));
}

// =========================================
// MONTO Y RESUMEN
// =========================================

function sanitizeAmountInput(raw) {
  return String(raw == null ? '' : raw).replace(/[^\d]/g, '').slice(0, 9);
}

function handleAmountInput(val) {
  const input = el('transfer-amount');
  const clean = sanitizeAmountInput(val);
  if (input && input.value !== clean) input.value = clean;
  updateTransferPreview();
}

function addAmountPreset(delta) {
  const input = el('transfer-amount');
  if (!input) return;
  const next = (parseInt(input.value, 10) || 0) + delta;
  input.value = sanitizeAmountInput(String(next));
  updateTransferPreview();
  updateTransferDetailsLock();
}

function setTransferMaxAmount() {
  const currency = currentCurrency();
  const available = Number(currentBalances[currency] || 0);
  const state = loadManagement();
  const limitsApply = state.limits.enabled && mgScopeMatchesActiveCard(state);
  const hasLimit = limitsApply && !mgSuspensionActive(state) && Number(state.limits[currency] || 0) > 0;
  const perOp = limitsApply ? Number(state.limits.perOp[currency] || 0) : 0;
  const room = mgMaxAvailable(currency, available);
  const cappedRoom = perOp > 0 ? Math.min(room, perOp) : room;
  const max = calcMaxSendable(currency, cappedRoom);
  const input = el('transfer-amount');

  if (!max) {
    if (hasLimit && room <= 0) {
      showToast('No te queda margen dentro del límite de ' + currencyLabel(currency) + '.');
    } else if (available <= 0) {
      showToast('No tenés saldo disponible en ' + currency.toUpperCase() + '.');
    } else if (cappedRoom > 0) {
      showToast('El monto disponible no alcanza para cubrir la comisión de ' + currencyLabel(currency) + '.');
    } else {
      showToast('No tenés saldo disponible en ' + currency.toUpperCase() + '.');
    }
    return;
  }
  if (input) input.value = String(max);
  updateTransferPreview();

  const caps = [];
  if (hasLimit && room < available) caps.push('tu límite del período');
  if (perOp > 0 && perOp < room) caps.push('tu máximo por envío');
  if (caps.length) {
    showToast('Máximo disponible según ' + caps.join(' y ') + ': ' +
      max.toLocaleString('es-AR') + ' ' + currencyLabel(currency) + '.');
  }
}

/* Resumen: comisión, motivo y total. También decide si se puede enviar. */
function updateTransferPreview() {
  const currency = currentCurrency();
  const currencyLabel = currency.toUpperCase();
  const amount = parseInt(el('transfer-amount')?.value, 10) || 0;
  const available = Number(currentBalances[currency] || 0);

  const feeData = calculateFee(currency, amount);
  const total = amount + feeData.fee;
  const mgCheck = mgEvaluateTransfer(currency, amount, total);

  const feeValueEl = el('fee-value-display');
  const feeHintEl  = el('fee-hint-display');
  const totalEl    = el('summary-total-display');

  if (feeValueEl) {
    if (feeData.isFree) {
      feeValueEl.textContent = 'Gratis';
      feeValueEl.className = 'srf-free';
    } else {
      const pct = Math.round(feeData.rate * 10000) / 100;
      feeValueEl.textContent = feeData.fee.toLocaleString() + ' ' + currencyLabel + ' (' + pct + '%)';
      feeValueEl.className = 'srf-fee';
    }
  }

  if (feeHintEl) {
    const hint = feeData.reasons && feeData.reasons.length ? feeData.reasons.join(' · ') : '';
    feeHintEl.textContent = hint;
    feeHintEl.classList.toggle('hidden', !hint);
  }

  if (totalEl) totalEl.textContent = total.toLocaleString() + ' ' + currencyLabel;

  const limitHintEl = el('limit-hint-display');
  if (limitHintEl) {
    const showHint = !!mgCheck.hint && (amount > 0 || mgCheck.blocked);
    limitHintEl.textContent = showHint ? mgCheck.hint : '';
    limitHintEl.classList.toggle('hidden', !showHint);
    limitHintEl.classList.toggle('is-warn', !!mgCheck.warn && !mgCheck.suspended && !mgCheck.scopeInactive);
    limitHintEl.classList.toggle('is-info', !!(mgCheck.suspended || mgCheck.scopeInactive));
  }

  const snoozeBtn = el('btn-snooze-limit');
  if (snoozeBtn) {
    const showSnooze = !!mgCheck.periodLimitHit && !mgCheck.suspended;
    snoozeBtn.classList.toggle('hidden', !showSnooze);
  }

  const submitBtn = el('btn-submit-transfer');
  if (submitBtn) {
    const over = amount > 0 && total > available;
    submitBtn.disabled = !(isRecipientValid && amount > 0 && !over && !mgCheck.blocked);
    if (mgCheck.blocked) {
      submitBtn.textContent = mgCheck.button || 'No disponible';
    } else if (over) {
      submitBtn.textContent = 'Saldo insuficiente';
    } else {
      submitBtn.textContent = amount > 0
        ? 'Enviar ' + amount.toLocaleString() + ' ' + currencyLabel
        : 'Enviar';
    }
  }
}

function resetTransferForm() {
  const recipient = el('transfer-recipient');
  const amount = el('transfer-amount');
  if (recipient) recipient.value = '';
  if (amount) amount.value = '';
  setRecipientState('idle');
  isRecipientValid = false;
  verifiedRecipientUser = null;
  updateTransferDetailsLock();
  updateTransferPreview();
}

// =========================================
// CONFIRMACIÓN Y ENVÍO
// =========================================

function promptTransferConfirmation(e) {
  if (e && e.preventDefault) e.preventDefault();
  hideAlert('operation-alert');

  const recipient = (el('transfer-recipient')?.value || '').trim();
  const currency = currentCurrency();
  const currencyLabel = currency.toUpperCase();
  const amount = parseInt(el('transfer-amount')?.value, 10) || 0;

  if (!recipient || !isRecipientValid) {
    return showAlert('operation-alert', 'Ingresá y verificá un destinatario válido.', 'error');
  }
  if (!amount || amount <= 0) {
    return showAlert('operation-alert', 'El monto tiene que ser mayor a 0.', 'error');
  }

  const feeData = calculateFee(currency, amount);
  const totalDebit = amount + feeData.fee;

  if (Number(currentBalances[currency] || 0) < totalDebit) {
    const msg = feeData.fee > 0
      ? 'Saldo insuficiente: necesitás ' + totalDebit.toLocaleString() + ' ' + currencyLabel +
        ' (' + amount.toLocaleString() + ' + ' + feeData.fee.toLocaleString() + ' de comisión).'
      : 'Saldo insuficiente de ' + currencyLabel + '.';
    return showAlert('operation-alert', msg, 'error');
  }

  const mgCheck = mgEvaluateTransfer(currency, amount, totalDebit);
  if (mgCheck.blocked) {
    return showAlert('operation-alert', mgCheck.message, 'error');
  }

  const mgState = loadManagement();
  const largeThreshold = Number(mgState.controls.largeAmount || 0);
  const isLarge = largeThreshold > 0 && amount >= largeThreshold;

  pendingTransferPayload = {
    recipient,
    currency,
    currencyLabel,
    amount,
    fee: feeData.fee,
    totalDebit,
    feeReasons: feeData.reasons,
    feeIsFree: feeData.isFree,
    feeRate: feeData.rate,
  };

  const amountEl = el('confirm-amount-text');
  if (amountEl) amountEl.textContent = amount.toLocaleString() + ' ' + currencyLabel;

  const recipientEl = el('confirm-recipient-text');
  if (recipientEl) recipientEl.textContent = '@' + recipient;

  const currencyEl = el('confirm-currency-text');
  if (currencyEl) currencyEl.textContent = currencyLabel;

  const feeEl = el('confirm-fee-text');
  if (feeEl) {
    if (feeData.isFree) {
      feeEl.textContent = 'Gratis';
      feeEl.style.color = '';
    } else {
      const pct = Math.round(feeData.rate * 10000) / 100;
      feeEl.textContent = feeData.fee.toLocaleString() + ' ' + currencyLabel + ' (' + pct + '%)';
      feeEl.style.color = 'var(--srf-gold)';
    }
  }

  const totalEl = el('confirm-total-text');
  if (totalEl) totalEl.textContent = totalDebit.toLocaleString() + ' ' + currencyLabel;

  const discountText = el('confirm-discount-text');
  if (discountText) {
    const reasons = feeData.reasons && feeData.reasons.length ? feeData.reasons.join(' · ') : '';
    discountText.textContent = reasons ? '✦ ' + reasons : '';
    discountText.closest('.srf-rows-item')?.classList.toggle('hidden', !reasons);
  }

  // Gestión: umbral de envío grande y aviso de límite dentro del modal.
  const mgRowBox = el('confirm-mg-row');
  const mgText = el('confirm-mg-text');
  if (mgRowBox && mgText) {
    let note = '';
    if (isLarge) {
      note = 'Envío grande: supera tu umbral de ' + largeThreshold.toLocaleString('es-AR') + ' ' + currencyLabel + '.';
    } else if (mgCheck.hint) {
      note = mgCheck.hint;
    }
    mgText.textContent = note;
    mgRowBox.classList.toggle('hidden', !note);
  }

  const finalBtn = el('btn-final-transfer');
  if (finalBtn) {
    finalBtn.textContent = (mgState.controls.confirmLarge && isLarge) ? 'Confirmar envío grande' : 'Sí, enviar';
  }

  if (mgState.controls.alertLarge && isLarge) {
    showToast('Envío grande: ' + amount.toLocaleString('es-AR') + ' ' + currencyLabel + '.');
  }

  el('confirm-modal')?.classList.remove('hidden');
  el('btn-final-transfer')?.focus();
}

function closeConfirmModal() {
  el('confirm-modal')?.classList.add('hidden');
  const btn = el('btn-final-transfer');
  if (btn) btn.textContent = 'Sí, enviar';
  pendingTransferPayload = null;
}

async function executeFinalTransfer() {
  if (!pendingTransferPayload) return;

  const token = localStorage.getItem(TOKEN_KEY);
  if (!token) return handleLogout();

  const payload = pendingTransferPayload;
  const btn = el('btn-final-transfer');
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Enviando…';
  }

  try {
    // Un solo movimiento atómico en el servidor: debita al remitente y
    // acredita al destinatario. Si el backend no lo tiene activo todavía,
    // se avisa y NO se toca ningún saldo.
    const res = await fetch(API_BASE + '/surface/p2p/send', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
      },
      body: JSON.stringify({
        toUsername: payload.recipient,
        currency: payload.currency,
        amount: payload.amount,
        fee: payload.fee,
        concepto: 'Surface P2P'
      })
    });

    const data = await res.json().catch(() => ({}));

    if (res.status === 401) { closeConfirmModal(); return handleLogout(); }
    if (res.status === 404 || res.status === 501) {
      throw new Error('El servidor todavía no tiene activo el envío directo. Probá de nuevo en unos minutos.');
    }
    if (!res.ok) throw new Error(data.error || 'No se pudo completar el envío.');

    recordTransferInCounter(payload.currency, payload.amount);
    mgAddLog('transfer', 'Envío de ' + payload.amount.toLocaleString('es-AR') + ' ' + payload.currencyLabel + ' a @' + payload.recipient + '.');
    closeConfirmModal();

    const feeMsg = payload.fee > 0
      ? ' (comisión: ' + payload.fee.toLocaleString() + ' ' + payload.currencyLabel + ')'
      : ' (sin comisión)';
    showAlert('operation-alert',
      'Envío listo: ' + payload.amount.toLocaleString() + ' ' + payload.currencyLabel +
      ' a @' + payload.recipient + feeMsg + '.', 'success');
    showToast('¡Enviaste ' + payload.amount.toLocaleString() + ' ' + payload.currencyLabel + '!');

    resetTransferForm();
    await loadWalletData();
  } catch (err) {
    closeConfirmModal();
    showAlert('operation-alert', err.message || 'Error al enviar.', 'error');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = 'Sí, enviar';
    }
  }
}

// =========================================
// COMPRA DE TIDES (MERCADO PAGO)
// =========================================

/* Aplica el estado de la tienda: con TIDES_SHOP_ENABLED en false se muestra
   el candado y se oculta por completo el catálogo y el checkout. */
function applyTidesShopLock() {
  const panel = el('tides-lock-panel');
  const content = el('tides-shop-content');
  if (panel) panel.classList.toggle('hidden', TIDES_SHOP_ENABLED);
  if (content) content.classList.toggle('hidden', !TIDES_SHOP_ENABLED);

  if (TIDES_SHOP_ENABLED) return;

  resetTidesPayPalButtons();
  setTidesPayPalStatus('Pagos con PayPal no disponibles por el momento.', 'info');
  hideAlert('tides-shop-alert');
}

function formatTidesAmount(value) {
  const amount = Number(value || 0);
  return Number.isFinite(amount) ? amount.toLocaleString() : '0';
}

function formatUyu(value) {
  const amount = Number(value || 0);
  if (!Number.isFinite(amount)) return '—';
  try { return '$U ' + amount.toLocaleString('es-UY'); } catch (_) { return '$U ' + amount; }
}

function formatUsd(value) {
  const amount = Number(value);
  if (!Number.isFinite(amount) || amount <= 0) return '—';
  try {
    return 'US$ ' + amount.toLocaleString('en-US', {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2
    });
  } catch (_) {
    return 'US$ ' + amount.toFixed(2);
  }
}

function tidesPackagePriceLabel(pkg) {
  if (!pkg) return '—';
  const usd = Number(pkg.priceUsd);
  if (Number.isFinite(usd) && usd > 0) return formatUsd(usd);
  return formatUyu(pkg.priceUyu);
}

function setTidesPayPalStatus(message, tone) {
  const node = el('tides-paypal-status');
  if (!node) return;
  const text = String(message || '').trim();
  node.textContent = text;
  node.classList.toggle('hidden', !text);
  node.classList.remove('is-info', 'is-success', 'is-error');
  if (text && tone) node.classList.add('is-' + tone);
}

function resetTidesPayPalButtons() {
  const container = el('paypal-button-container');
  if (container) container.innerHTML = '';
  tidesPayPalButtonsMounted = false;
  tidesPayPalPendingPackageId = '';
}

function loadTidesPayPalConfig(force) {
  if (tidesPayPalConfig && !force) return Promise.resolve(tidesPayPalConfig);
  if (tidesPayPalConfigPromise && !force) return tidesPayPalConfigPromise;

  tidesPayPalConfigPromise = (async function () {
    try {
      const res = await fetch(API_BASE + '/surface/paypal/config');
      const data = await res.json().catch(function () { return {}; });
      if (!res.ok) throw new Error(data.error || 'No se pudo consultar PayPal.');

      tidesPayPalConfig = {
        enabled: !!data.enabled,
        configured: !!data.configured,
        environment: String(data.environment || 'live').toLowerCase() === 'sandbox' ? 'sandbox' : 'live',
        clientId: String(data.clientId || '').trim(),
        currency: String(data.currency || 'USD').toUpperCase()
      };
      return tidesPayPalConfig;
    } catch (err) {
      tidesPayPalConfig = null;
      throw err;
    } finally {
      tidesPayPalConfigPromise = null;
    }
  })();

  return tidesPayPalConfigPromise;
}

function loadTidesPayPalSdk(config) {
  if (window.paypal && window.paypal.Buttons) return Promise.resolve(window.paypal);
  if (tidesPayPalSdkPromise) return tidesPayPalSdkPromise;

  tidesPayPalSdkPromise = new Promise(function (resolve, reject) {
    const removeSdkTag = function () {
      const tag = document.getElementById(PAYPAL_SDK_ID);
      if (tag && tag.parentNode) tag.parentNode.removeChild(tag);
    };
    const finishOk = function () {
      if (window.paypal && window.paypal.Buttons) resolve(window.paypal);
      else {
        removeSdkTag();
        reject(new Error('PayPal SDK no disponible.'));
      }
    };
    const finishError = function () {
      removeSdkTag();
      reject(new Error('No se pudo cargar PayPal.'));
    };

    const existing = document.getElementById(PAYPAL_SDK_ID);
    if (existing) {
      existing.addEventListener('load', finishOk);
      existing.addEventListener('error', finishError);
      return;
    }

    const host = config && config.environment === 'sandbox'
      ? 'https://www.sandbox.paypal.com'
      : 'https://www.paypal.com';
    const params = new URLSearchParams({
      'client-id': String(config && config.clientId || ''),
      currency: String(config && config.currency || 'USD'),
      intent: 'capture',
      components: 'buttons'
    });

    const script = document.createElement('script');
    script.id = PAYPAL_SDK_ID;
    script.src = host + '/sdk/js?' + params.toString();
    script.async = true;
    script.onload = finishOk;
    script.onerror = finishError;
    document.head.appendChild(script);
  }).catch(function (err) {
    tidesPayPalSdkPromise = null;
    throw err;
  });

  return tidesPayPalSdkPromise;
}

function tidesPayPalErrorMessage(data, fallback) {
  const base = String((data && data.error) || fallback || '').trim();
  const detail = String((data && data.detail) || '').trim();
  return detail ? base + ' — ' + detail : base;
}

async function createTidesPayPalOrder(pkg) {
  const token = localStorage.getItem(TOKEN_KEY);
  if (!token) {
    handleLogout();
    throw new Error('Iniciá sesión para comprar Tides.');
  }

  const res = await fetch(API_BASE + '/surface/tides/paypal/order', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + token
    },
    body: JSON.stringify({ packageId: pkg.id })
  });
  const data = await res.json().catch(function () { return {}; });
  if (res.status === 401) {
    handleLogout();
    throw new Error('Tu sesión venció. Iniciá sesión de nuevo.');
  }
  if (!res.ok) throw new Error(tidesPayPalErrorMessage(data, 'No se pudo iniciar el pago con PayPal.'));
  if (!data.orderId) throw new Error('PayPal no devolvió una orden válida.');

  const orderEnv = String(data.environment || '').toLowerCase() === 'sandbox' ? 'sandbox' : 'live';
  if (tidesPayPalConfig && tidesPayPalConfig.environment !== orderEnv) {
    tidesPayPalConfig = null;
    throw new Error('El modo de PayPal cambió. Recargá la página para continuar.');
  }
  return String(data.orderId);
}

async function captureTidesPayPalOrder(orderId, packageId) {
  const token = localStorage.getItem(TOKEN_KEY);
  if (!token) {
    handleLogout();
    throw new Error('Iniciá sesión para confirmar el pago.');
  }
  if (!orderId) throw new Error('PayPal no devolvió una orden válida.');

  setTidesPayPalStatus('Confirmando el pago con PayPal…', 'info');

  const res = await fetch(API_BASE + '/surface/tides/paypal/capture', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + token
    },
    body: JSON.stringify({ orderId: orderId, packageId: packageId || '' })
  });
  const data = await res.json().catch(function () { return {}; });
  if (res.status === 401) {
    handleLogout();
    throw new Error('Tu sesión venció. Iniciá sesión de nuevo.');
  }
  if (res.status === 409) {
    const pendingMessage = data.error || 'Tu pago quedó pendiente de confirmación. Las Tides se acreditarán automáticamente.';
    setTidesPayPalStatus(pendingMessage, 'info');
    showAlert('tides-shop-alert', pendingMessage, 'info');
    showToast('Pago pendiente de confirmación.');
    return null;
  }
  if (!res.ok) throw new Error(tidesPayPalErrorMessage(data, 'No se pudo confirmar el pago.'));

  const credited = Number(data.credited || 0);
  const packageTitle = data.package && data.package.title ? data.package.title : '';

  if (data.alreadyApplied) {
    setTidesPayPalStatus('Este pago ya estaba acreditado en tu cuenta.', 'info');
    showAlert('tides-shop-alert', 'Este pago ya estaba acreditado en tu cuenta.', 'info');
  } else {
    const message = '¡Listo! Se acreditaron ' + formatTidesAmount(credited) + ' Tides' +
      (packageTitle ? ' (' + packageTitle + ')' : '') + ' en tu billetera.';
    setTidesPayPalStatus(message, 'success');
    showAlert('tides-shop-alert', message, 'success');
    showToast('+' + formatTidesAmount(credited) + ' Tides acreditadas.');
  }

  const newBalance = Number(data.newBalance);
  if (Number.isFinite(newBalance)) {
    currentBalances.tides = newBalance;
    updateBalanceDisplay();
    updatePillsBalances();
    updateTidesBalanceUI();
  }
  await loadWalletData();
  return data;
}

function mountTidesPayPalButtons() {
  const container = el('paypal-button-container');
  if (!container) return;
  if (tidesPayPalButtonsMounted) return;
  if (!window.paypal || !window.paypal.Buttons) return;
  if (!localStorage.getItem(TOKEN_KEY)) {
    setTidesPayPalStatus('Iniciá sesión para comprar Tides con PayPal.', 'info');
    return;
  }

  container.innerHTML = '';
  const buttons = window.paypal.Buttons({
    style: {
      layout: 'vertical',
      shape: 'pill',
      label: 'paypal',
      height: 46,
      color: 'gold'
    },
    onClick: function (_data, actions) {
      if (tidesCheckoutBusy) return actions.reject();
      if (!localStorage.getItem(TOKEN_KEY)) {
        showAlert('tides-shop-alert', 'Iniciá sesión para comprar Tides.', 'error');
        return actions.reject();
      }
      if (!getTidesPackage(selectedTidesPackageId)) {
        showAlert('tides-shop-alert', 'Elegí un paquete para continuar.', 'error');
        return actions.reject();
      }
      hideAlert('tides-shop-alert');
      return actions.resolve();
    },
    createOrder: async function () {
      const pkg = getTidesPackage(selectedTidesPackageId);
      if (!pkg) throw new Error('Elegí un paquete para continuar.');

      tidesCheckoutBusy = true;
      tidesPayPalPendingPackageId = pkg.id;
      setTidesPayPalStatus('Abriendo PayPal…', 'info');

      try {
        return await createTidesPayPalOrder(pkg);
      } catch (err) {
        tidesCheckoutBusy = false;
        tidesPayPalPendingPackageId = '';
        setTidesPayPalStatus(err.message || 'No se pudo iniciar el pago.', 'error');
        showAlert('tides-shop-alert', err.message || 'No se pudo iniciar el pago con PayPal.', 'error');
        throw err;
      }
    },
    onApprove: async function (data) {
      const packageId = tidesPayPalPendingPackageId || selectedTidesPackageId;
      try {
        await captureTidesPayPalOrder(String(data && data.orderID || ''), packageId);
      } catch (err) {
        console.error('[Surface] Error confirmando pago PayPal:', err);
        setTidesPayPalStatus(err.message || 'No se pudo confirmar el pago.', 'error');
        showAlert(
          'tides-shop-alert',
          err.message || 'No se pudo confirmar el pago. Si ya pagaste, esperá unos segundos y recargá Surface.',
          'error'
        );
        showToast('No se pudo confirmar el pago.');
      } finally {
        tidesCheckoutBusy = false;
        tidesPayPalPendingPackageId = '';
      }
    },
    onCancel: function () {
      tidesCheckoutBusy = false;
      tidesPayPalPendingPackageId = '';
      setTidesPayPalStatus('Pago cancelado. No se descontó nada.', 'info');
    },
    onError: function (err) {
      console.error('[Surface] Error de PayPal:', err);
      tidesCheckoutBusy = false;
      tidesPayPalPendingPackageId = '';
      setTidesPayPalStatus('PayPal reportó un error. Podés intentar de nuevo.', 'error');
      showAlert('tides-shop-alert', 'No se pudo completar el pago con PayPal. Intentá de nuevo.', 'error');
    }
  });

  tidesPayPalButtonsMounted = true;
  const rendered = buttons.render('#paypal-button-container');
  if (rendered && typeof rendered.catch === 'function') {
    rendered.catch(function (err) {
      tidesPayPalButtonsMounted = false;
      console.error('[Surface] No se pudieron montar los botones de PayPal:', err);
      setTidesPayPalStatus('No se pudo cargar el botón de PayPal.', 'error');
    });
  }
}

async function ensureTidesPayPalReady() {
  if (!TIDES_SHOP_ENABLED) return;

  if (!localStorage.getItem(TOKEN_KEY)) {
    resetTidesPayPalButtons();
    setTidesPayPalStatus('Iniciá sesión para comprar Tides con PayPal.', 'info');
    return;
  }
  if (tidesPayPalButtonsMounted) return;

  setTidesPayPalStatus('Cargando PayPal…', 'info');

  try {
    const config = await loadTidesPayPalConfig();
    if (!config || !config.enabled || !config.clientId) {
      resetTidesPayPalButtons();
      setTidesPayPalStatus(
        config && config.configured === false
          ? 'PayPal todavía no está configurado en el servidor.'
          : 'El pago con PayPal no está disponible por el momento.',
        'info'
      );
      return;
    }

    await loadTidesPayPalSdk(config);

    if (!localStorage.getItem(TOKEN_KEY)) {
      resetTidesPayPalButtons();
      setTidesPayPalStatus('Iniciá sesión para comprar Tides con PayPal.', 'info');
      return;
    }

    mountTidesPayPalButtons();
    if (tidesPayPalButtonsMounted) {
      const isSandbox = config.environment === 'sandbox';
      setTidesPayPalStatus(
        isSandbox ? 'Modo prueba: PayPal Sandbox, no se cobra dinero real.' : '',
        isSandbox ? 'info' : ''
      );
    }
  } catch (err) {
    console.error('[Surface] Error preparando PayPal:', err);
    resetTidesPayPalButtons();
    setTidesPayPalStatus('No se pudo cargar PayPal. Recargá la página e intentá de nuevo.', 'error');
  }
}

// =========================================
// AÑADIR CRÉDITO — PayPal con monto libre
// =========================================

let creditPendingAmountCents = 0;

function formatCreditUsd(value) {
  const amount = Number(value);
  if (!Number.isFinite(amount) || amount < 0) return 'US$ 0,00';
  try {
    return 'US$ ' + amount.toLocaleString('es-UY', {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2
    });
  } catch (_) {
    return 'US$ ' + amount.toFixed(2).replace('.', ',');
  }
}

function creditLimitsLabel() {
  return 'Mínimo ' + formatCreditUsd(creditLimits.minUsd) +
    ' · Máximo ' + formatCreditUsd(creditLimits.maxUsd);
}

function setCreditStatus(message, tone) {
  const node = el('credit-paypal-status');
  if (!node) return;
  const text = String(message || '').trim();
  node.textContent = text;
  node.classList.toggle('hidden', !text);
  node.classList.remove('is-info', 'is-success', 'is-error');
  if (text && tone) node.classList.add('is-' + tone);
}

function resetCreditPayPalButtons() {
  const container = el('credit-paypal-button-container');
  if (container) container.innerHTML = '';
  creditButtonsMounted = false;
  creditCheckoutBusy = false;
  creditPendingAmountCents = 0;
}

function readCreditAmountInput() {
  const input = el('credit-amount');
  if (!input) return null;
  const raw = String(input.value || '').trim().replace(',', '.');
  if (!raw) return null;
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) return null;

  const cents = Math.round(value * 100);
  if (Math.abs(value * 100 - cents) > 0.001) return null;

  const minCents = Math.round(Number(creditLimits.minUsd || 1) * 100);
  const maxCents = Math.round(Number(creditLimits.maxUsd || 500) * 100);
  if (!Number.isFinite(cents) || cents < minCents || cents > maxCents) return null;
  return { cents: cents, amount: cents / 100 };
}

function normalizeCreditInput() {
  const input = el('credit-amount');
  if (!input) return;
  const raw = String(input.value || '').trim().replace(',', '.');
  if (!raw) return;

  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) {
    input.value = '';
    updateCreditUI();
    return;
  }

  const min = Number(creditLimits.minUsd || 1);
  const max = Number(creditLimits.maxUsd || 500);
  const clamped = Math.min(max, Math.max(min, value));
  input.value = (Math.round(clamped * 100) / 100).toFixed(2).replace('.', ',');
  updateCreditUI();
}

function updateCreditUI() {
  const balanceEl = el('credit-current-balance');
  if (balanceEl) balanceEl.textContent = formatCreditUsd(currentBalances.usd);

  const noteEl = el('credit-limits-note');
  if (noteEl) noteEl.textContent = creditLimitsLabel();

  const parsed = readCreditAmountInput();
  const minUsd = Number(creditLimits.minUsd || 1);
  const maxUsd = Number(creditLimits.maxUsd || 500);
  document.querySelectorAll('[data-credit-amount]').forEach(function (btn) {
    const amount = Number(btn.getAttribute('data-credit-amount') || 0);
    const inRange = amount >= minUsd && amount <= maxUsd;
    btn.hidden = !inRange;
    const cents = Math.round(amount * 100);
    const active = inRange && !!parsed && parsed.cents === cents;
    btn.classList.toggle('is-active', active);
    btn.setAttribute('aria-pressed', String(active));
  });
}

function loadCreditConfig(force) {
  if (creditConfig && !force) return Promise.resolve(creditConfig);
  if (creditConfigPromise && !force) return creditConfigPromise;

  creditConfigPromise = (async function () {
    try {
      const res = await fetch(API_BASE + '/surface/credit/config');
      const data = await res.json().catch(function () { return {}; });
      if (!res.ok) throw new Error(data.error || 'No se pudo consultar la carga de saldo.');

      const minUsd = Number(data.minUsd);
      const maxUsd = Number(data.maxUsd);
      if (Number.isFinite(minUsd) && minUsd > 0) creditLimits.minUsd = minUsd;
      if (Number.isFinite(maxUsd) && maxUsd >= creditLimits.minUsd) creditLimits.maxUsd = maxUsd;

      creditConfig = {
        enabled: !!data.enabled,
        configured: !!data.configured,
        environment: String(data.environment || 'live').toLowerCase() === 'sandbox' ? 'sandbox' : 'live',
        clientId: String(data.clientId || '').trim(),
        currency: String(data.currency || 'USD').toUpperCase(),
        minUsd: creditLimits.minUsd,
        maxUsd: creditLimits.maxUsd
      };
      updateCreditUI();
      return creditConfig;
    } catch (err) {
      creditConfig = null;
      throw err;
    } finally {
      creditConfigPromise = null;
    }
  })();

  return creditConfigPromise;
}

function creditPayPalErrorMessage(data, fallback) {
  const base = String((data && data.error) || fallback || '').trim();
  const detail = String((data && data.detail) || '').trim();
  return detail ? base + ' — ' + detail : base;
}

async function createCreditPayPalOrder(amount) {
  const token = localStorage.getItem(TOKEN_KEY);
  if (!token) {
    handleLogout();
    throw new Error('Iniciá sesión para cargar saldo.');
  }

  const res = await fetch(API_BASE + '/surface/credit/paypal/order', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + token
    },
    body: JSON.stringify({ amount: amount })
  });
  const data = await res.json().catch(function () { return {}; });
  if (res.status === 401) {
    handleLogout();
    throw new Error('Tu sesión venció. Iniciá sesión de nuevo.');
  }
  if (!res.ok) throw new Error(creditPayPalErrorMessage(data, 'No se pudo iniciar la carga de saldo.'));

  const orderId = String(data.orderId || '').trim();
  if (!orderId) throw new Error('PayPal no devolvió una orden válida.');

  const orderEnv = String(data.environment || '').toLowerCase() === 'sandbox' ? 'sandbox' : 'live';
  if (creditConfig && creditConfig.environment !== orderEnv) {
    creditConfig = null;
    throw new Error('El modo de PayPal cambió. Recargá la página para continuar.');
  }
  return orderId;
}

async function captureCreditPayPalOrder(orderId, cents) {
  const token = localStorage.getItem(TOKEN_KEY);
  if (!token) {
    handleLogout();
    throw new Error('Iniciá sesión para confirmar la carga.');
  }
  if (!orderId) throw new Error('PayPal no devolvió una orden válida.');

  setCreditStatus('Confirmando el pago con PayPal…', 'info');

  const res = await fetch(API_BASE + '/surface/credit/paypal/capture', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + token
    },
    body: JSON.stringify({ orderId: orderId })
  });
  const data = await res.json().catch(function () { return {}; });
  if (res.status === 401) {
    handleLogout();
    throw new Error('Tu sesión venció. Iniciá sesión de nuevo.');
  }
  if (res.status === 409) {
    const pendingMessage = data.error || 'Tu pago quedó pendiente de confirmación. El saldo se acreditará automáticamente.';
    setCreditStatus(pendingMessage, 'info');
    showAlert('credit-alert', pendingMessage, 'info');
    showToast('Pago pendiente de confirmación.');
    return null;
  }
  if (!res.ok) throw new Error(creditPayPalErrorMessage(data, 'No se pudo confirmar la carga de saldo.'));

  const credited = Number(data.credited || 0);
  const amountUsd = Number(data.amountUsd || (Number(cents || 0) / 100) || 0);

  if (data.alreadyApplied) {
    const already = 'Este pago ya estaba acreditado en tu cuenta.';
    setCreditStatus(already, 'info');
    showAlert('credit-alert', already, 'info');
  } else {
    const message = '¡Listo! Se acreditaron ' + formatCreditUsd(amountUsd || credited) + ' en tu saldo.';
    setCreditStatus(message, 'success');
    showAlert('credit-alert', message, 'success');
    showToast('+' + formatCreditUsd(amountUsd || credited) + ' de saldo.');
  }

  const newBalance = Number(data.newBalance);
  if (Number.isFinite(newBalance)) {
    currentBalances.usd = newBalance;
    updateCreditUI();
    updateBalanceDisplay();
    updatePillsBalances();
  }
  await loadWalletData();
  return data;
}

function mountCreditPayPalButtons() {
  const container = el('credit-paypal-button-container');
  if (!container) return;
  if (creditButtonsMounted) return;
  if (!window.paypal || !window.paypal.Buttons) return;
  if (!localStorage.getItem(TOKEN_KEY)) {
    setCreditStatus('Iniciá sesión para cargar saldo con PayPal.', 'info');
    return;
  }

  container.innerHTML = '';
  const buttons = window.paypal.Buttons({
    style: {
      layout: 'vertical',
      shape: 'pill',
      label: 'paypal',
      height: 46,
      color: 'gold'
    },
    onClick: function (_data, actions) {
      if (creditCheckoutBusy) return actions.reject();
      if (!localStorage.getItem(TOKEN_KEY)) {
        showAlert('credit-alert', 'Iniciá sesión para cargar saldo.', 'error');
        return actions.reject();
      }
      if (!readCreditAmountInput()) {
        showAlert(
          'credit-alert',
          'Elegí un monto entre ' + formatCreditUsd(creditLimits.minUsd) +
            ' y ' + formatCreditUsd(creditLimits.maxUsd) + '.',
          'error'
        );
        const input = el('credit-amount');
        if (input) input.focus();
        return actions.reject();
      }
      hideAlert('credit-alert');
      return actions.resolve();
    },
    createOrder: async function () {
      const parsed = readCreditAmountInput();
      if (!parsed) {
        const msg = 'Elegí un monto válido para cargar.';
        setCreditStatus(msg, 'error');
        showAlert('credit-alert', msg, 'error');
        throw new Error(msg);
      }

      creditCheckoutBusy = true;
      creditPendingAmountCents = parsed.cents;
      setCreditStatus('Abriendo PayPal…', 'info');

      try {
        return await createCreditPayPalOrder(parsed.amount);
      } catch (err) {
        creditCheckoutBusy = false;
        creditPendingAmountCents = 0;
        setCreditStatus(err.message || 'No se pudo iniciar la carga.', 'error');
        showAlert('credit-alert', err.message || 'No se pudo iniciar la carga con PayPal.', 'error');
        throw err;
      }
    },
    onApprove: async function (data) {
      const cents = creditPendingAmountCents;
      try {
        await captureCreditPayPalOrder(String(data && data.orderID || ''), cents);
      } catch (err) {
        console.error('[Surface] Error confirmando carga PayPal:', err);
        setCreditStatus(err.message || 'No se pudo confirmar la carga.', 'error');
        showAlert(
          'credit-alert',
          err.message || 'No se pudo confirmar la carga. Si ya pagaste, esperá unos segundos y recargá Surface.',
          'error'
        );
        showToast('No se pudo confirmar la carga.');
      } finally {
        creditCheckoutBusy = false;
        creditPendingAmountCents = 0;
      }
    },
    onCancel: function () {
      creditCheckoutBusy = false;
      creditPendingAmountCents = 0;
      setCreditStatus('Pago cancelado. No se descontó nada.', 'info');
    },
    onError: function (err) {
      console.error('[Surface] Error de PayPal (saldo):', err);
      creditCheckoutBusy = false;
      creditPendingAmountCents = 0;
      setCreditStatus('PayPal reportó un error. Podés intentar de nuevo.', 'error');
      showAlert('credit-alert', 'No se pudo completar la carga con PayPal. Intentá de nuevo.', 'error');
    }
  });

  creditButtonsMounted = true;
  const rendered = buttons.render('#credit-paypal-button-container');
  if (rendered && typeof rendered.catch === 'function') {
    rendered.catch(function (err) {
      creditButtonsMounted = false;
      console.error('[Surface] No se pudieron montar los botones de saldo:', err);
      setCreditStatus('No se pudo cargar el botón de PayPal.', 'error');
    });
  }
}

async function ensureCreditPayPalReady() {
  if (!localStorage.getItem(TOKEN_KEY)) {
    resetCreditPayPalButtons();
    setCreditStatus('Iniciá sesión para cargar saldo con PayPal.', 'info');
    return;
  }
  if (creditButtonsMounted) {
    updateCreditUI();
    return;
  }

  setCreditStatus('Cargando PayPal…', 'info');

  try {
    const config = await loadCreditConfig();
    if (!config || !config.enabled || !config.clientId) {
      resetCreditPayPalButtons();
      setCreditStatus(
        config && config.configured === false
          ? 'PayPal todavía no está configurado en el servidor.'
          : 'La carga de saldo con PayPal no está disponible por el momento.',
        'info'
      );
      return;
    }

    await loadTidesPayPalSdk(config);

    if (!localStorage.getItem(TOKEN_KEY)) {
      resetCreditPayPalButtons();
      setCreditStatus('Iniciá sesión para cargar saldo con PayPal.', 'info');
      return;
    }

    mountCreditPayPalButtons();
    if (creditButtonsMounted) {
      const isSandbox = config.environment === 'sandbox';
      setCreditStatus(
        isSandbox ? 'Modo prueba: PayPal Sandbox, no se cobra dinero real.' : '',
        isSandbox ? 'info' : ''
      );
      updateCreditUI();
    }
  } catch (err) {
    console.error('[Surface] Error preparando PayPal para saldo:', err);
    resetCreditPayPalButtons();
    setCreditStatus('No se pudo cargar PayPal. Recargá la página e intentá de nuevo.', 'error');
  }
}

function getTidesPackage(packageId) {
  return tidesPackages.find(function (pkg) { return pkg.id === packageId; }) || null;
}

function handleTidesPackageClick(e) {
  const target = e.target && e.target.closest ? e.target.closest('[data-tides-package]') : null;
  if (!target) return;
  selectTidesPackage(target.getAttribute('data-tides-package'));
}

function selectTidesPackage(packageId) {
  if (!getTidesPackage(packageId)) return;
  selectedTidesPackageId = packageId;
  document.querySelectorAll('[data-tides-package]').forEach(function (btn) {
    const active = btn.getAttribute('data-tides-package') === packageId;
    btn.classList.toggle('is-active', active);
    btn.setAttribute('aria-pressed', String(active));
  });
  hideAlert('tides-shop-alert');
  updateTidesSummary();
}

function renderTidesPackagesError(message) {
  const container = el('tides-packages');
  if (!container) return;
  container.innerHTML = '';

  const box = document.createElement('div');
  box.className = 'srf-packs-error';

  const note = document.createElement('p');
  note.className = 'srf-empty';
  note.textContent = message || 'No se pudieron cargar los paquetes de Tides.';

  const retry = document.createElement('button');
  retry.type = 'button';
  retry.className = 'srf-ghost';
  retry.textContent = 'Reintentar';
  retry.addEventListener('click', function () { loadTidesPackages(true); });

  box.appendChild(note);
  box.appendChild(retry);
  container.appendChild(box);
}

function renderTidesPackages() {
  const container = el('tides-packages');
  if (!container) return;
  container.innerHTML = '';

  if (!tidesPackages.length) {
    renderTidesPackagesError('No hay paquetes de Tides disponibles por ahora.');
    return;
  }

  tidesPackages.forEach(function (pkg) {
    const base = Number(pkg.tidesAmount || 0);
    const bonus = Number(pkg.bonus || 0);
    const total = base + bonus;

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'srf-pack';
    btn.setAttribute('data-tides-package', pkg.id);
    btn.setAttribute('aria-pressed', String(pkg.id === selectedTidesPackageId));
    btn.classList.toggle('is-active', pkg.id === selectedTidesPackageId);

    if (bonus > 0) {
      const badge = document.createElement('span');
      badge.className = 'srf-pack-bonus';
      badge.textContent = '+' + formatTidesAmount(bonus) + ' bono';
      btn.appendChild(badge);
    }

    const amount = document.createElement('span');
    amount.className = 'srf-pack-amount';
    amount.textContent = formatTidesAmount(base);
    const unit = document.createElement('small');
    unit.textContent = ' Tides';
    amount.appendChild(unit);

    const totalEl = document.createElement('span');
    totalEl.className = 'srf-pack-total';
    totalEl.textContent = total > base
      ? formatTidesAmount(total) + ' en total'
      : 'Paquete base';

    const price = document.createElement('span');
    price.className = 'srf-pack-price';
    price.textContent = tidesPackagePriceLabel(pkg);

    btn.appendChild(amount);
    btn.appendChild(totalEl);
    btn.appendChild(price);
    container.appendChild(btn);
  });
}

async function loadTidesPackages(force) {
  if (!TIDES_SHOP_ENABLED) return;
  if (tidesPackagesLoading) return;
  if (tidesPackagesLoaded && !force) return;

  tidesPackagesLoading = true;
  const container = el('tides-packages');
  if (container) {
    container.innerHTML = '';
    const loading = document.createElement('p');
    loading.className = 'srf-empty';
    loading.textContent = 'Cargando paquetes…';
    container.appendChild(loading);
  }
  updateTidesSummary();

  try {
    const res = await fetch(API_BASE + '/surface/tides/packages?v=2');
    const data = await res.json().catch(function () { return {}; });
    if (!res.ok) throw new Error(data.error || 'No se pudieron cargar los paquetes.');

    tidesPackages = Array.isArray(data.packages) ? data.packages : [];
    tidesPackagesLoaded = true;
    if (!getTidesPackage(selectedTidesPackageId)) {
      selectedTidesPackageId = tidesPackages.length ? tidesPackages[0].id : '';
    }
    renderTidesPackages();
  } catch (err) {
    console.error('[Surface] Error cargando paquetes Tides:', err);
    tidesPackagesLoaded = false;
    renderTidesPackagesError('No se pudieron cargar los paquetes de Tides.');
  } finally {
    tidesPackagesLoading = false;
    updateTidesSummary();
  }
}

function updateTidesBalanceUI() {
  const value = el('tides-shop-balance');
  if (value) value.textContent = currentBalances.tides.toLocaleString();
}

function updateTidesSummary() {
  const pkg = getTidesPackage(selectedTidesPackageId);
  const packEl = el('tides-summary-pack');
  const baseEl = el('tides-summary-base');
  const bonusEl = el('tides-summary-bonus');
  const totalEl = el('tides-summary-total');
  const priceEl = el('tides-summary-price');

  if (!TIDES_SHOP_ENABLED) {
    setTidesPayPalStatus('Pagos con PayPal no disponibles por el momento.', 'info');
    return;
  }

  if (!pkg) {
    if (packEl) packEl.textContent = '—';
    if (baseEl) baseEl.textContent = '—';
    if (bonusEl) bonusEl.textContent = '—';
    if (totalEl) totalEl.textContent = '—';
    if (priceEl) priceEl.textContent = '—';
    return;
  }

  const base = Number(pkg.tidesAmount || 0);
  const bonus = Number(pkg.bonus || 0);
  const total = base + bonus;

  if (packEl) packEl.textContent = pkg.title || pkg.id;
  if (baseEl) baseEl.textContent = formatTidesAmount(base) + ' Tides';
  if (bonusEl) bonusEl.textContent = bonus > 0 ? '+' + formatTidesAmount(bonus) + ' Tides' : 'Sin bono';
  if (totalEl) totalEl.textContent = formatTidesAmount(total) + ' Tides';
  if (priceEl) priceEl.textContent = tidesPackagePriceLabel(pkg);
}

function buildTidesReturnUrl() {
  try {
    const url = new URL(window.location.href);
    if (/^https?:$/i.test(url.protocol)) {
      const apiOverride = url.searchParams.get('api');
      url.search = '';
      url.hash = '';
      // Conservar el override de API (?api=...) para no perder la sesión local.
      if (apiOverride && /^https?:\/\//i.test(apiOverride)) {
        url.searchParams.set('api', apiOverride);
      }
      return url.toString();
    }
  } catch (_) {}
  // file:// u otro esquema no sirve como back_url: volvemos a la copia pública.
  return API_BASE.replace(/\/+$/, '') + '/ows/Surface/index.html';
}

async function startTidesCheckout() {
  if (!TIDES_SHOP_ENABLED) {
    showToast('La compra de Tides está indisponible por el momento.');
    return;
  }
  if (tidesCheckoutBusy) return;
  const token = localStorage.getItem(TOKEN_KEY);
  if (!token) return handleLogout();

  const pkg = getTidesPackage(selectedTidesPackageId);
  if (!pkg) {
    showAlert('tides-shop-alert', 'Elegí un paquete para continuar.', 'error');
    return;
  }

  tidesCheckoutBusy = true;
  hideAlert('tides-shop-alert');
  updateTidesSummary();

  try {
    const res = await fetch(API_BASE + '/surface/tides/checkout', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
      },
      body: JSON.stringify({ packageId: pkg.id, returnUrl: buildTidesReturnUrl() })
    });
    const data = await res.json().catch(function () { return {}; });
    if (res.status === 401) return handleLogout();
    if (!res.ok) throw new Error(data.error || 'No se pudo iniciar el pago.');
    if (!data.initPoint) throw new Error('Mercado Pago no devolvió un enlace de pago.');

    // Guardar la referencia esperada: evita confirmar un pago de otra compra.
    try {
      sessionStorage.setItem(TIDES_RETURN_KEY + '_ref', String(data.externalReference || ''));
    } catch (_) {}

    window.location.href = data.initPoint;
  } catch (err) {
    console.error('[Surface] Error iniciando checkout Tides:', err);
    tidesCheckoutBusy = false;
    updateTidesSummary();
    showAlert('tides-shop-alert', err.message || 'No se pudo iniciar el pago con Mercado Pago.', 'error');
    showToast('No se pudo iniciar el pago.');
  }
}

function readTidesReturnParams() {
  const out = {};
  const collect = function (search) {
    if (!search) return;
    try {
      new URLSearchParams(search).forEach(function (value, key) {
        if (!(key in out)) out[key] = value;
      });
    } catch (_) {}
  };
  collect(window.location.search || '');
  const hash = String(window.location.hash || '');
  const queryIndex = hash.indexOf('?');
  if (queryIndex !== -1) collect(hash.slice(queryIndex + 1));
  return out;
}

function readPendingTidesReturn() {
  try {
    const raw = sessionStorage.getItem(TIDES_RETURN_KEY);
    const pending = raw ? JSON.parse(raw) : null;
    if (!pending || !Number(pending.paymentId)) return null;
    return pending;
  } catch (_) { return null; }
}

function clearTidesReturn() {
  try {
    sessionStorage.removeItem(TIDES_RETURN_KEY);
    sessionStorage.removeItem(TIDES_RETURN_KEY + '_ref');
  } catch (_) {}
}

function cleanTidesReturnUrl() {
  try {
    const url = new URL(window.location.href);
    stripTidesReturnParams(url.searchParams);
    const hash = String(url.hash || '');
    const queryIndex = hash.indexOf('?');
    if (queryIndex !== -1) {
      const hashPath = hash.slice(0, queryIndex);
      const hashParams = new URLSearchParams(hash.slice(queryIndex + 1));
      stripTidesReturnParams(hashParams);
      const remaining = hashParams.toString();
      url.hash = remaining ? hashPath + '?' + remaining : hashPath;
    }
    window.history.replaceState(null, '', url.pathname + url.search + url.hash);
  } catch (_) {}
}

function stripTidesReturnParams(params) {
  [
    'payment_id', 'collection_id', 'collection_status', 'status',
    'external_reference', 'payment_type', 'merchant_order_id',
    'preference_id', 'site_id', 'processing_mode', 'merchant_account_id'
  ].forEach(function (key) { params.delete(key); });
}

function captureTidesReturnParams() {
  const params = readTidesReturnParams();
  const paymentId = Number(params.payment_id || params.collection_id || 0);
  if (!Number.isFinite(paymentId) || paymentId <= 0) return null;

  const pending = {
    paymentId: paymentId,
    externalReference: String(params.external_reference || '').trim(),
    status: String(params.status || params.collection_status || '').trim().toLowerCase(),
    capturedAt: Date.now()
  };
  try { sessionStorage.setItem(TIDES_RETURN_KEY, JSON.stringify(pending)); } catch (_) {}
  cleanTidesReturnUrl();
  return pending;
}

async function processPendingTidesReturn() {
  if (tidesReturnProcessing) return;
  const token = localStorage.getItem(TOKEN_KEY);
  if (!token) return;

  const pending = readPendingTidesReturn();
  if (!pending) return;

  tidesReturnProcessing = true;
  if (currentView !== 'tides') goToView('tides', { keepHash: true });

  const expectedRef = (function () {
    try { return sessionStorage.getItem(TIDES_RETURN_KEY + '_ref') || ''; } catch (_) { return ''; }
  })();

  if (expectedRef && pending.externalReference && pending.externalReference !== expectedRef) {
    clearTidesReturn();
    tidesReturnProcessing = false;
    showAlert('tides-shop-alert', 'El pago recibido no corresponde a esta compra. No se acreditó nada.', 'error');
    return;
  }

  const status = String(pending.status || '').toLowerCase();
  if (status && status !== 'approved') {
    clearTidesReturn();
    tidesReturnProcessing = false;
    if (status === 'pending' || status === 'in_process' || status === 'authorized') {
      showAlert('tides-shop-alert', 'Tu pago quedó pendiente de confirmación. Cuando Mercado Pago lo apruebe, las Tides se acreditan automáticamente.', 'info');
      showToast('Pago pendiente de confirmación.');
    } else {
      showAlert('tides-shop-alert', 'El pago no se completó (estado: ' + status + '). No se descontó nada; podés intentar de nuevo.', 'error');
      showToast('El pago no se completó.');
    }
    updateTidesSummary();
    return;
  }

  showAlert('tides-shop-alert', 'Estamos confirmando tu pago con Mercado Pago…', 'info');
  updateTidesSummary();

  try {
    const res = await fetch(API_BASE + '/surface/tides/confirm', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
      },
      body: JSON.stringify({
        paymentId: pending.paymentId,
        externalReference: pending.externalReference || ''
      })
    });
    const data = await res.json().catch(function () { return {}; });
    if (res.status === 401) return handleLogout();
    if (!res.ok) {
      const errorMessage = String(data.error || '');
      if (res.status === 403 || /no corresponde|inv[aá]lido|no reconocido/i.test(errorMessage)) {
        clearTidesReturn();
      }
      throw new Error(errorMessage || 'No se pudo confirmar el pago.');
    }

    clearTidesReturn();
    const credited = Number(data.credited || 0);
    const packageTitle = data.package && data.package.title ? data.package.title : '';

    if (data.alreadyApplied) {
      showAlert('tides-shop-alert', 'Este pago ya estaba acreditado en tu cuenta.', 'info');
    } else {
      showAlert(
        'tides-shop-alert',
        '¡Listo! Se acreditaron ' + formatTidesAmount(credited) + ' Tides' +
          (packageTitle ? ' (' + packageTitle + ')' : '') + ' en tu billetera.',
        'success'
      );
      showToast('+' + formatTidesAmount(credited) + ' Tides acreditadas.');
    }

    const newBalance = Number(data.newBalance);
    if (Number.isFinite(newBalance)) {
      currentBalances.tides = newBalance;
      updateBalanceDisplay();
      updatePillsBalances();
      updateTidesBalanceUI();
    }
    await loadWalletData();
  } catch (err) {
    console.error('[Surface] Error confirmando pago Tides:', err);
    showAlert(
      'tides-shop-alert',
      err.message || 'No se pudo confirmar el pago. Si ya pagaste, esperá unos segundos y recargá Surface.',
      'error'
    );
    showToast('No se pudo confirmar el pago.');
  } finally {
    tidesReturnProcessing = false;
    updateTidesSummary();
  }
}

// =========================================
// HISTORIAL
// =========================================

async function loadAllTransactionsFromDB(showLoading) {
  const token = localStorage.getItem(TOKEN_KEY);
  if (!token) return;

  let userId = currentUser ? (currentUser.id || currentUser.uid) : null;
  if (!userId) {
    try { userId = JSON.parse(localStorage.getItem(USER_KEY) || '{}').id; } catch (_) {}
  }
  if (!userId) return renderTransactionsList(allTransactionsList, showLoading);

  if (showLoading) renderTransactionsList(allTransactionsList, true);

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);

    const res = await fetch(API_BASE + '/surface/txs/' + userId, {
      headers: { 'Authorization': 'Bearer ' + token },
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    if (!res.ok) return renderTransactionsList(allTransactionsList);

    const data = await res.json().catch(() => []);
    const rawTxs = Array.isArray(data) ? data : (data.rows || []);

    const dbList = rawTxs.map((tx) => ({
      id: tx.id,
      concepto: tx.concepto || 'Movimiento OWS',
      amount: Number(tx.monto || 0),
      currency: String(tx.moneda || 'GAMBITS').toUpperCase(),
      origen: tx.origen || 'Surface',
      date: tx.created_at ? new Date(tx.created_at) : new Date()
    }));

    const merged = new Map();
    allTransactionsList.forEach((item) => { if (item.id) merged.set(String(item.id), item); });
    dbList.forEach((item) => merged.set(String(item.id), item));

    allTransactionsList = Array.from(merged.values()).sort((a, b) => b.date.getTime() - a.date.getTime());
    renderTransactionsList(allTransactionsList);
    updateTransferPreview();
    if (currentView === 'management') renderManagement();
  } catch (_) {
    renderTransactionsList(allTransactionsList);
  }
}

function renderTransactionsList(listToRender, showLoading) {
  const container = el('modal-activity-list');
  const countBadge = el('modal-tx-count');
  if (!container) return;

  const list = Array.isArray(listToRender) ? listToRender : [];
  if (countBadge) countBadge.textContent = list.length === 1 ? '1 movimiento' : list.length + ' movimientos';

  container.innerHTML = '';

  if (showLoading && list.length === 0) {
    const loading = document.createElement('p');
    loading.className = 'srf-empty';
    loading.textContent = 'Cargando movimientos…';
    container.appendChild(loading);
    return;
  }

  if (list.length === 0) {
    const empty = document.createElement('p');
    empty.className = 'srf-empty';
    empty.textContent = 'Todavía no hay movimientos en tu cuenta.';
    container.appendChild(empty);
    return;
  }

  list.forEach((tx) => container.appendChild(createActivityElement(tx)));
}

/* Filas del historial: se construyen con textContent (sin innerHTML),
   así un nombre de usuario con caracteres raros no rompe el listado. */
function createActivityElement(info) {
  const isPositive = info.amount > 0;
  const row = document.createElement('div');
  row.className = 'srf-mov';

  const left = document.createElement('div');
  left.className = 'srf-mov-left';

  const icon = document.createElement('span');
  icon.className = 'srf-mov-ico';
  icon.textContent = isPositive ? '📥' : '📤';
  icon.setAttribute('aria-hidden', 'true');

  const txt = document.createElement('div');
  txt.className = 'srf-mov-txt';

  const title = document.createElement('span');
  title.className = 'srf-mov-title';
  title.textContent = info.concepto || 'Movimiento OWS';

  const meta = document.createElement('span');
  meta.className = 'srf-mov-meta';

  const when = document.createElement('span');
  when.textContent = info.date.toLocaleDateString() + ' · ' +
    info.date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  meta.appendChild(when);

  const tag = document.createElement('span');
  tag.className = 'srf-tag';
  tag.textContent = info.origen || 'Surface';
  meta.appendChild(tag);

  txt.appendChild(title);
  txt.appendChild(meta);
  left.appendChild(icon);
  left.appendChild(txt);

  const amount = document.createElement('span');
  amount.className = 'srf-mov-amount ' + (isPositive ? 'srf-mov-pos' : 'srf-mov-neg');
  const sign = isPositive ? '+' : (info.amount < 0 ? '−' : '');
  amount.textContent = sign + Math.abs(info.amount).toLocaleString() + ' ' + String(info.currency || '').toUpperCase();

  row.appendChild(left);
  row.appendChild(amount);
  return row;
}

function filterTransactions() {
  const searchVal = (el('tx-search-input')?.value || '').trim().toLowerCase();
  const filterCurrency = (el('tx-filter-currency')?.value || 'all').toLowerCase();

  const filtered = allTransactionsList.filter((tx) => {
    const currency = String(tx.currency || '').toLowerCase();
    if (filterCurrency === 'gambits' && !currency.includes('gambit')) return false;
    if (filterCurrency === 'tides' && !currency.includes('tide')) return false;

    if (!searchVal) return true;
    return String(tx.concepto || '').toLowerCase().includes(searchVal)
      || String(tx.origen || '').toLowerCase().includes(searchVal)
      || currency.includes(searchVal)
      || tx.date.toLocaleDateString().includes(searchVal);
  });

  renderTransactionsList(filtered);
}

/* El historial dejó de ser un modal: ahora es su propia sección (goToView). */

// =========================================
// SECCIONES Y PREFERENCIAS
// =========================================

function getStoredValue(key, allowed, fallback) {
  try {
    const value = localStorage.getItem(key);
    if (allowed.indexOf(value) !== -1) return value;
  } catch (_) {}
  return fallback;
}

function getLayoutMode() {
  return getStoredValue(LAYOUT_KEY, LAYOUT_MODES, 'left');
}

/* Aplica el layout elegido en Configuración > Preferencias. */
function applyLayoutMode(mode) {
  const safe = LAYOUT_MODES.indexOf(mode) !== -1 ? mode : 'left';
  document.body.setAttribute('data-nav', safe);
  const dash = el('dashboard-section');
  if (dash) dash.setAttribute('data-nav', safe);

  document.querySelectorAll('input[name="layout-mode"]').forEach(function (radio) {
    radio.checked = radio.value === safe;
    const opt = radio.closest('.srf-layout-opt');
    if (opt) opt.classList.toggle('is-active', radio.checked);
  });
}

function setLayoutMode(mode, announce) {
  if (LAYOUT_MODES.indexOf(mode) === -1) return;
  try { localStorage.setItem(LAYOUT_KEY, mode); } catch (_) {}
  applyLayoutMode(mode);
  if (announce) {
    const labels = {
      left: 'menú lateral izquierdo',
      right: 'menú lateral derecho',
      top: 'menú superior',
      bottom: 'menú inferior'
    };
    showToast('Diseño actualizado: ' + (labels[mode] || mode) + '.');
  }
}

function animationsEnabled() {
  try { return localStorage.getItem(ANIM_KEY) !== 'off'; } catch (_) { return true; }
}

function applyAnimationPref() {
  const enabled = animationsEnabled();
  document.body.classList.toggle('srf-no-anim', !enabled);
  const toggle = el('pref-animations');
  if (toggle) toggle.checked = enabled;
}

function setAnimationsEnabled(enabled) {
  try { localStorage.setItem(ANIM_KEY, enabled ? 'on' : 'off'); } catch (_) {}
  applyAnimationPref();
  if (enabled) replayEnter(el('view-' + currentView));
  showToast(enabled ? 'Animaciones de entrada activadas.' : 'Animaciones de entrada desactivadas.');
}

function getDefaultCurrency() {
  return getStoredValue(DEFAULT_CURRENCY_KEY, ['gambits', 'tides'], 'gambits');
}

function applyDefaultCurrency() {
  const currency = getDefaultCurrency();
  const input = el('transfer-currency');
  if (input) input.value = currency;
  const select = el('pref-default-currency');
  if (select) select.value = currency;
  updateCurrencySelectionUI();
  updateTransferPreview();
}

function setDefaultCurrency(currency) {
  if (currency !== 'gambits' && currency !== 'tides') return;
  try { localStorage.setItem(DEFAULT_CURRENCY_KEY, currency); } catch (_) {}
  const input = el('transfer-currency');
  if (input) input.value = currency;
  const select = el('pref-default-currency');
  if (select) select.value = currency;
  updateCurrencySelectionUI();
  updateTransferPreview();
  showToast('Divisa predeterminada: ' + currency.toUpperCase() + '.');
}

function viewFromHash() {
  try {
    const match = String(window.location.hash || '').match(/^#\/([a-z-]+)/i);
    const name = match ? match[1].toLowerCase() : '';
    return SURFACE_VIEWS.indexOf(name) !== -1 ? name : '';
  } catch (_) { return ''; }
}

/* Cambia de sección: una sola visible, el menú se marca solo y la URL
   conserva #/seccion para poder recargar sin perder el lugar. */
function goToView(name, opts) {
  if (SURFACE_VIEWS.indexOf(name) === -1) name = 'overview';
  currentView = name;

  SURFACE_VIEWS.forEach(function (view) {
    const section = el('view-' + view);
    if (section) section.classList.toggle('hidden', view !== name);
  });

  document.querySelectorAll('[data-goto-view]').forEach(function (btn) {
    const active = btn.getAttribute('data-goto-view') === name;
    btn.classList.toggle('is-active', active);
    if (btn.classList.contains('srf-nav-btn')) {
      if (active) btn.setAttribute('aria-current', 'page');
      else btn.removeAttribute('aria-current');
    }
  });

  try { localStorage.setItem(VIEW_KEY, name); } catch (_) {}

  if (!(opts && opts.keepHash)) {
    try {
      // Conservar la query (por ejemplo ?api=...) al cambiar de sección.
      const query = window.location.search || '';
      history.replaceState(null, '', query + '#/' + name);
    } catch (_) {}
  }

  onEnterView(name);
  replayEnter(el('view-' + name));

  if (!(opts && opts.noScroll)) {
    window.scrollTo({ top: 0, behavior: animationsEnabled() ? 'smooth' : 'auto' });
  }
}

function onEnterView(name) {
  if (name === 'overview') {
    renderOverview();
    if (!overviewData && !overviewLoading) loadOverviewActivity();
  } else if (name === 'history') {
    syncAutoClearDropdownUI();
    checkAndExecuteAutoClear();
    renderTransactionsList(allTransactionsList, true);
    loadAllTransactionsFromDB(false);
  } else if (name === 'card') {
    displaySelectedCard();
  } else if (name === 'settings') {
    syncSettingsUI();
  } else if (name === 'transfer') {
    updateTransferPreview();
  } else if (name === 'management') {
    setManagementTab(mgTab);
    mgAnnounceOnEnter();
  } else if (name === 'tides') {
    updateTidesBalanceUI();
    updateTidesSummary();
    if (TIDES_SHOP_ENABLED && !tidesPackagesLoaded && !tidesPackagesLoading) loadTidesPackages();
    if (TIDES_SHOP_ENABLED) ensureTidesPayPalReady();
  }
}

// ── Configuración: sub-secciones ────────────────────────
function setSettingsTab(tab) {
  const isPrefs = tab !== 'account';
  el('set-panel-prefs')?.classList.toggle('hidden', !isPrefs);
  el('set-panel-account')?.classList.toggle('hidden', isPrefs);
  document.querySelectorAll('[data-set-tab]').forEach(function (btn) {
    const active = btn.getAttribute('data-set-tab') === (isPrefs ? 'prefs' : 'account');
    btn.classList.toggle('is-active', active);
    btn.setAttribute('aria-selected', String(active));
  });
  if (!isPrefs) updateAccountPanel();
}

function syncSettingsUI() {
  applyLayoutMode(getLayoutMode());
  applyAnimationPref();
  const currencySelect = el('pref-default-currency');
  if (currencySelect) currencySelect.value = getDefaultCurrency();
  syncAutoClearDropdownUI();
  updateAccountPanel();
}

function updateAccountPanel() {
  const name = (currentUser && (currentUser.username || currentUser.id)) || 'Jugador';
  const id = (currentUser && (currentUser.id || currentUser.uid)) || '—';
  const nameEl = el('account-username');
  if (nameEl) nameEl.textContent = name;
  const idEl = el('account-user-id');
  if (idEl) idEl.textContent = String(id);
  const cardsEl = el('account-cards');
  if (cardsEl) cardsEl.textContent = String(userCards.length);
  const adminBtn = el('btn-account-admin');
  if (adminBtn) adminBtn.classList.toggle('hidden', String(name).toLowerCase() !== 'oceanandwild');
}

// =========================================
// GESTIÓN — límites, equivalencias y controles
// =========================================

const MG_KEY_PREFIX = 'ocean_pay_management::';
const MG_LOG_LIMIT = 60;
const MG_TABS = ['summary', 'limits', 'credit', 'rates', 'controls'];
const MG_PERIODS = {
  daily:   { label: 'Hoy',            short: 'hoy',      note: 'Se reinicia a las 00:00.' },
  weekly:  { label: 'Últimos 7 días', short: '7 días',   note: 'Ventana móvil de 7 días.' },
  monthly: { label: 'Este mes',       short: 'este mes', note: 'Se reinicia el día 1 de cada mes.' }
};
const MG_CURRENCIES = [
  { id: 'gambits', name: 'Gambits', code: 'GAMBITS', ico: '🃏' },
  { id: 'tides',   name: 'Tides',   code: 'TIDES',   ico: '🌊' }
];
/* Equivalencias oficiales de OWS. Único origen para todos los usuarios.
   Se completan acá cuando OWS publique las tasas; la interfaz no las edita.
   1 Gambit = USD 0,002 · 1 Tide = USD 0,01 */
const MG_OFFICIAL_RATES = Object.freeze({
  base: 'USD',
  updatedAt: '2026-10-26T23:45:00-03:00',
  values: Object.freeze({ gambits: 0.002, tides: 0.01 })
});
const MG_LOG_ICONS = {
  settings: '⚙️',
  limits:   '🛡️',
  rates:    '🧮',
  transfer: '💸',
  pause:    '⏸️',
  alert:    '🔔',
  credit:   '💳'
};

function mgUserKey() {
  const raw = String((currentUser && (currentUser.username || currentUser.id)) || 'invitado').trim().toLowerCase();
  return MG_KEY_PREFIX + raw;
}

function mgDefaults() {
  return {
    version: 4,
    limits: {
      enabled: false,
      period: 'monthly',
      gambits: 0,
      tides: 0,
      perOp: { gambits: 0, tides: 0 },
      threshold: 80,
      warnings: [80],
      block: true,
      scope: 'all',
      scopeConfirmed: false,
      cardId: null,
      cardLabel: '',
      activeCardId: null,
      suspendedAt: null,
      suspendedUntil: null,
      suspendedPeriod: null
    },
    controls: {
      alertLimit: true,
      alertLarge: true,
      confirmLarge: false,
      largeAmount: 0,
      pauseTransfers: false
    },
    log: []
  };
}

function mgInt(raw) {
  const num = Number(String(raw == null ? '' : raw).replace(',', '.'));
  if (!Number.isFinite(num) || num <= 0) return 0;
  return Math.floor(num);
}

/* Avisos previos del límite: porcentajes únicos, ordenados y acotados. */
const MG_WARNING_LIMIT = 8;

function mgNormalizeWarnings(raw, legacyThreshold) {
  const out = [];
  const push = function (value) {
    const num = Math.round(Number(value));
    if (!Number.isFinite(num) || num < 1 || num > 100) return;
    if (out.indexOf(num) === -1) out.push(num);
  };
  if (Array.isArray(raw)) raw.forEach(push);
  else {
    const legacy = Number(legacyThreshold);
    if (Number.isFinite(legacy) && legacy > 0) push(legacy);
  }
  out.sort(function (a, b) { return a - b; });
  return out.slice(0, MG_WARNING_LIMIT);
}

function mgCardId(raw) {
  const num = Number(raw);
  if (!Number.isFinite(num) || num <= 0) return null;
  return Math.floor(num);
}

function mgIsoOrNull(raw) {
  if (!raw) return null;
  const date = new Date(raw);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function mgRateValue(raw) {
  if (raw == null || raw === '') return null;
  const num = typeof raw === 'number' ? raw : Number(String(raw).replace(',', '.'));
  if (!Number.isFinite(num) || num < 0) return null;
  return Math.round(num * 1000000) / 1000000;
}

function mgBoolean(value, fallback) {
  if (value === undefined || value === null) return !!fallback;
  return !!value;
}

function sanitizeManagement(raw) {
  const base = mgDefaults();
  if (!raw || typeof raw !== 'object') return base;

  const limits = raw.limits && typeof raw.limits === 'object' ? raw.limits : {};
  base.limits.enabled = !!limits.enabled;
  base.limits.period = Object.prototype.hasOwnProperty.call(MG_PERIODS, limits.period) ? limits.period : 'monthly';
  base.limits.gambits = mgInt(limits.gambits);
  base.limits.tides = mgInt(limits.tides);
  const perOp = limits.perOp && typeof limits.perOp === 'object' ? limits.perOp : {};
  base.limits.perOp = { gambits: mgInt(perOp.gambits), tides: mgInt(perOp.tides) };
  // `warnings` es la fuente nueva; `threshold` queda como alias del primero
  // para que los clientes y el backend viejo sigan entendiendo el ajuste.
  const legacyThreshold = limits.threshold;
  const warnings = Array.isArray(limits.warnings)
    ? mgNormalizeWarnings(limits.warnings)
    : mgNormalizeWarnings(null, legacyThreshold == null || legacyThreshold === '' ? 80 : legacyThreshold);
  base.limits.warnings = warnings;
  base.limits.threshold = warnings.length ? warnings[0] : 0;
  base.limits.block = limits.block !== false;

  // Alcance del límite: toda la billetera o una tarjeta puntual.
  base.limits.scope = limits.scope === 'card' ? 'card' : 'all';
  base.limits.scopeConfirmed = limits.scopeConfirmed === true;
  base.limits.cardId = mgCardId(limits.cardId);
  base.limits.cardLabel = String(limits.cardLabel || '').trim().slice(0, 80);
  base.limits.activeCardId = mgCardId(limits.activeCardId);

  // Desactivación temporal: se reactiva sola cuando arranca el período.
  const suspendedUntil = mgIsoOrNull(limits.suspendedUntil);
  const suspendedPeriod = Object.prototype.hasOwnProperty.call(MG_PERIODS, limits.suspendedPeriod)
    ? limits.suspendedPeriod
    : null;
  base.limits.suspendedUntil = suspendedUntil;
  base.limits.suspendedPeriod = suspendedUntil ? suspendedPeriod : null;
  base.limits.suspendedAt = suspendedUntil ? mgIsoOrNull(limits.suspendedAt) : null;

  const controls = raw.controls && typeof raw.controls === 'object' ? raw.controls : {};
  base.controls.alertLimit = mgBoolean(controls.alertLimit, true);
  base.controls.alertLarge = mgBoolean(controls.alertLarge, true);
  base.controls.confirmLarge = mgBoolean(controls.confirmLarge, false);
  base.controls.largeAmount = mgInt(controls.largeAmount);
  base.controls.pauseTransfers = mgBoolean(controls.pauseTransfers, false);

  const log = Array.isArray(raw.log) ? raw.log : [];
  base.log = log.map(function (entry, index) {
    if (!entry || typeof entry !== 'object') return null;
    const text = String(entry.text || '').trim().slice(0, 180);
    if (!text) return null;
    const at = new Date(entry.at);
    const type = String(entry.type || 'settings');
    return {
      id: String(entry.id || ('mgl_' + index)),
      at: isNaN(at.getTime()) ? new Date().toISOString() : at.toISOString(),
      type: Object.prototype.hasOwnProperty.call(MG_LOG_ICONS, type) ? type : 'settings',
      text: text
    };
  }).filter(Boolean).slice(0, MG_LOG_LIMIT);

  return base;
}

function loadManagement() {
  try {
    const raw = localStorage.getItem(mgUserKey());
    const parsed = raw ? JSON.parse(raw) : null;
    const clean = sanitizeManagement(parsed);
    // Migración: versiones anteriores guardaban tasas editables por usuario.
    if (parsed && (parsed.rates || parsed.version !== clean.version)) {
      if (parsed.rates) {
        clean.log = clean.log.filter(function (entry) { return entry.type !== 'rates'; });
      }
      try { localStorage.setItem(mgUserKey(), JSON.stringify(clean)); } catch (_) {}
    }
    return clean;
  } catch (_) {
    return mgDefaults();
  }
}

function saveManagement(state) {
  const clean = sanitizeManagement(state);
  try { localStorage.setItem(mgUserKey(), JSON.stringify(clean)); } catch (_) {}
  mgServerSchedulePush(clean);
  return clean;
}

// =========================================
// GESTIÓN — puente con el servidor
// -----------------------------------------
// El checkout global de Unity valida los topes contra el servidor, así que
// Surface › Gestión no puede vivir solo en localStorage. Reglas:
//   · Si este dispositivo ya tiene ajustes guardados, esos mandan y se suben.
//   · Si no tiene nada, se adoptan los del servidor (otro dispositivo).
//   · Cada cambio local se empuja con un pequeño debounce.
// =========================================

let mgServerPushTimer = null;
let mgServerLastPushed = '';

/* El backend necesita saber qué tarjeta está activa para poder aplicar un
   límite de una sola tarjeta en los checkouts de los juegos. */
function mgServerSnapshot(state) {
  const clean = state ? sanitizeManagement(state) : loadManagement();
  const activeId = mgActiveCardId();
  if (activeId) clean.limits.activeCardId = activeId;
  return clean;
}

function mgServerToken() {
  try { return localStorage.getItem(TOKEN_KEY) || ''; } catch (_) { return ''; }
}

function mgServerSchedulePush(state) {
  if (!mgServerToken()) return;
  const clean = mgServerSnapshot(state);
  const serialized = JSON.stringify(clean);
  if (serialized === mgServerLastPushed) return;

  if (mgServerPushTimer) clearTimeout(mgServerPushTimer);
  mgServerPushTimer = setTimeout(function () {
    mgServerPushTimer = null;
    mgServerPush(clean);
  }, 450);
}

async function mgServerPush(state) {
  const token = mgServerToken();
  if (!token) return;
  const clean = mgServerSnapshot(state);
  const serialized = JSON.stringify(clean);
  if (serialized === mgServerLastPushed) return;

  try {
    const res = await fetch(API_BASE + '/surface/checkout/settings', {
      method: 'PUT',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ management: clean })
    });
    if (res.ok) mgServerLastPushed = serialized;
  } catch (err) {
    console.warn('[Surface] No se pudo sincronizar Gestión con el servidor:', err);
  }
}

async function mgServerHydrate() {
  const token = mgServerToken();
  if (!token) return;

  let localRaw = null;
  try { localRaw = localStorage.getItem(mgUserKey()); } catch (_) {}

  // Este dispositivo ya tiene ajustes propios: se empujan al servidor.
  if (localRaw) {
    mgServerSchedulePush(loadManagement());
    return;
  }

  try {
    const res = await fetch(API_BASE + '/surface/checkout/settings', {
      headers: { 'Authorization': 'Bearer ' + token }
    });
    if (res.status === 401 || !res.ok) return;

    const data = await res.json().catch(function () { return {}; });
    if (!data || !data.management) return;

    const clean = sanitizeManagement(data.management);
    try { localStorage.setItem(mgUserKey(), JSON.stringify(clean)); } catch (_) {}
    mgServerLastPushed = JSON.stringify(clean);
    mgApplyStoredActiveCard(clean);
    mgResolveSuspension({ announce: true });
    renderManagement();
    updateTransferPreview();
    mgScheduleSuspensionWake();
  } catch (err) {
    console.warn('[Surface] No se pudo leer la gestión del servidor:', err);
  }
}

function mgServerReset() {
  if (mgServerPushTimer) clearTimeout(mgServerPushTimer);
  mgServerPushTimer = null;
  mgServerLastPushed = '';
}

// =========================================
// GESTIÓN — alcance por tarjeta y suspensión temporal
// =========================================

function mgActiveCardId() {
  const card = activeCard();
  return card && card.id != null ? mgCardId(card.id) : null;
}

function mgCardById(cardId) {
  const id = mgCardId(cardId);
  if (!id) return null;
  return userCards.find(function (card) { return Number(card.id) === id; }) || null;
}

function mgCardDisplayName(card) {
  if (!card) return 'Tarjeta';
  const digits = String(card.card_number || '').replace(/\D/g, '');
  return (card.card_name || 'Tarjeta') + (digits ? ' · •• ' + digits.slice(-4) : '');
}

function mgScopedCard(state) {
  const limits = (state || loadManagement()).limits;
  return mgCardById(limits.cardId);
}

function mgScopeLabel(state) {
  const limits = (state || loadManagement()).limits;
  if (limits.scope !== 'card') return 'Todas tus tarjetas';
  const card = mgScopedCard(state);
  if (card) return mgCardDisplayName(card);
  if (limits.cardLabel) return limits.cardLabel;
  return 'Tarjeta seleccionada';
}

/* Un límite de una sola tarjeta solo se controla cuando esa tarjeta está
   activa. Si el dato todavía no está disponible, se aplica igual: es más
   seguro frenar de más que dejar pasar el gasto. */
function mgScopeMatchesActiveCard(state) {
  const limits = (state || loadManagement()).limits;
  if (limits.scope !== 'card') return true;
  const scoped = mgScopedCard(state);
  if (!scoped) return true;
  const active = activeCard();
  return !!active && Number(active.id) === Number(scoped.id);
}

function mgApplyStoredActiveCard(state) {
  if (mgCardSelectionTouched) return;
  const limits = (state || loadManagement()).limits;
  const stored = mgCardId(limits.activeCardId);
  if (!stored) return;
  const index = userCards.findIndex(function (card) { return Number(card.id) === stored; });
  if (index < 0 || index === selectedCardIndex) return;
  selectedCardIndex = index;
  populateCardsDropdown();
  displaySelectedCard();
  updateTransferPreview();
}

/* Al cambiar la tarjeta activa se guarda y se empuja al servidor: los
   checkouts de los juegos necesitan saber cuál está activa. */
function mgSyncActiveCard() {
  const activeId = mgActiveCardId();
  const state = loadManagement();
  if (mgCardId(state.limits.activeCardId) === activeId) {
    mgServerSchedulePush(state);
    return;
  }
  state.limits.activeCardId = activeId;
  saveManagement(state);
  if (currentView === 'management') renderManagement();
  updateTransferPreview();
}

function clearMgSuspensionFields(state) {
  if (!state || !state.limits) return;
  state.limits.suspendedAt = null;
  state.limits.suspendedUntil = null;
  state.limits.suspendedPeriod = null;
}

function mgSuspensionActive(state) {
  const limits = (state || loadManagement()).limits;
  if (!limits.enabled || !limits.suspendedUntil) return false;
  if (limits.suspendedPeriod !== limits.period) return false;
  const until = new Date(limits.suspendedUntil).getTime();
  return Number.isFinite(until) && until > Date.now();
}

function mgSuspensionUntilDate(state) {
  if (!mgSuspensionActive(state)) return null;
  const until = new Date(state.limits.suspendedUntil);
  return Number.isNaN(until.getTime()) ? null : until;
}

function mgFormatDateTime(value) {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleDateString('es-AR', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric'
  }) + ' · ' + date.toLocaleTimeString('es-AR', { hour: '2-digit', minute: '2-digit' });
}

function mgNextFixedReset(period, from) {
  const now = from instanceof Date ? from : new Date();
  if (period === 'daily') {
    return new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1, 0, 0, 0, 0);
  }
  if (period === 'monthly') {
    return new Date(now.getFullYear(), now.getMonth() + 1, 1, 0, 0, 0, 0);
  }
  return null;
}

/* Para la ventana móvil de 7 días no hay un reinicio fijo: el tope vuelve a
   tener margen cuando las compras más viejas salen de la ventana. */
function mgWeeklyResetAt(currency, targetRemaining) {
  const now = Date.now();
  const windowMs = 7 * 24 * 60 * 60 * 1000;
  const since = now - windowMs;
  const spends = (Array.isArray(allTransactionsList) ? allTransactionsList : [])
    .filter(function (tx) {
      const amount = Number(tx && tx.amount);
      if (!Number.isFinite(amount) || amount >= 0) return false;
      if (currencyBucket(tx.currency) !== currency) return false;
      const date = tx.date instanceof Date ? tx.date : new Date(tx.date);
      return !Number.isNaN(date.getTime()) && date.getTime() >= since;
    })
    .map(function (tx) {
      const date = tx.date instanceof Date ? tx.date : new Date(tx.date);
      return { at: date.getTime(), amount: Math.abs(Number(tx.amount) || 0) };
    })
    .sort(function (a, b) { return a.at - b.at; });

  if (!spends.length) return new Date(now + windowMs);

  let remaining = spends.reduce(function (sum, tx) { return sum + tx.amount; }, 0);
  const target = Math.max(0, Number(targetRemaining) || 0);
  for (let i = 0; i < spends.length; i++) {
    remaining -= spends[i].amount;
    const expiresAt = spends[i].at + windowMs;
    if (remaining <= target && expiresAt > now) return new Date(expiresAt);
  }

  const lastExpiry = spends[spends.length - 1].at + windowMs;
  return new Date(Math.max(now + 60 * 1000, lastExpiry));
}

/* Fecha en la que el tope del período vuelve a quedar disponible. */
function mgSuspensionUntil(state, opts) {
  const options = opts || {};
  const period = state.limits.period;
  const fixed = mgNextFixedReset(period);
  if (fixed) return fixed;

  const requested = MG_CURRENCIES.some(function (cur) { return cur.id === options.currency; })
    ? options.currency
    : '';
  const requestedAmount = Math.max(0, Number(options.amount) || 0);

  let candidates = requested ? [requested] : [];
  if (!candidates.length) {
    candidates = MG_CURRENCIES
      .filter(function (cur) {
        const limit = Number(state.limits[cur.id] || 0);
        return limit > 0 && mgSpent(cur.id, 'weekly') >= limit;
      })
      .map(function (cur) { return cur.id; });
  }
  if (!candidates.length) {
    candidates = MG_CURRENCIES
      .filter(function (cur) { return Number(state.limits[cur.id] || 0) > 0; })
      .map(function (cur) { return cur.id; });
  }

  let latest = 0;
  candidates.forEach(function (currency) {
    const limit = Number(state.limits[currency] || 0);
    if (limit <= 0) return;
    const amount = currency === requested ? requestedAmount : 1;
    const target = Math.max(0, limit - Math.max(1, amount));
    const reset = mgWeeklyResetAt(currency, target);
    latest = Math.max(latest, reset.getTime());
  });

  if (!latest) latest = Date.now() + 7 * 24 * 60 * 60 * 1000;
  return new Date(Math.max(Date.now() + 60 * 1000, latest));
}

function mgScheduleSuspensionWake() {
  if (mgSuspensionTimer) {
    clearTimeout(mgSuspensionTimer);
    mgSuspensionTimer = null;
  }
  const state = loadManagement();
  if (!state.limits.suspendedUntil) return;
  const until = new Date(state.limits.suspendedUntil).getTime();
  if (!Number.isFinite(until)) return;
  const delay = Math.max(1000, Math.min(until - Date.now() + 1200, 2147483000));
  mgSuspensionTimer = setTimeout(function () {
    mgSuspensionTimer = null;
    if (mgResolveSuspension({ announce: true })) {
      renderManagement();
      updateTransferPreview();
    }
    mgScheduleSuspensionWake();
  }, delay);
}

function mgResolveSuspension(options) {
  const state = loadManagement();
  const limits = state.limits;
  if (!limits.suspendedUntil) return false;

  const until = new Date(limits.suspendedUntil).getTime();
  const periodChanged = !!limits.suspendedPeriod && limits.suspendedPeriod !== limits.period;
  const invalid = !limits.suspendedPeriod || !Number.isFinite(until);
  const expired = invalid || until <= Date.now() || periodChanged;
  if (!expired) return false;

  clearMgSuspensionFields(state);
  mgLogTo(state, 'limits', periodChanged
    ? 'Límite reactivado al cambiar el período.'
    : (invalid
      ? 'Límite reactivado: la desactivación temporal no era válida.'
      : 'Límite reactivado automáticamente al reiniciarse el período.'));
  saveManagement(state);
  mgScheduleSuspensionWake();

  if (!options || options.announce !== false) {
    const key = mgUserKey() + ':reactivated';
    if (!mgSessionNotices[key]) {
      mgSessionNotices[key] = true;
      setTimeout(function () {
        if (periodChanged) {
          showToast('El límite se reactivó al cambiar el período.');
        } else if (invalid) {
          showToast('El límite volvió a estar activo.');
        } else {
          showToast('El límite se reactivó solo al reiniciarse el período.');
        }
      }, 80);
    }
  }
  return true;
}

function mgCheckSuspensionWake() {
  if (mgResolveSuspension({ announce: true })) {
    renderManagement();
    updateTransferPreview();
  }
  mgScheduleSuspensionWake();
}

function handleLimitsEnabledChange(e) {
  const enabled = !!e.target.checked;
  const state = loadManagement();

  if (!enabled) {
    mgUpdate(
      (s) => {
        s.limits.enabled = false;
        clearMgSuspensionFields(s);
      },
      'Límites de gasto desactivados.',
      'limits'
    );
    return;
  }

  const staleCard = state.limits.scope === 'card' &&
    (!mgCardId(state.limits.cardId) || (userCards.length > 0 && !mgScopedCard(state)));
  const needsScopeChoice = !state.limits.scopeConfirmed || staleCard;

  if (needsScopeChoice) {
    // La pregunta se responde en el modal: el switch queda apagado hasta
    // confirmar el alcance (o se queda apagado si se cancela).
    e.target.checked = false;
    openLimitScopeModal({ enableOnApply: true });
    return;
  }

  mgUpdate(
    (s) => {
      s.limits.enabled = true;
      s.limits.activeCardId = mgActiveCardId() || s.limits.activeCardId;
      clearMgSuspensionFields(s);
    },
    'Límites de gasto activados.',
    'limits'
  );
  mgScheduleSuspensionWake();
}

// ── Alcance del límite: todas las tarjetas o una sola ──

function limitScopeRadioNodes() {
  return Array.prototype.slice.call(
    document.querySelectorAll('input[name="limit-scope-radio"]')
  );
}

function selectedLimitScope() {
  const node = limitScopeRadioNodes().find(function (radio) { return radio.checked; });
  return node ? node.value : '';
}

function populateLimitScopeCards(state) {
  const select = el('limit-scope-card-select');
  if (!select) return;

  select.innerHTML = '';
  const placeholder = document.createElement('option');
  placeholder.value = '';
  placeholder.textContent = userCards.length ? 'Elegí una tarjeta' : 'No tenés tarjetas guardadas';
  select.appendChild(placeholder);

  const activeId = mgActiveCardId();
  userCards.forEach(function (card) {
    const option = document.createElement('option');
    option.value = String(card.id);
    let text = mgCardDisplayName(card);
    if (Number(card.id) === activeId) text += ' · activa';
    if (card.is_primary) text += ' · principal';
    option.textContent = text;
    select.appendChild(option);
  });

  const current = mgCardId(state.limits.cardId);
  if (current && userCards.some(function (card) { return Number(card.id) === current; })) {
    select.value = String(current);
  } else if (userCards.length === 1) {
    select.value = String(userCards[0].id);
  } else {
    select.value = '';
  }
  select.disabled = !userCards.length;
}

function hideLimitScopeAlert() {
  const box = el('limit-scope-alert');
  if (box) box.classList.add('hidden');
}

function showLimitScopeAlert(message) {
  const box = el('limit-scope-alert');
  if (!box) return;
  box.textContent = message;
  box.classList.remove('hidden');
}

function syncLimitScopeModalUI() {
  const scope = selectedLimitScope();
  const cardField = el('limit-scope-card-field');
  if (cardField) cardField.classList.toggle('hidden', scope !== 'card');

  const hint = el('limit-scope-hint');
  if (hint) {
    if (!scope) {
      hint.textContent = 'Elegí una opción para aplicar el límite.';
    } else if (scope === 'card') {
      hint.textContent = userCards.length
        ? 'El tope se controla solo cuando esa tarjeta está activa en Surface.'
        : 'Para aplicar el límite a una tarjeta, primero agregá una en Surface.';
    } else {
      hint.textContent = 'El tope se aplica a toda la billetera, sin importar qué tarjeta esté activa.';
    }
  }

  const select = el('limit-scope-card-select');
  const apply = el('btn-apply-limit-scope');
  if (apply) {
    const missingCard = scope === 'card' && !(select && mgCardId(select.value));
    apply.disabled = !scope || missingCard;
  }
  hideLimitScopeAlert();
}

function openLimitScopeModal(options) {
  const state = loadManagement();
  pendingLimitScopeContext = options && typeof options === 'object' ? options : {};

  populateLimitScopeCards(state);
  const current = state.limits.scopeConfirmed ? state.limits.scope : '';
  limitScopeRadioNodes().forEach(function (radio) {
    radio.checked = !!current && radio.value === current;
  });

  hideLimitScopeAlert();
  syncLimitScopeModalUI();

  const modal = el('limit-scope-modal');
  if (!modal) return;
  modal.classList.remove('hidden');

  const focusTarget = document.querySelector('#limit-scope-modal input[name="limit-scope-radio"]:checked') ||
    document.querySelector('#limit-scope-modal input[name="limit-scope-radio"]');
  if (focusTarget) {
    setTimeout(function () { focusTarget.focus({ preventScroll: true }); }, 40);
  }
}

function closeLimitScopeModal(syncSwitch) {
  const modal = el('limit-scope-modal');
  if (modal) modal.classList.add('hidden');
  pendingLimitScopeContext = null;
  hideLimitScopeAlert();

  // Si se canceló después de tocar el switch, el control vuelve a reflejar
  // el estado real (los límites siguen apagados).
  if (syncSwitch !== false) {
    const state = loadManagement();
    const toggle = el('mg-limits-enabled');
    if (toggle) toggle.checked = !!state.limits.enabled;
  }
}

function applyLimitScopeModal() {
  const scope = selectedLimitScope();
  if (!scope) {
    return showLimitScopeAlert('Elegí si el límite controla todas tus tarjetas o solo una.');
  }

  let card = null;
  if (scope === 'card') {
    const select = el('limit-scope-card-select');
    card = mgCardById(select && select.value);
    if (!card) {
      return showLimitScopeAlert(userCards.length
        ? 'Elegí la tarjeta a la que querés aplicar el límite.'
        : 'No tenés tarjetas guardadas en Surface. Agregá una para usar este alcance.');
    }
  }

  const context = pendingLimitScopeContext || {};
  const enable = !!context.enableOnApply;
  const cardLabel = card ? mgCardDisplayName(card) : '';
  const scopeText = card ? cardLabel : 'todas tus tarjetas';

  mgUpdate(
    function (s) {
      s.limits.scope = scope;
      s.limits.scopeConfirmed = true;
      s.limits.cardId = card ? mgCardId(card.id) : null;
      s.limits.cardLabel = cardLabel;
      s.limits.activeCardId = mgActiveCardId() || s.limits.activeCardId;
      if (enable) {
        s.limits.enabled = true;
        // Activar de nuevo arranca sin la desactivación temporal anterior.
        clearMgSuspensionFields(s);
      }
    },
    (enable ? 'Límites de gasto activados. ' : '') + 'Alcance del límite: ' + scopeText + '.',
    'limits'
  );

  closeLimitScopeModal(true);
  mgScheduleSuspensionWake();
  showToast(enable
    ? 'Límites activados para ' + scopeText + '.'
    : 'El límite ahora controla ' + scopeText + '.');
}

function mgReachedLimitCurrencies(state) {
  return MG_CURRENCIES.filter(function (cur) {
    const limit = Number(state.limits[cur.id] || 0);
    return limit > 0 && mgSpent(cur.id, state.limits.period) >= limit;
  }).map(function (cur) { return cur.id; });
}

/* Aviso antes de desactivar: deja claro que es temporal y cuándo vuelve. */
function openLimitSnoozeModal(options) {
  const opts = options && typeof options === 'object' ? options : {};
  const state = loadManagement();

  if (!state.limits.enabled) {
    showToast('Los límites de gasto están desactivados.');
    return;
  }
  if (!mgScopeMatchesActiveCard(state)) {
    showToast('El límite pertenece a ' + mgScopeLabel(state) + '. Activá esa tarjeta para desactivarlo.');
    return;
  }
  if (mgSuspensionActive(state)) {
    showToast('El límite ya está desactivado hasta ' + mgFormatDateTime(mgSuspensionUntilDate(state)) + '.');
    return;
  }

  const reached = mgReachedLimitCurrencies(state);
  let currency = '';
  if (opts.currency && reached.indexOf(opts.currency) !== -1) {
    currency = opts.currency;
  } else if (reached.length) {
    currency = reached[0];
  } else {
    const withLimit = MG_CURRENCIES.find(function (cur) {
      return Number(state.limits[cur.id] || 0) > 0;
    });
    currency = withLimit ? withLimit.id : '';
  }
  if (!currency) {
    showToast('No hay un tope configurado para desactivar.');
    return;
  }

  const amount = Math.max(0, Number(opts.amount) || 0);
  const until = mgSuspensionUntil(state, { currency: currency, amount: amount });
  pendingLimitSnoozeContext = { currency: currency, amount: amount };

  const scopeEl = el('limit-snooze-scope');
  if (scopeEl) scopeEl.textContent = mgScopeLabel(state);
  const periodEl = el('limit-snooze-period');
  if (periodEl) {
    periodEl.textContent = MG_PERIODS[state.limits.period]
      ? MG_PERIODS[state.limits.period].label
      : 'Período';
  }
  const untilEl = el('limit-snooze-until');
  if (untilEl) untilEl.textContent = mgFormatDateTime(until);
  const noteEl = el('limit-snooze-note');
  if (noteEl) {
    noteEl.textContent = state.limits.period === 'weekly'
      ? 'Se reactiva solo cuando las compras más viejas salgan de la ventana de 7 días. Podés reactivarlo antes desde Gestión.'
      : 'También podés reactivarlo antes desde Gestión › Límite de gasto.';
  }

  const modal = el('limit-snooze-modal');
  if (!modal) return;
  modal.classList.remove('hidden');

  const cancel = document.querySelector('#limit-snooze-modal [data-close-limit-snooze]');
  if (cancel) {
    setTimeout(function () { cancel.focus({ preventScroll: true }); }, 40);
  }
}

function closeLimitSnoozeModal() {
  const modal = el('limit-snooze-modal');
  if (modal) modal.classList.add('hidden');
  pendingLimitSnoozeContext = null;
}

function confirmLimitSnooze() {
  const context = pendingLimitSnoozeContext;
  if (!context) return;

  // Se recalcula al confirmar por si el período cambió con el modal abierto.
  const state = loadManagement();
  const until = mgSuspensionUntil(state, { currency: context.currency, amount: context.amount });
  const untilIso = until.toISOString();

  mgUpdate(
    function (s) {
      s.limits.suspendedAt = new Date().toISOString();
      s.limits.suspendedUntil = untilIso;
      s.limits.suspendedPeriod = s.limits.period;
    },
    'Límite desactivado hasta ' + mgFormatDateTime(until) + '. Se reactiva solo.',
    'limits'
  );

  closeLimitSnoozeModal();
  mgScheduleSuspensionWake();
  showToast('Límite desactivado. Se reactiva solo el ' + mgFormatDateTime(until) + '.');
}

function reactivateLimitNow() {
  const state = loadManagement();
  if (!state.limits.suspendedUntil) {
    showToast('El límite ya está activo.');
    return;
  }
  mgUpdate(
    function (s) { clearMgSuspensionFields(s); },
    'Límite reactivado manualmente.',
    'limits'
  );
  mgScheduleSuspensionWake();
  showToast('Límite reactivado.');
}

/* Si una cuenta llega con límites activos pero sin alcance confirmado (por
   ejemplo, datos migrados), se pregunta una vez al entrar a Gestión. */
function mgMaybePromptLimitScope() {
  const state = loadManagement();
  if (!state.limits.enabled || state.limits.scopeConfirmed) return;
  if (!el('limit-scope-modal')?.classList.contains('hidden')) return;
  const key = mgUserKey() + ':scope-prompt';
  if (mgSessionNotices[key]) return;
  mgSessionNotices[key] = true;
  openLimitScopeModal();
}

function mgLogTo(state, type, text) {
  if (!state || !text) return;
  if (!Array.isArray(state.log)) state.log = [];
  state.log.unshift({
    id: 'mgl_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7),
    at: new Date().toISOString(),
    type: String(type || 'settings'),
    text: String(text).slice(0, 180)
  });
  state.log = state.log.slice(0, MG_LOG_LIMIT);
}

function mgAddLog(type, text) {
  const state = loadManagement();
  mgLogTo(state, type, text);
  saveManagement(state);
  if (currentView === 'management') renderManagement();
}

function mgFormatAmount(value) {
  const num = Number(value || 0);
  return Number.isFinite(num) ? num.toLocaleString('es-AR') : '0';
}

function mgFormatMoney(value) {
  if (value == null || value === '' || !Number.isFinite(Number(value))) return 'Pendiente';
  try {
    return new Intl.NumberFormat('es-AR', {
      style: 'currency',
      currency: MG_OFFICIAL_RATES.base || 'USD',
      minimumFractionDigits: 0,
      maximumFractionDigits: 6
    }).format(Number(value));
  } catch (_) {
    return Number(value).toLocaleString('es-AR');
  }
}

function mgFormatDate(value) {
  const date = value instanceof Date ? value : new Date(value);
  if (isNaN(date.getTime())) return '';
  return date.toLocaleDateString('es-AR', { day: '2-digit', month: '2-digit' }) + ' · ' +
    date.toLocaleTimeString('es-AR', { hour: '2-digit', minute: '2-digit' });
}

function mgPeriodStart(period) {
  const now = new Date();
  if (period === 'daily') return new Date(now.getFullYear(), now.getMonth(), now.getDate());
  if (period === 'weekly') return new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  return new Date(now.getFullYear(), now.getMonth(), 1);
}

/* Frase natural del período para los avisos de límite. */
function mgPeriodPhrase(period) {
  if (period === 'daily') return 'hoy';
  if (period === 'weekly') return 'los últimos 7 días';
  return 'este mes';
}

/* Porcentajes de aviso vigentes, de menor a mayor. */
function mgLimitWarnings(state) {
  const limits = (state || loadManagement()).limits;
  const legacy = limits.threshold;
  return mgNormalizeWarnings(
    Array.isArray(limits.warnings) ? limits.warnings : null,
    legacy == null || legacy === '' ? 80 : legacy
  );
}

/* Aviso más alto ya cruzado (0 si todavía no llegó a ninguno). */
function mgWarningLevel(warnings, pct) {
  let level = 0;
  (Array.isArray(warnings) ? warnings : []).forEach(function (value) {
    if (pct >= value) level = value;
  });
  return level;
}

function mgWarningLabel(warnings) {
  const list = Array.isArray(warnings) ? warnings : [];
  return list.length ? list.map(function (value) { return value + '%'; }).join(' · ') : 'Sin avisos';
}

/* Gasto acumulado del período en una divisa (solo movimientos negativos). */
function mgSpent(currency, period) {
  const key = period === 'daily' || period === 'weekly' || period === 'monthly' ? period : 'monthly';
  const since = mgPeriodStart(key).getTime();
  let total = 0;
  (Array.isArray(allTransactionsList) ? allTransactionsList : []).forEach(function (tx) {
    const amount = Number(tx && tx.amount);
    if (!Number.isFinite(amount) || amount >= 0) return;
    if (currencyBucket(tx.currency) !== currency) return;
    const date = tx.date instanceof Date ? tx.date : new Date(tx.date);
    if (isNaN(date.getTime()) || date.getTime() < since) return;
    total += Math.abs(amount);
  });
  return total;
}

/* Evalúa un envío contra la pausa, el tope del período y el máximo por operación. */
function mgEvaluateTransfer(currency, amount, totalDebit) {
  mgResolveSuspension({ announce: true });
  const state = loadManagement();
  const label = currencyLabel(currency);
  const result = {
    blocked: false,
    message: '',
    hint: '',
    button: '',
    warn: false,
    warningLevel: 0,
    periodLimitHit: false,
    suspended: false,
    suspendedUntil: null,
    scopeInactive: false
  };

  if (state.controls.pauseTransfers) {
    result.blocked = true;
    result.button = 'Envíos pausados';
    result.message = 'Los envíos están pausados desde Gestión. Desactivá la pausa para volver a enviar.';
    result.hint = 'Pausa de seguridad activa: no se pueden confirmar envíos.';
    return result;
  }

  if (!state.limits.enabled) return result;

  if (!mgScopeMatchesActiveCard(state)) {
    result.scopeInactive = true;
    result.hint = 'El límite está asignado a ' + mgScopeLabel(state) +
      '. La tarjeta activa es ' + mgCardDisplayName(activeCard()) + ', así que el tope no se aplica.';
    return result;
  }

  const suspended = mgSuspensionActive(state);
  const suspendedUntil = suspended ? mgSuspensionUntilDate(state) : null;
  result.suspended = suspended;
  result.suspendedUntil = suspendedUntil ? suspendedUntil.toISOString() : null;
  if (suspended) {
    result.hint = 'Límite del período desactivado hasta ' + mgFormatDateTime(suspendedUntil) +
      '. Se reactiva automáticamente; el máximo por operación sigue activo.';
  }

  const perOp = Number(state.limits.perOp[currency] || 0);

  if (perOp > 0 && Number(amount) > perOp) {
    result.blocked = true;
    result.button = 'Máximo por envío';
    result.message = 'El máximo por envío en ' + label + ' es ' + mgFormatAmount(perOp) + '.';
    result.hint = 'Supera el máximo por envío de ' + mgFormatAmount(perOp) + ' ' + label + '.';
    return result;
  }

  // La desactivación temporal solo libera el tope del período. El máximo
  // por operación se mantiene como red de seguridad.
  if (suspended) return result;

  const limit = Number(state.limits[currency] || 0);
  const spent = mgSpent(currency, state.limits.period);
  const periodPhrase = mgPeriodPhrase(state.limits.period);
  const debit = Number(totalDebit || 0);

  if (limit <= 0) return result;

  const projected = spent + debit;
  const rawPct = (projected / limit) * 100;
  const pct = Math.round(rawPct);
  const scopeSuffix = state.limits.scope === 'card' ? ' (' + mgScopeLabel(state) + ')' : '';

  if (projected > limit) {
    const detail = 'Tope de ' + label + ' para ' + periodPhrase + scopeSuffix + ': ' + mgFormatAmount(limit) +
      '. Ya usaste ' + mgFormatAmount(spent) + ' y este envío necesita ' + mgFormatAmount(debit) + '.';
    result.hint = 'Este envío supera tu tope de ' + label + ' para ' + periodPhrase + '.';
    result.warn = true;
    result.periodLimitHit = true;
    if (state.limits.block) {
      result.blocked = true;
      result.button = 'Límite alcanzado';
      result.message = detail;
      return result;
    }
    return result;
  }

  if (spent >= limit) {
    result.warn = true;
    result.periodLimitHit = true;
    result.hint = 'Ya alcanzaste tu tope de ' + label + ' para ' + periodPhrase + '.';
    if (state.limits.block) {
      result.blocked = true;
      result.button = 'Límite alcanzado';
      result.message = 'Tope de ' + label + ' para ' + periodPhrase + scopeSuffix + ': ' +
        mgFormatAmount(limit) + '. Ya usaste ' + mgFormatAmount(spent) + '.';
      return result;
    }
    return result;
  }

  const warnings = mgLimitWarnings(state);
  const warningLevel = mgWarningLevel(warnings, rawPct);
  if (state.controls.alertLimit && warningLevel > 0) {
    const nextWarning = warnings.find(function (value) { return value > rawPct; }) || 0;
    result.warn = true;
    result.warningLevel = warningLevel;
    result.hint = 'Con este envío vas a usar el ' + pct + '% de tu tope de ' + label +
      ' (' + mgFormatAmount(limit) + ' para ' + periodPhrase + '); aviso del ' + warningLevel + '%.' +
      (nextWarning ? ' Próximo aviso al ' + nextWarning + '%.' : '');
  }

  return result;
}

/* Margen disponible dentro del límite (para «Usar todo»). */
function mgMaxAvailable(currency, available) {
  mgResolveSuspension({ announce: true });
  const state = loadManagement();
  if (!state.limits.enabled) return available;
  if (!mgScopeMatchesActiveCard(state)) return available;
  if (mgSuspensionActive(state)) return available;
  const limit = Number(state.limits[currency] || 0);
  if (limit <= 0) return available;
  const remaining = Math.max(0, limit - mgSpent(currency, state.limits.period));
  return Math.min(available, remaining);
}

/* Tasa oficial global. No depende del usuario ni se guarda en su dispositivo. */
function mgOfficialRate(code) {
  const key = String(code || '').toLowerCase();
  if (!Object.prototype.hasOwnProperty.call(MG_OFFICIAL_RATES.values, key)) return null;
  return mgRateValue(MG_OFFICIAL_RATES.values[key]);
}

function mgCurrencyName(code) {
  const key = String(code || '').toLowerCase();
  const cur = MG_CURRENCIES.find(function (item) { return item.id === key; });
  return cur ? cur.name : String(code || '—').toUpperCase();
}

function mgCurrencySingular(name) {
  if (name === 'Gambits') return 'Gambit';
  if (name === 'Tides') return 'Tide';
  return name;
}

function mgActiveWarnings(state) {
  mgResolveSuspension({ announce: true });
  state = state || loadManagement();
  const out = [];
  if (state.controls.pauseTransfers) {
    out.push({ tone: 'error', code: 'pause', text: 'Los envíos están pausados desde Gestión.' });
  }
  if (!state.limits.enabled) return out;

  if (!mgScopeMatchesActiveCard(state)) {
    out.push({
      tone: 'info',
      code: 'scope',
      text: 'El límite está asignado a ' + mgScopeLabel(state) + ', que no es la tarjeta activa. Se aplica cuando esa tarjeta esté activa.'
    });
    return out;
  }

  if (mgSuspensionActive(state)) {
    out.push({
      tone: 'info',
      code: 'suspended',
      text: 'Límite desactivado temporalmente hasta ' + mgFormatDateTime(mgSuspensionUntilDate(state)) + '. Se reactiva solo.'
    });
    return out;
  }

  const limitWarnings = mgLimitWarnings(state);
  MG_CURRENCIES.forEach(function (cur) {
    const limit = Number(state.limits[cur.id] || 0);
    if (limit <= 0) return;
    const spent = mgSpent(cur.id, state.limits.period);
    const rawPct = (spent / limit) * 100;
    const pct = Math.round(rawPct);
    if (spent > limit) {
      out.push({
        tone: 'error',
        code: 'limit',
        text: 'Te pasaste del tope de ' + cur.name + ' por ' + mgFormatAmount(spent - limit) + '.'
      });
    } else if (spent === limit) {
      out.push({
        tone: 'error',
        code: 'limit',
        text: 'Llegaste justo al tope de ' + cur.name + ' del período.'
      });
    } else if (state.controls.alertLimit) {
      const level = mgWarningLevel(limitWarnings, rawPct);
      if (level > 0) {
        out.push({
          tone: 'info',
          code: 'near',
          level: level,
          text: 'Usaste el ' + pct + '% del tope de ' + cur.name + ' (aviso del ' + level + '%).'
        });
      }
    }
  });
  return out;
}

function mgEl(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
}

function setManagementTab(tab) {
  mgTab = MG_TABS.indexOf(tab) !== -1 ? tab : 'summary';
  MG_TABS.forEach(function (name) {
    const panel = el('mg-panel-' + name);
    if (panel) panel.classList.toggle('hidden', name !== mgTab);
  });
  document.querySelectorAll('.srf-mg-tabs [data-mg-tab]').forEach(function (btn) {
    const active = btn.getAttribute('data-mg-tab') === mgTab;
    btn.classList.toggle('is-active', active);
    btn.setAttribute('aria-selected', String(active));
  });
  renderManagement();

  if (mgTab === 'credit') {
    updateCreditUI();
    ensureCreditPayPalReady();
  }
}

function mgUpdate(mutator, logText, type) {
  const state = loadManagement();
  const before = JSON.stringify(state);
  try { mutator(state); } catch (_) {}
  if (JSON.stringify(state) === before) return state;
  if (logText) mgLogTo(state, type || 'settings', logText);
  saveManagement(state);
  renderManagement();
  updateTransferPreview();
  return state;
}

function mgAnnounceOnEnter() {
  const key = mgUserKey();
  if (!mgSessionNotices[key]) {
    const state = loadManagement();
    const warnings = mgActiveWarnings(state).filter(function (w) { return w.tone === 'error'; });
    if (warnings.length) {
      mgSessionNotices[key] = true;
      showToast(warnings[0].text);
    }
  }
  mgMaybePromptLimitScope();
}

function renderManagement() {
  mgResolveSuspension({ announce: true });
  const state = loadManagement();
  renderMgStatusPill(state);
  renderMgSummary(state);
  renderMgLimits(state);
  renderMgRates();
  renderMgControls(state);
  renderMgLogs(state);
}

function renderMgStatusPill(state) {
  const pill = el('mg-status-pill');
  if (!pill) return;
  pill.classList.remove('is-ok', 'is-bad', 'is-warn');
  if (state.controls.pauseTransfers) {
    pill.textContent = 'Envíos pausados';
    pill.classList.add('is-bad');
  } else if (state.limits.enabled) {
    if (mgSuspensionActive(state)) {
      pill.textContent = 'Límite pausado';
      pill.classList.add('is-warn');
    } else if (!mgScopeMatchesActiveCard(state)) {
      pill.textContent = 'Límite en otra tarjeta';
      pill.classList.add('is-warn');
    } else {
      pill.textContent = 'Límites activos';
      pill.classList.add('is-ok');
    }
  } else {
    pill.textContent = 'Sin límites';
  }
}

function renderMgSummary(state) {
  const period = state.limits.period;
  const periodShort = MG_PERIODS[period] ? MG_PERIODS[period].short : 'período';
  const periodLabel = MG_PERIODS[period] ? MG_PERIODS[period].label : 'Período';
  const officialRates = MG_CURRENCIES.map(function (cur) { return mgOfficialRate(cur.id); });
  const totalRates = officialRates.length;
  const loadedRates = officialRates.filter(function (value) { return value != null; }).length;
  const suspended = mgSuspensionActive(state);
  const suspendedDate = suspended ? mgSuspensionUntilDate(state) : null;
  const scopeApplies = mgScopeMatchesActiveCard(state);
  const scopeLabel = mgScopeLabel(state);
  const limitWarnings = mgLimitWarnings(state);

  // Aviso superior: pausa, tope superado o cercanía al límite.
  const alertBox = el('mg-summary-alert');
  const warnings = mgActiveWarnings(state);
  if (alertBox) {
    alertBox.innerHTML = '';
    if (warnings.length) {
      const isError = warnings.some(function (w) { return w.tone === 'error'; });
      alertBox.className = 'srf-alert srf-alert-' + (isError ? 'error' : 'info');
      alertBox.classList.remove('hidden');
      alertBox.appendChild(mgEl('span', 'srf-alert-text', warnings.map(function (w) { return w.text; }).join(' · ')));
      if (warnings.some(function (w) { return w.code === 'limit'; })) {
        const cta = mgEl('button', 'srf-textlink srf-alert-cta', 'Desactivar límite hasta el reinicio');
        cta.type = 'button';
        cta.addEventListener('click', function () { openLimitSnoozeModal(); });
        alertBox.appendChild(cta);
      }
    } else {
      alertBox.classList.add('hidden');
    }
  }

  // Tarjetas de resumen.
  const stats = el('mg-summary-stats');
  if (stats) {
    stats.innerHTML = '';

    MG_CURRENCIES.forEach(function (cur) {
      const spent = mgSpent(cur.id, period);
      const limit = Number(state.limits[cur.id] || 0);
      const pct = limit > 0 ? (spent / limit) * 100 : 0;
      const card = mgEl('div', 'srf-stat srf-mg-stat');
      card.appendChild(mgEl('span', 'srf-stat-label', cur.ico + ' ' + cur.name + ' · ' + periodShort));

      const value = mgEl('b', 'srf-stat-value', mgFormatAmount(spent));
      if (limit > 0 && spent >= limit && !suspended && scopeApplies) value.classList.add('srf-stat-neg');
      else if (limit > 0 && limitWarnings.length && pct >= limitWarnings[0] && !suspended && scopeApplies) value.classList.add('srf-mg-warn');
      card.appendChild(value);

      let sub = limit > 0
        ? 'Tope ' + mgFormatAmount(limit) + ' · ' + Math.min(999, Math.round(pct)) + '% usado'
        : (state.limits.enabled ? 'Sin tope para esta divisa' : 'Límites desactivados');
      if (limit > 0 && suspended) sub += ' · pausado';
      else if (limit > 0 && !scopeApplies) sub += ' · otra tarjeta';
      card.appendChild(mgEl('small', 'srf-stat-sub', sub));
      stats.appendChild(card);
    });

    const limitsCard = mgEl('div', 'srf-stat srf-mg-stat');
    limitsCard.appendChild(mgEl('span', 'srf-stat-label', 'Límites de gasto'));
    const limitsValue = mgEl('b', 'srf-stat-value',
      suspended ? 'Pausados' : (state.limits.enabled ? 'Activos' : 'Inactivos'));
    limitsValue.classList.add(suspended ? 'srf-mg-warn' : (state.limits.enabled ? 'srf-ok-text' : 'srf-mg-muted'));
    limitsCard.appendChild(limitsValue);
    let limitsSub;
    if (!state.limits.enabled) limitsSub = 'Activá un tope para empezar';
    else if (suspended) limitsSub = 'Se reactiva ' + mgFormatDateTime(suspendedDate);
    else limitsSub = scopeLabel + ' · avisos ' + mgWarningLabel(limitWarnings);
    limitsCard.appendChild(mgEl('small', 'srf-stat-sub', limitsSub));
    stats.appendChild(limitsCard);

    const ratesCard = mgEl('div', 'srf-stat srf-mg-stat');
    ratesCard.appendChild(mgEl('span', 'srf-stat-label', 'Equivalencias'));
    ratesCard.appendChild(mgEl('b', 'srf-stat-value', loadedRates + ' de ' + totalRates));
    ratesCard.appendChild(mgEl('small', 'srf-stat-sub',
      loadedRates === 0
        ? 'Pendientes de OWS'
        : 'Oficiales en ' + MG_OFFICIAL_RATES.base));
    stats.appendChild(ratesCard);
  }

  const usageSub = el('mg-usage-sub');
  if (usageSub) {
    if (!state.limits.enabled) {
      usageSub.textContent = 'Activá los límites para poner un tope por período.';
    } else {
      usageSub.textContent = 'Período: ' + periodLabel + '. ' + (MG_PERIODS[period] ? MG_PERIODS[period].note : '') +
        ' Alcance: ' + scopeLabel + '.' +
        (suspended ? ' Desactivado hasta ' + mgFormatDateTime(suspendedDate) + '.' : '');
    }
  }

  const usage = el('mg-summary-usage');
  if (usage) {
    usage.innerHTML = '';
    MG_CURRENCIES.forEach(function (cur) {
      const spent = mgSpent(cur.id, period);
      const limit = Number(state.limits[cur.id] || 0);
      const rawPct = limit > 0 ? (spent / limit) * 100 : 0;
      const pct = Math.min(100, Math.max(0, rawPct));

      const row = mgEl('div', 'srf-mg-usage-row');

      const top = mgEl('div', 'srf-mg-usage-top');
      top.appendChild(mgEl('span', 'srf-mg-usage-name', cur.ico + ' ' + cur.name));
      top.appendChild(mgEl('b', 'srf-mg-usage-value', limit > 0
        ? mgFormatAmount(spent) + ' / ' + mgFormatAmount(limit)
        : mgFormatAmount(spent)));
      row.appendChild(top);

      const bar = mgEl('span', 'srf-mg-usage-bar');
      const fill = mgEl('span', 'srf-mg-usage-fill');
      fill.style.width = pct + '%';
      if (limit > 0 && spent > limit && !suspended && scopeApplies) fill.classList.add('is-over');
      else if (limit > 0 && limitWarnings.length && rawPct >= limitWarnings[0] && !suspended && scopeApplies) fill.classList.add('is-warn');
      else if (limit > 0 && (!scopeApplies || suspended)) fill.classList.add('is-paused');
      bar.appendChild(fill);
      row.appendChild(bar);

      let note;
      if (suspended) {
        note = 'Límite desactivado hasta ' + mgFormatDateTime(suspendedDate) + '.';
      } else if (!scopeApplies) {
        note = 'Solo se controla con ' + scopeLabel + ' activa.';
      } else if (limit <= 0) {
        note = state.limits.enabled ? 'Sin tope para ' + cur.name + '.' : 'Los límites están desactivados.';
      } else if (spent > limit) {
        note = 'Te pasaste por ' + mgFormatAmount(spent - limit) + ' ' + cur.name + '.';
      } else if (spent === limit) {
        note = 'Alcanzaste justo el tope de ' + cur.name + '.';
      } else {
        note = 'Te quedan ' + mgFormatAmount(limit - spent) + ' ' + cur.name + ' · ' + Math.round(rawPct) + '% usado.';
      }
      row.appendChild(mgEl('small', 'srf-mg-usage-note', note));
      usage.appendChild(row);
    });
  }

  const status = el('mg-summary-status');
  if (status) {
    status.innerHTML = '';
    status.appendChild(mgRow('Límites', state.limits.enabled ? (suspended ? 'Pausados' : 'Activos') : 'Inactivos',
      state.limits.enabled ? (suspended ? 'bad' : 'ok') : ''));
    status.appendChild(mgRow('Alcance', scopeLabel));
    if (state.limits.scope === 'card' && !scopeApplies) {
      status.appendChild(mgRow('Tarjeta activa', mgCardDisplayName(activeCard())));
    }
    status.appendChild(mgRow('Período', state.limits.enabled ? periodLabel : '—'));
    status.appendChild(mgRow('Se reactiva', suspended ? mgFormatDateTime(suspendedDate) : '—',
      suspended ? 'warn' : ''));
    status.appendChild(mgRow('Envíos', state.controls.pauseTransfers ? 'Pausados' : 'Habilitados', state.controls.pauseTransfers ? 'bad' : 'ok'));
    status.appendChild(mgRow('Avisos previos',
      state.controls.alertLimit ? (limitWarnings.length ? mgWarningLabel(limitWarnings) : 'Sin avisos') : 'Desactivado'));
    status.appendChild(mgRow('Bloqueo al superar', state.limits.block ? 'Activado' : 'Solo aviso', state.limits.block ? 'ok' : ''));
    status.appendChild(mgRow('Equivalencias', loadedRates === totalRates && totalRates > 0 ? 'Oficiales' : 'Pendientes de OWS', loadedRates === totalRates && totalRates > 0 ? 'ok' : ''));
  }
}

function mgRow(label, value, tone) {
  const row = mgEl('div', 'srf-rows-item');
  row.appendChild(mgEl('span', null, label));
  const bold = mgEl('b', null, value);
  if (tone === 'ok') bold.classList.add('srf-ok-text');
  if (tone === 'bad') bold.classList.add('srf-mg-bad-text');
  if (tone === 'warn') bold.classList.add('srf-mg-warn');
  row.appendChild(bold);
  return row;
}

function mgIsEditing(node) {
  return !!node && document.activeElement === node;
}

function mgWarningSuggestion(warnings, after) {
  const suggestions = [50, 65, 80, 90, 95];
  const list = Array.isArray(warnings) ? warnings : [];
  const free = suggestions.filter(function (value) { return list.indexOf(value) === -1; });
  if (!free.length) return null;
  const next = free.find(function (value) { return value > (Number(after) || 0); });
  return next || free[0];
}

function syncMgWarningDraft(raw) {
  const parsed = parseInt(raw, 10);
  const value = Math.min(100, Math.max(5, Math.round((Number.isFinite(parsed) ? parsed : mgWarningDraft) / 5) * 5));
  mgWarningDraft = value;
  mgWarningDraftTouched = true;
  const out = el('mg-warning-out');
  if (out) out.textContent = value + '%';
  updateMgWarningAddButton(loadManagement());
}

function updateMgWarningAddButton(state) {
  const add = el('btn-mg-add-warning');
  if (!add) return;
  const warnings = mgLimitWarnings(state);
  const full = warnings.length >= MG_WARNING_LIMIT;
  const duplicate = warnings.indexOf(mgWarningDraft) !== -1;
  add.disabled = full || duplicate;
  add.textContent = full ? 'Máximo de avisos' : (duplicate ? 'Ya agregado' : 'Agregar aviso');
  add.title = full
    ? 'Podés configurar hasta ' + MG_WARNING_LIMIT + ' avisos previos.'
    : (duplicate ? 'Ese aviso ya está en la lista.' : '');
}

function addMgWarning() {
  const state = loadManagement();
  const warnings = mgLimitWarnings(state);
  if (warnings.length >= MG_WARNING_LIMIT) {
    showToast('Podés configurar hasta ' + MG_WARNING_LIMIT + ' avisos previos.');
    return;
  }
  const value = mgWarningDraft;
  if (warnings.indexOf(value) !== -1) {
    showToast('Ese aviso ya está en la lista.');
    return;
  }
  const next = mgWarningSuggestion(warnings.concat(value), value);
  if (next) mgWarningDraft = next;
  mgWarningDraftTouched = false;
  mgUpdate(function (s) {
    s.limits.warnings = mgNormalizeWarnings(
      (Array.isArray(s.limits.warnings) ? s.limits.warnings : []).concat(value)
    );
    s.limits.threshold = s.limits.warnings[0] || 0;
  }, 'Aviso previo agregado al ' + value + '%.', 'limits');
}

function removeMgWarning(value) {
  const state = loadManagement();
  if (mgLimitWarnings(state).indexOf(value) === -1) return;
  mgUpdate(function (s) {
    s.limits.warnings = mgNormalizeWarnings(
      (Array.isArray(s.limits.warnings) ? s.limits.warnings : []).filter(function (item) {
        return item !== value;
      })
    );
    s.limits.threshold = s.limits.warnings[0] || 0;
  }, 'Aviso previo del ' + value + '% quitado.', 'limits');
}

/* Lista editable de avisos: chips con quitar + selector para sumar otro. */
function renderMgWarnings(state) {
  const warnings = mgLimitWarnings(state);
  // Al abrir Gestión, el selector arranca en un valor que todavía no esté
  // usado para que «Agregar aviso» sea accionable desde el primer momento.
  if (!mgWarningDraftTouched && warnings.indexOf(mgWarningDraft) !== -1) {
    const next = mgWarningSuggestion(warnings, mgWarningDraft);
    if (next) mgWarningDraft = next;
  }

  const chips = el('mg-warning-chips');
  if (chips) {
    chips.innerHTML = '';
    if (!warnings.length) {
      chips.appendChild(mgEl('span', 'srf-mg-warning-empty', 'Sin avisos previos. Agregá uno para que Surface te avise.'));
    } else {
      warnings.forEach(function (value) {
        const chip = mgEl('span', 'srf-mg-warning-chip');
        chip.appendChild(mgEl('b', null, value + '%'));
        const remove = mgEl('button', 'srf-mg-warning-remove', '×');
        remove.type = 'button';
        remove.setAttribute('data-remove-warning', String(value));
        remove.setAttribute('aria-label', 'Quitar aviso al ' + value + '%');
        chip.appendChild(remove);
        chips.appendChild(chip);
      });
    }
  }

  const range = el('mg-warning-range');
  if (range && !mgIsEditing(range)) range.value = String(mgWarningDraft);
  const out = el('mg-warning-out');
  if (out) out.textContent = mgWarningDraft + '%';
  updateMgWarningAddButton(state);
}

function renderMgLimits(state) {
  const enabled = el('mg-limits-enabled');
  if (enabled) enabled.checked = !!state.limits.enabled;

  const period = el('mg-period');
  if (period) period.value = state.limits.period;

  const scopeLabelEl = el('mg-scope-label');
  if (scopeLabelEl) scopeLabelEl.textContent = mgScopeLabel(state);

  const scopeNoteEl = el('mg-scope-note');
  if (scopeNoteEl) {
    if (!state.limits.enabled) {
      scopeNoteEl.textContent = 'Activá los límites para elegir el alcance.';
    } else if (state.limits.scope === 'card') {
      const scoped = mgScopedCard(state);
      if (!scoped) {
        scopeNoteEl.textContent = 'Elegí una tarjeta para aplicar el tope.';
      } else if (!mgScopeMatchesActiveCard(state)) {
        scopeNoteEl.textContent = 'Solo se controla con ' + mgScopeLabel(state) + ' activa. Ahora: ' +
          mgCardDisplayName(activeCard()) + '.';
      } else {
        scopeNoteEl.textContent = 'El tope se controla con ' + mgScopeLabel(state) + ' activa.';
      }
    } else {
      scopeNoteEl.textContent = 'El tope controla toda la billetera, sin importar la tarjeta activa.';
    }
  }

  const scopeBtn = el('btn-mg-change-scope');
  if (scopeBtn) scopeBtn.disabled = !state.limits.enabled;

  const suspendedNow = mgSuspensionActive(state);
  const scopeAppliesNow = mgScopeMatchesActiveCard(state);
  const enforceNow = !suspendedNow && scopeAppliesNow;
  const warnings = mgLimitWarnings(state);

  MG_CURRENCIES.forEach(function (cur) {
    const input = el('mg-limit-' + cur.id);
    if (input && !mgIsEditing(input)) input.value = state.limits[cur.id] ? String(state.limits[cur.id]) : '';

    const perOp = el('mg-perop-' + cur.id);
    if (perOp && !mgIsEditing(perOp)) perOp.value = state.limits.perOp[cur.id] ? String(state.limits.perOp[cur.id]) : '';

    const spent = mgSpent(cur.id, state.limits.period);
    const limit = Number(state.limits[cur.id] || 0);
    const spentEl = el('mg-spent-' + cur.id);
    if (spentEl) spentEl.textContent = 'Gastado ' + MG_PERIODS[state.limits.period].short + ': ' + mgFormatAmount(spent) + ' ' + cur.name;

    const bar = el('mg-bar-' + cur.id);
    if (bar) {
      const pct = limit > 0 ? Math.min(100, (spent / limit) * 100) : 0;
      bar.style.width = pct + '%';
      bar.className = '';
      if (limit > 0 && enforceNow && spent > limit) bar.classList.add('is-over');
      else if (limit > 0 && enforceNow && warnings.length && pct >= warnings[0]) bar.classList.add('is-warn');
      else if (limit > 0 && !enforceNow) bar.classList.add('is-paused');
    }
  });

  renderMgWarnings(state);

  const block = el('mg-block-exceeded');
  if (block) block.checked = state.limits.block !== false;

  renderMgLimitState(state);
}

/* Aviso contextual bajo los topes: pausa temporal, tope alcanzado o tarjeta
   del límite que no está activa. */
function renderMgLimitState(state) {
  const box = el('mg-limit-state');
  if (!box) return;
  box.innerHTML = '';

  if (!state.limits.enabled) return;

  if (mgSuspensionActive(state)) {
    const until = mgSuspensionUntilDate(state);
    const banner = mgEl('div', 'srf-mg-limit-banner is-suspended');
    banner.appendChild(mgEl('span', 'srf-mg-limit-banner-ico', '⏸️'));
    const body = mgEl('span', 'srf-mg-limit-banner-body');
    body.appendChild(mgEl('b', null, 'Límite desactivado temporalmente'));
    body.appendChild(mgEl('small', null, 'Se reactiva solo el ' + mgFormatDateTime(until) + '.'));
    banner.appendChild(body);
    const reactivate = mgEl('button', 'srf-textlink', 'Reactivar ahora');
    reactivate.type = 'button';
    reactivate.addEventListener('click', reactivateLimitNow);
    banner.appendChild(reactivate);
    box.appendChild(banner);
    return;
  }

  if (!mgScopeMatchesActiveCard(state)) {
    const banner = mgEl('div', 'srf-mg-limit-banner is-info');
    banner.appendChild(mgEl('span', 'srf-mg-limit-banner-ico', '💳'));
    const body = mgEl('span', 'srf-mg-limit-banner-body');
    body.appendChild(mgEl('b', null, 'El límite está en otra tarjeta'));
    body.appendChild(mgEl('small', null, 'Se controla con ' + mgScopeLabel(state) + ' activa.'));
    banner.appendChild(body);
    const useCard = mgEl('button', 'srf-textlink', 'Usar esa tarjeta');
    useCard.type = 'button';
    useCard.addEventListener('click', useScopedCardNow);
    banner.appendChild(useCard);
    box.appendChild(banner);
    return;
  }

  const reached = MG_CURRENCIES.filter(function (cur) {
    const limit = Number(state.limits[cur.id] || 0);
    return limit > 0 && mgSpent(cur.id, state.limits.period) >= limit;
  });
  if (!reached.length) return;

  const names = reached.map(function (cur) { return cur.name; }).join(' y ');
  const banner = mgEl('div', 'srf-mg-limit-banner is-reached');
  banner.appendChild(mgEl('span', 'srf-mg-limit-banner-ico', '⚠️'));
  const body = mgEl('span', 'srf-mg-limit-banner-body');
  body.appendChild(mgEl('b', null, 'Alcanzaste el tope de ' + names));
  body.appendChild(mgEl('small', null, 'Si necesitás seguir operando, podés desactivarlo hasta el reinicio del período.'));
  banner.appendChild(body);
  const snooze = mgEl('button', 'srf-warn srf-mg-limit-banner-btn', 'Desactivar hasta el reinicio');
  snooze.type = 'button';
  snooze.addEventListener('click', function () { openLimitSnoozeModal(); });
  banner.appendChild(snooze);
  box.appendChild(banner);
}

function useScopedCardNow() {
  const state = loadManagement();
  const scoped = mgScopedCard(state);
  if (!scoped) {
    openLimitScopeModal();
    return;
  }
  const index = userCards.findIndex(function (card) { return Number(card.id) === Number(scoped.id); });
  if (index < 0) return;
  selectedCardIndex = index;
  mgCardSelectionTouched = true;
  populateCardsDropdown();
  displaySelectedCard();
  mgSyncActiveCard();
  showToast('Tarjeta activa: ' + mgCardDisplayName(scoped) + '.');
}

function mgRateRow(item) {
  const row = mgEl('div', 'srf-mg-rate-row');

  const nameWrap = mgEl('span', 'srf-mg-rate-name');
  nameWrap.appendChild(mgEl('span', 'srf-mg-rate-ico', item.ico || '🪙'));
  const meta = mgEl('span', 'srf-mg-rate-meta');
  meta.appendChild(mgEl('b', null, item.name));
  meta.appendChild(mgEl('small', null, item.code));
  nameWrap.appendChild(meta);

  const value = mgEl('b', 'srf-mg-rate-value', mgFormatMoney(item.value));
  if (item.value == null) value.classList.add('is-pending');
  value.setAttribute('aria-label', 'Valor oficial de 1 ' + mgCurrencySingular(item.name) + ' en ' + MG_OFFICIAL_RATES.base);

  row.appendChild(nameWrap);
  row.appendChild(value);
  return row;
}

function renderMgRates() {
  const body = el('mg-rates-body');
  if (body) {
    body.innerHTML = '';
    MG_CURRENCIES.forEach(function (cur) {
      body.appendChild(mgRateRow({
        id: cur.id,
        name: cur.name,
        code: cur.code,
        ico: cur.ico,
        value: mgOfficialRate(cur.id)
      }));
    });
  }

  const rateItems = MG_CURRENCIES.map(function (cur) { return mgOfficialRate(cur.id); });
  const loaded = rateItems.filter(function (value) { return value != null; }).length;
  const note = el('mg-rates-note');
  if (note) {
    if (loaded === 0) {
      note.textContent = 'Las equivalencias oficiales todavía no fueron publicadas por OWS.';
    } else {
      note.textContent = 'Tasas oficiales en ' + MG_OFFICIAL_RATES.base + ': ' + loaded + ' de ' +
        rateItems.length + ' publicadas. Se aplican a todos los usuarios.' +
        (MG_OFFICIAL_RATES.updatedAt ? ' Actualizadas: ' + mgFormatDate(MG_OFFICIAL_RATES.updatedAt) + '.' : '');
    }
  }

  // Selector de la calculadora: solo divisas oficiales.
  const select = el('mg-calc-currency');
  if (select) {
    const previous = select.value;
    select.innerHTML = '';
    MG_CURRENCIES.forEach(function (cur) {
      const option = document.createElement('option');
      option.value = cur.id;
      option.textContent = cur.ico + ' ' + cur.name;
      select.appendChild(option);
    });
    if (previous && Array.prototype.some.call(select.options, function (opt) { return opt.value === previous; })) {
      select.value = previous;
    }
  }

  updateMgCalculator();
}

function updateMgCalculator() {
  const code = el('mg-calc-currency')?.value || 'gambits';
  const amount = Math.max(0, Number(el('mg-calc-amount')?.value || 0));
  const resultEl = el('mg-calc-result');
  const noteEl = el('mg-calc-note');
  const rate = mgOfficialRate(code);
  const name = mgCurrencyName(code);

  if (rate == null) {
    if (resultEl) resultEl.textContent = 'Pendiente';
    if (noteEl) noteEl.textContent = 'Todavía no hay una tasa oficial publicada para ' + name + '.';
    return;
  }

  if (resultEl) resultEl.textContent = mgFormatMoney(rate * (Number.isFinite(amount) ? amount : 0));
  if (noteEl) {
    noteEl.textContent = '1 ' + mgCurrencySingular(name) + ' = ' + mgFormatMoney(rate) + ' · ' +
      mgFormatAmount(amount) + ' ' + name + '.';
  }
}

function renderMgControls(state) {
  const setChecked = function (id, value) {
    const node = el(id);
    if (node) node.checked = !!value;
  };
  setChecked('mg-alert-limit', state.controls.alertLimit);
  setChecked('mg-alert-large', state.controls.alertLarge);
  setChecked('mg-confirm-large', state.controls.confirmLarge);
  setChecked('mg-pause-transfers', state.controls.pauseTransfers);

  const large = el('mg-large-amount');
  if (large && !mgIsEditing(large)) large.value = state.controls.largeAmount ? String(state.controls.largeAmount) : '';

  const pauseState = el('mg-pause-state');
  if (pauseState) {
    pauseState.textContent = state.controls.pauseTransfers
      ? '⏸️ Envíos pausados hasta que desactives la pausa.'
      : '✅ Envíos habilitados.';
    pauseState.classList.toggle('is-bad', state.controls.pauseTransfers);
  }

  const pauseNote = el('mg-pause-note');
  if (pauseNote) {
    pauseNote.textContent = state.controls.pauseTransfers
      ? 'Mientras la pausa esté activa, Surface no deja confirmar envíos.'
      : 'Con la pausa activa, Surface no deja confirmar envíos hasta que la desactives.';
  }
}

function mgRenderLog(container, entries, emptyText) {
  if (!container) return;
  container.innerHTML = '';
  if (!entries || !entries.length) {
    container.appendChild(mgEl('p', 'srf-empty', emptyText || 'Sin actividad todavía.'));
    return;
  }
  entries.forEach(function (entry) {
    const row = mgEl('div', 'srf-mg-log-row');
    row.appendChild(mgEl('span', 'srf-mg-log-ico', MG_LOG_ICONS[entry.type] || '•'));
    const txt = mgEl('span', 'srf-mg-log-txt');
    txt.appendChild(mgEl('span', 'srf-mg-log-title', entry.text));
    txt.appendChild(mgEl('small', 'srf-mg-log-meta', mgFormatDate(entry.at)));
    row.appendChild(txt);
    container.appendChild(row);
  });
}

function renderMgLogs(state) {
  mgRenderLog(el('mg-log-list'), state.log, 'Sin actividad todavía.');
  mgRenderLog(el('mg-summary-log'), state.log.slice(0, 4), 'Sin actividad todavía.');
}

function exportMgLog() {
  const state = loadManagement();
  const name = (currentUser && (currentUser.username || currentUser.id)) || 'jugador';
  const payload = {
    usuario: name,
    exportado: new Date().toISOString(),
    limites: state.limits,
    controles: state.controls,
    equivalencias_oficiales: {
      base: MG_OFFICIAL_RATES.base,
      actualizado: MG_OFFICIAL_RATES.updatedAt,
      valores: {
        gambits: mgOfficialRate('gambits'),
        tides: mgOfficialRate('tides')
      }
    },
    registro: state.log
  };
  try {
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'surface-gestion-' + new Date().toISOString().slice(0, 10) + '.json';
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1500);
    showToast('Registro exportado.');
  } catch (err) {
    console.error('[Surface] No se pudo exportar el registro:', err);
    showToast('No se pudo exportar el registro.');
  }
}

function clearMgLog() {
  const state = loadManagement();
  state.log = [];
  saveManagement(state);
  renderManagement();
  showToast('Registro de gestión vaciado.');
}

function resetManagement() {
  if (mgSuspensionTimer) { clearTimeout(mgSuspensionTimer); mgSuspensionTimer = null; }
  mgWarningDraft = 80;
  mgWarningDraftTouched = false;
  const state = mgDefaults();
  mgLogTo(state, 'settings', 'Gestión restablecida a los valores iniciales.');
  saveManagement(state);
  mgTab = 'summary';
  setManagementTab('summary');
  mgScheduleSuspensionWake();
  showToast('Gestión restablecida.');
}

// =========================================
// RESUMEN DE ACTIVIDAD (cualquier juego)
// =========================================

/* Normaliza la divisa: la columna `moneda` llega como 'tides', 'TIDES',
   'gambits', 'GAMBITS' o con códigos de otras monedas ('WG', 'ET', 'WC').
   Solo se agrupan las que lo dicen explícitamente. */
function currencyBucket(moneda) {
  const raw = String(moneda == null ? '' : moneda).trim().toLowerCase();
  if (!raw) return 'sin-divisa';
  if (raw.indexOf('gambit') !== -1) return 'gambits';
  if (raw.indexOf('tide') !== -1) return 'tides';
  return raw;
}

function currencyLabel(code) {
  const raw = String(code || '').trim();
  if (!raw) return '—';
  if (raw === 'gambits') return 'GAMBITS';
  if (raw === 'tides') return 'TIDES';
  return raw.toUpperCase();
}

/* Nombres e íconos de los juegos que escriben en ocean_pay_txs.
   Un origen nuevo se muestra tal cual, con un ícono genérico. */
const GAME_META = {
  'wildweapon mayhem':  { label: 'WildWeapon Mayhem',   ico: '⚔️' },
  'wilder gambit':      { label: 'Wilder Gambit',       ico: '🃏' },
  'wild shorts':        { label: 'WildShorts',          ico: '🎬' },
  'wildshorts':         { label: 'WildShorts',          ico: '🎬' },
  'wild savage':        { label: 'Wild Savage',         ico: '🦖' },
  'wildsavage':         { label: 'Wild Savage',         ico: '🦖' },
  'wild explorer':      { label: 'Wild Explorer',       ico: '🧭' },
  'wildexplorer':       { label: 'Wild Explorer',       ico: '🧭' },
  'wild fireworks':     { label: 'Wild Fireworks',      ico: '🎆' },
  'wildfireworks':      { label: 'Wild Fireworks',      ico: '🎆' },
  'wild wave':          { label: 'Wild Wave',           ico: '🌊' },
  'wildwave':           { label: 'Wild Wave',           ico: '🌊' },
  'ecoxion':            { label: 'Ecoxion',             ico: '🌱' },
  'allapp':             { label: 'AllApp',              ico: '📱' },
  'all app':            { label: 'AllApp',              ico: '📱' },
  'surface p2p':        { label: 'Surface · envíos',    ico: '💸' },
  'ocean pay':          { label: 'Surface',             ico: '💠' },
  'oceanpay':           { label: 'Surface',             ico: '💠' },
  'surfacetransfer':    { label: 'Surface · envíos',    ico: '💸' },
  'wildtransfer':       { label: 'WildTransfer',        ico: '🔁' },
  'tiger tasks':        { label: 'Tiger Tasks',         ico: '🐯' },
  'tigertasks':         { label: 'Tiger Tasks',         ico: '🐯' },
  'global goal reward': { label: 'Recompensas OWS',     ico: '🎁' },
  'mercado pago tides': { label: 'Mercado Pago Tides',  ico: '💳' },
  'paypal tides':       { label: 'PayPal Tides',        ico: '🅿️' },
  'paypal tides sandbox': { label: 'PayPal Sandbox',    ico: '🧪' }
};

function gameMeta(origen) {
  const key = String(origen == null ? '' : origen).trim().toLowerCase();
  if (GAME_META[key]) return GAME_META[key];
  const clean = key.replace(/[_-]+/g, ' ').replace(/\s+/g, ' ').trim();
  if (GAME_META[clean]) return GAME_META[clean];
  return {
    label: key ? key.charAt(0).toUpperCase() + key.slice(1) : 'OWS',
    ico: '🎮'
  };
}

function toDateOrNull(value) {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  return isNaN(date.getTime()) ? null : date;
}

function relativeDay(value) {
  const date = toDateOrNull(value);
  if (!date) return 'sin fecha';
  const diff = Date.now() - date.getTime();
  if (diff < 0) return 'hoy';
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'recién';
  if (mins < 60) return 'hace ' + mins + ' min';
  const hours = Math.floor(mins / 60);
  if (hours < 24) return 'hace ' + hours + ' h';
  const days = Math.floor(hours / 24);
  if (days < 7) return 'hace ' + days + (days === 1 ? ' día' : ' días');
  return date.toLocaleDateString();
}

function emptyNote(text) {
  const p = document.createElement('p');
  p.className = 'srf-empty';
  p.textContent = text;
  return p;
}

function normalizeOverview(payload) {
  const totals = (Array.isArray(payload && payload.totals) ? payload.totals : []).map(function (row) {
    return {
      currency: currencyBucket(row.currency),
      spent: Number(row.spent || 0),
      received: Number(row.received || 0),
      spentWeek: Number(row.spentWeek || 0),
      receivedWeek: Number(row.receivedWeek || 0),
      movs: Number(row.movs || 0),
      lastAt: row.lastAt || null
    };
  });

  const games = (Array.isArray(payload && payload.games) ? payload.games : []).map(function (row) {
    return {
      origen: row.origen || 'OWS',
      currency: currencyBucket(row.currency),
      spent: Number(row.spent || 0),
      received: Number(row.received || 0),
      movs: Number(row.movs || 0),
      lastAt: row.lastAt || null
    };
  });

  const recent = (Array.isArray(payload && payload.recent) ? payload.recent : []).map(function (tx) {
    return {
      id: tx.id,
      concepto: tx.concepto || 'Movimiento OWS',
      amount: Number(tx.monto || 0),
      currency: currencyLabel(currencyBucket(tx.moneda)),
      origen: tx.origen || 'Surface',
      date: toDateOrNull(tx.created_at) || new Date()
    };
  });

  return { totals: totals, games: games, recent: recent, source: 'api' };
}

/* Respaldo: si el endpoint todavía no está desplegado, el mismo resumen se
   arma con el historial que ya se trajo de /surface/txs/:userId. */
function buildOverviewFromLocal() {
  const totalsMap = new Map();
  const gamesMap = new Map();
  const weekAgo = Date.now() - 7 * 86400000;

  allTransactionsList.forEach(function (tx) {
    const bucket = currencyBucket(tx.currency);
    const at = tx.date instanceof Date ? tx.date.getTime() : new Date(tx.date).getTime();
    const isRecent = Number.isFinite(at) && at >= weekAgo;
    const isSpend = Number(tx.amount) < 0;
    const abs = Math.abs(Number(tx.amount) || 0);

    const total = totalsMap.get(bucket) || {
      currency: bucket, spent: 0, received: 0, spentWeek: 0, receivedWeek: 0, movs: 0, lastAt: null
    };
    total.movs += 1;
    if (isSpend) {
      total.spent += abs;
      if (isRecent) total.spentWeek += abs;
    } else {
      total.received += abs;
      if (isRecent) total.receivedWeek += abs;
    }
    if (Number.isFinite(at) && (!total.lastAt || at > total.lastAt)) total.lastAt = at;
    totalsMap.set(bucket, total);

    const gameKey = String(tx.origen || 'OWS') + '::' + bucket;
    const game = gamesMap.get(gameKey) || {
      origen: tx.origen || 'OWS', currency: bucket, spent: 0, received: 0, movs: 0, lastAt: null
    };
    game.movs += 1;
    if (isSpend) game.spent += abs;
    else game.received += abs;
    if (Number.isFinite(at) && (!game.lastAt || at > game.lastAt)) game.lastAt = at;
    gamesMap.set(gameKey, game);
  });

  const games = Array.from(gamesMap.values()).sort(function (a, b) {
    if (b.spent !== a.spent) return b.spent - a.spent;
    return (b.lastAt || 0) - (a.lastAt || 0);
  });

  return {
    totals: Array.from(totalsMap.values()).sort(function (a, b) { return b.spent - a.spent; }),
    games: games,
    recent: allTransactionsList.slice(0, 12).map(function (tx) {
      return {
        id: tx.id,
        concepto: tx.concepto || 'Movimiento OWS',
        amount: Number(tx.amount || 0),
        currency: currencyLabel(currencyBucket(tx.currency)),
        origen: tx.origen || 'Surface',
        date: tx.date instanceof Date ? tx.date : (toDateOrNull(tx.date) || new Date())
      };
    }),
    source: 'local'
  };
}

async function loadOverviewActivity() {
  if (overviewLoading) return;
  const token = localStorage.getItem(TOKEN_KEY);
  if (!token) return;

  overviewLoading = true;
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(function () { controller.abort(); }, 12000);

    const res = await fetch(API_BASE + '/surface/activity/overview', {
      headers: { 'Authorization': 'Bearer ' + token },
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json().catch(function () { return null; });
    if (!data || !data.success) throw new Error('Respuesta inválida');

    overviewData = normalizeOverview(data);
  } catch (err) {
    // Endpoint no desplegado o sin conexión: se usa el historial local.
    console.warn('[Surface] Resumen sin endpoint, usando historial local:', err && err.message);
    if (!overviewData || overviewData.source !== 'api') {
      overviewData = buildOverviewFromLocal();
    }
  } finally {
    overviewLoading = false;
    renderOverview();
  }
}

function setGamesCurrencyFilter(currency) {
  gamesCurrencyFilter = (currency === 'gambits' || currency === 'tides') ? currency : 'all';
  document.querySelectorAll('[data-games-currency]').forEach(function (btn) {
    const active = btn.getAttribute('data-games-currency') === gamesCurrencyFilter;
    btn.classList.toggle('is-active', active);
    btn.setAttribute('aria-pressed', String(active));
  });
  renderOverviewGames();
}

function renderOverview() {
  renderOverviewStats();
  renderOverviewGames();
  renderOverviewRecent();
}

function renderOverviewStats() {
  const totals = overviewData ? overviewData.totals : [];
  const known = totals.filter(function (t) { return t.currency === 'gambits' || t.currency === 'tides'; });
  const spentWeek = known.reduce(function (sum, t) { return sum + t.spentWeek; }, 0);
  const receivedWeek = known.reduce(function (sum, t) { return sum + t.receivedWeek; }, 0);
  const movs = totals.reduce(function (sum, t) { return sum + t.movs; }, 0);
  const gamesCount = overviewData ? overviewData.games.filter(function (g) {
    return g.spent > 0 || g.received > 0;
  }).length : 0;

  const spentEl = el('stat-spent-week');
  const earnedEl = el('stat-earned-week');
  const movsEl = el('stat-movs');
  const gamesEl = el('stat-games');

  if (spentEl) spentEl.textContent = overviewData ? spentWeek.toLocaleString() : '—';
  if (earnedEl) earnedEl.textContent = overviewData ? receivedWeek.toLocaleString() : '—';
  if (movsEl) movsEl.textContent = overviewData ? movs.toLocaleString() : '—';
  if (gamesEl) gamesEl.textContent = overviewData ? String(gamesCount) : '—';

  // Nota por divisa dentro de cada tarjeta de saldo.
  ['gambits', 'tides'].forEach(function (code) {
    const note = el('balance-' + code + '-note');
    if (!note) return;
    if (!overviewData) {
      note.textContent = 'Cargando actividad…';
      return;
    }
    const row = totals.find(function (t) { return t.currency === code; });
    if (!row || (!row.spentWeek && !row.receivedWeek)) {
      note.textContent = 'Sin movimientos esta semana';
      return;
    }
    note.textContent = '7 días · −' + row.spentWeek.toLocaleString()
      + ' / +' + row.receivedWeek.toLocaleString() + ' ' + currencyLabel(code);
  });
}

function renderOverviewGames() {
  const container = el('overview-games');
  if (!container) return;
  container.innerHTML = '';

  if (!overviewData) {
    container.appendChild(emptyNote('Cargando actividad…'));
    return;
  }

  const rows = overviewData.games.filter(function (game) {
    if (gamesCurrencyFilter !== 'all' && game.currency !== gamesCurrencyFilter) return false;
    return game.spent > 0 || game.received > 0;
  });

  if (!rows.length) {
    container.appendChild(emptyNote(gamesCurrencyFilter === 'all'
      ? 'Todavía no hay gastos ni recompensas registrados en tus juegos.'
      : 'No hay actividad en ' + currencyLabel(gamesCurrencyFilter) + ' todavía.'));
    return;
  }

  rows.slice(0, 8).forEach(function (game) {
    const meta = gameMeta(game.origen);
    const row = document.createElement('div');
    row.className = 'srf-game';

    const ico = document.createElement('span');
    ico.className = 'srf-game-ico';
    ico.textContent = meta.ico;
    ico.setAttribute('aria-hidden', 'true');

    const txt = document.createElement('div');
    txt.className = 'srf-game-txt';

    const name = document.createElement('span');
    name.className = 'srf-game-name';
    name.textContent = meta.label;

    const sub = document.createElement('span');
    sub.className = 'srf-game-meta';
    sub.textContent = game.movs + (game.movs === 1 ? ' movimiento · ' : ' movimientos · ')
      + currencyLabel(game.currency) + ' · ' + relativeDay(game.lastAt);

    txt.appendChild(name);
    txt.appendChild(sub);

    const amounts = document.createElement('div');
    amounts.className = 'srf-game-amounts';
    if (game.spent > 0) {
      const spent = document.createElement('span');
      spent.className = 'srf-game-spent';
      spent.textContent = '−' + game.spent.toLocaleString() + ' ' + currencyLabel(game.currency);
      amounts.appendChild(spent);
    }
    if (game.received > 0) {
      const earned = document.createElement('span');
      earned.className = 'srf-game-earned';
      earned.textContent = '+' + game.received.toLocaleString() + ' ' + currencyLabel(game.currency);
      amounts.appendChild(earned);
    }

    row.appendChild(ico);
    row.appendChild(txt);
    row.appendChild(amounts);
    container.appendChild(row);
  });
}

function renderOverviewRecent() {
  const container = el('overview-recent');
  if (!container) return;
  container.innerHTML = '';

  if (!overviewData) {
    container.appendChild(emptyNote('Cargando movimientos…'));
    return;
  }
  if (!overviewData.recent.length) {
    container.appendChild(emptyNote('Todavía no hay movimientos en tu cuenta.'));
    return;
  }

  overviewData.recent.slice(0, 8).forEach(function (tx) {
    container.appendChild(createActivityElement(tx));
  });
}

// =========================================
// AUTO-LIMPIEZA DEL HISTORIAL
// =========================================

const AUTO_CLEAR_PREF_KEY = 'ocean_pay_auto_clear_period';
const LAST_CLEAR_TIMESTAMP_KEY = 'ocean_pay_last_clear_time';

function getAutoClearPeriod() {
  return localStorage.getItem(AUTO_CLEAR_PREF_KEY) || 'never';
}

function syncAutoClearDropdownUI() {
  const select = el('tx-auto-clear-period');
  if (select) select.value = getAutoClearPeriod();
}

function handleAutoClearSettingChange(period) {
  localStorage.setItem(AUTO_CLEAR_PREF_KEY, period);
  if (period === 'never') {
    showToast('Auto-limpieza desactivada.');
    return;
  }
  const labels = { '7d': 'cada 7 días', '15d': 'cada 15 días', '30d': 'cada 30 días' };
  showToast('Auto-limpieza configurada: ' + (labels[period] || period) + '.');
  checkAndExecuteAutoClear();
}

async function checkAndExecuteAutoClear() {
  const period = getAutoClearPeriod();
  if (period === 'never') return;

  const now = Date.now();
  const lastClear = Number(localStorage.getItem(LAST_CLEAR_TIMESTAMP_KEY) || 0);
  const days = { '7d': 7, '15d': 15, '30d': 30 }[period] || 0;
  if (!days) return;

  if (lastClear === 0) {
    localStorage.setItem(LAST_CLEAR_TIMESTAMP_KEY, String(now));
    return;
  }
  if (now - lastClear >= days * 86400000) {
    await executeClearHistory(true);
    localStorage.setItem(LAST_CLEAR_TIMESTAMP_KEY, String(now));
  }
}

function promptClearHistory() {
  el('clear-history-confirm-modal')?.classList.remove('hidden');
}

function closeClearHistoryModal() {
  el('clear-history-confirm-modal')?.classList.add('hidden');
}

async function executeClearHistory(isAuto) {
  const token = localStorage.getItem(TOKEN_KEY);
  if (!token) return;

  const btn = el('btn-confirm-clear-history');
  if (btn && !isAuto) {
    btn.disabled = true;
    btn.textContent = 'Eliminando…';
  }

  try {
    let userId = currentUser ? (currentUser.id || currentUser.uid) : null;
    if (!userId) {
      try { userId = JSON.parse(localStorage.getItem(USER_KEY) || '{}').id; } catch (_) {}
    }

    const endpoint = userId ? '/surface/txs/' + userId + '/clear' : '/surface/api/txs/clear';
    const res = await fetch(API_BASE + endpoint, {
      method: 'DELETE',
      headers: { 'Authorization': 'Bearer ' + token }
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || data.success === false) {
      throw new Error(data.error || 'El servidor no pudo eliminar el historial (' + res.status + ').');
    }

    allTransactionsList = [];
    renderTransactionsList(allTransactionsList);
    updateTransferPreview();
    overviewData = null;
    loadOverviewActivity();
    localStorage.setItem(LAST_CLEAR_TIMESTAMP_KEY, String(Date.now()));
    closeClearHistoryModal();

    const deleted = Number(data.deletedCount || 0);
    if (isAuto) showToast('Auto-limpieza del historial completada.');
    else showToast(deleted > 0 ? 'Historial eliminado (' + deleted + ' movimientos).' : 'Historial eliminado.');
  } catch (err) {
    console.error('[Surface] Error eliminando el historial:', err);
    closeClearHistoryModal();
    showAlert('operation-alert', err.message || 'No se pudo eliminar el historial.', 'error');
  } finally {
    if (btn && !isAuto) {
      btn.disabled = false;
      btn.textContent = 'Sí, eliminar historial';
    }
  }
}

// =========================================
// PANEL DE ADMINISTRACIÓN (solo OceanandWild)
// =========================================

function syncAdminModeUI() {
  document.querySelectorAll('.srf-seg-btn').forEach((label) => {
    const radio = label.querySelector('input[name="admin-mode-radio"]');
    if (radio) label.classList.toggle('is-active', radio.checked);
  });
}

function openAdminModal() {
  const name = String((currentUser && currentUser.username) || '').trim().toLowerCase();
  if (name !== 'oceanandwild') {
    showToast('Acceso no autorizado.');
    return;
  }
  hideAlert('admin-alert');
  syncAdminModeUI();
  el('admin-modal')?.classList.remove('hidden');
}

function closeAdminModal() {
  el('admin-modal')?.classList.add('hidden');
  hideAlert('admin-alert');
}

async function handleAdminBalanceSubmit(e) {
  if (e && e.preventDefault) e.preventDefault();
  hideAlert('admin-alert');

  const token = localStorage.getItem(TOKEN_KEY);
  if (!token) return handleLogout();

  const targetUser = (el('admin-target-user')?.value || '').trim();
  const currency   = el('admin-currency-select')?.value || 'tides';
  const amount     = Number(el('admin-amount-input')?.value || 0);
  const mode       = document.querySelector('input[name="admin-mode-radio"]:checked')?.value || 'set';
  const submitBtn  = el('btn-submit-admin');

  if (!targetUser) {
    showAlert('admin-alert', 'Ingresá el usuario destino.', 'error');
    return;
  }
  if (!Number.isFinite(amount) || amount < 0) {
    showAlert('admin-alert', 'Ingresá una cantidad válida (0 o mayor).', 'error');
    return;
  }

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = 'Aplicando…';
  }

  try {
    const res = await fetch(API_BASE + '/surface/api/admin/set-balance', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
      },
      body: JSON.stringify({ targetUsername: targetUser, currency, amount, mode })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || 'No se pudo actualizar el saldo.');

    showAlert('admin-alert',
      data.message || ('Saldo de ' + currency.toUpperCase() + ' actualizado a ' + amount.toLocaleString() + '.'),
      'success');
    showToast('Saldo de ' + currency.toUpperCase() + ' actualizado.');

    if (targetUser.toLowerCase() === 'oceanandwild') await loadWalletData();

    setTimeout(() => {
      closeAdminModal();
      const amountInput = el('admin-amount-input');
      if (amountInput) amountInput.value = '';
    }, 1200);
  } catch (err) {
    console.error('[Surface] Error en el panel admin:', err);
    showAlert('admin-alert', err.message || 'Error al conectar con la base de datos.', 'error');
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Aplicar';
    }
  }
}

// =========================================
// AVISOS
// =========================================

function showAlert(elementId, msg, type) {
  const box = el(elementId);
  if (!box) return;
  box.textContent = msg;
  box.className = 'srf-alert srf-alert-' + (type || 'error');
  box.classList.remove('hidden');
}

function hideAlert(elementId) {
  const box = el(elementId);
  if (box) box.classList.add('hidden');
}

let toastTimer = null;

function showToast(msg) {
  const toast = el('toast');
  if (!toast) return;
  toast.textContent = msg;
  toast.classList.remove('hidden');
  toast.classList.remove('is-in');
  void toast.offsetWidth;
  toast.classList.add('is-in');

  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(hideToast, 3800);
}

function hideToast() {
  const toast = el('toast');
  if (!toast) return;
  if (toastTimer) clearTimeout(toastTimer);
  toast.classList.add('hidden');
  toast.classList.remove('is-in');
}
