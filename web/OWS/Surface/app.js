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

let currentBalances = { tides: 0, gambits: 0 };

// Historial completo en memoria
let allTransactionsList = [];

// Pago pendiente de confirmar
let pendingTransferPayload = null;

// Verificación de destinatario
let isRecipientValid = false;
let verifiedRecipientUser = null;
let recipientCheckTimeout = null;

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
    loadWalletData();
  } else {
    showAuth();
  }
}

/* Reinicia la animación de entrada de un bloque (login → billetera y vuelta). */
function replayEnter(root) {
  if (!root) return;
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

  // Modales
  all('[data-action="open-history"]', 'click', openHistoryModal);
  all('[data-close-confirm]', 'click', closeConfirmModal);
  all('[data-close-history]', 'click', closeHistoryModal);
  all('[data-close-admin]', 'click', closeAdminModal);
  on('#btn-final-transfer', 'click', executeFinalTransfer);
  on('#confirm-modal', 'click', (e) => { if (e.target.id === 'confirm-modal') closeConfirmModal(); });
  on('#history-modal', 'click', (e) => { if (e.target.id === 'history-modal') closeHistoryModal(); });
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
    if (!el('admin-modal')?.classList.contains('hidden')) return closeAdminModal();
    if (!el('clear-history-confirm-modal')?.classList.contains('hidden')) return closeClearHistoryModal();
    if (!el('history-modal')?.classList.contains('hidden')) return closeHistoryModal();
    if (!el('confirm-modal')?.classList.contains('hidden')) return closeConfirmModal();
  });
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
  updateUserUI();
  checkAdminPrivileges();
  populateCardsDropdown();
  displaySelectedCard();
  updateCurrencySelectionUI();
  updateTransferPreview();
  updateFreeQuotaUI();
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
  const hello = el('srf-hello-name');

  if (navUser) navUser.textContent = name;
  if (avatar) avatar.textContent = String(name).charAt(0).toUpperCase();
  if (holder) holder.textContent = String(name).toUpperCase();
  if (hello) hello.textContent = name;
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
    const res = await fetch(API_BASE + '/ocean-pay/login', {
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
    const res = await fetch(API_BASE + '/ocean-pay/register', {
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

  closeHistoryModal();
  closeConfirmModal();
  closeAdminModal();
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

    const res = await fetch(API_BASE + '/ocean-pay/me', {
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

    // Verificación directa de saldos (por si /me viene con datos viejos)
    try {
      const [tidesRes, gambitsRes] = await Promise.allSettled([
        fetch(API_BASE + '/ocean-pay/tides/balance',   { headers: { 'Authorization': 'Bearer ' + token } }),
        fetch(API_BASE + '/ocean-pay/gambits/balance', { headers: { 'Authorization': 'Bearer ' + token } })
      ]);
      if (tidesRes.status === 'fulfilled' && tidesRes.value.ok) {
        const tData = await tidesRes.value.json().catch(() => ({}));
        if (typeof tData.tides === 'number') currentBalances.tides = tData.tides;
      }
      if (gambitsRes.status === 'fulfilled' && gambitsRes.value.ok) {
        const gData = await gambitsRes.value.json().catch(() => ({}));
        if (typeof gData.gambits === 'number') currentBalances.gambits = gData.gambits;
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
    updateBalanceDisplay();
    updatePillsBalances();
    updateTransferPreview();
    updateFreeQuotaUI();

    if (currentUser && currentUser.id) loadAllTransactionsFromDB(false);
  }
}

function updateBalanceDisplay() {
  const tidesEl = el('balance-tides');
  const gambitsEl = el('balance-gambits');
  if (tidesEl) tidesEl.textContent = currentBalances.tides.toLocaleString();
  if (gambitsEl) gambitsEl.textContent = currentBalances.gambits.toLocaleString();
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
  displaySelectedCard();
}

function displaySelectedCard() {
  const card = activeCard();
  const nameEl = el('card-name-display');
  const numberEl = el('card-number-display');
  const expiryEl = el('card-expiry-display');
  const cvvEl = el('card-cvv-display');

  const rawNumber = card ? String(card.card_number || '') : '';
  const formatted = formatCardNumber(rawNumber);

  if (nameEl) nameEl.textContent = ((card && card.card_name) || 'SURFACE').toUpperCase();
  if (numberEl) numberEl.textContent = (cardDataVisible && formatted) ? formatted : maskCardNumber(rawNumber);
  if (expiryEl) expiryEl.textContent = (card && card.expiry_date) || '—';
  if (cvvEl) cvvEl.textContent = cardDataVisible ? ((card && card.cvv) || '—') : '•••';

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
    const res = await fetch(API_BASE + '/ocean-pay/api/users/check?username=' + encodeURIComponent(username), {
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
  const max = calcMaxSendable(currency, available);
  const input = el('transfer-amount');

  if (!max) {
    showToast('No tenés saldo disponible en ' + currency.toUpperCase() + '.');
    return;
  }
  if (input) input.value = String(max);
  updateTransferPreview();
}

/* Resumen: comisión, motivo y total. También decide si se puede enviar. */
function updateTransferPreview() {
  const currency = currentCurrency();
  const currencyLabel = currency.toUpperCase();
  const amount = parseInt(el('transfer-amount')?.value, 10) || 0;
  const available = Number(currentBalances[currency] || 0);

  const feeData = calculateFee(currency, amount);
  const total = amount + feeData.fee;

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

  const submitBtn = el('btn-submit-transfer');
  if (submitBtn) {
    const over = amount > 0 && total > available;
    submitBtn.disabled = !(isRecipientValid && amount > 0 && !over);
    submitBtn.textContent = over
      ? 'Saldo insuficiente'
      : (amount > 0 ? 'Enviar ' + amount.toLocaleString() + ' ' + currencyLabel : 'Enviar');
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

  el('confirm-modal')?.classList.remove('hidden');
  el('btn-final-transfer')?.focus();
}

function closeConfirmModal() {
  el('confirm-modal')?.classList.add('hidden');
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
    const res = await fetch(API_BASE + '/ocean-pay/p2p/send', {
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

    const res = await fetch(API_BASE + '/ocean-pay/txs/' + userId, {
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

function openHistoryModal() {
  const modal = el('history-modal');
  if (!modal) return;
  modal.classList.remove('hidden');
  syncAutoClearDropdownUI();
  checkAndExecuteAutoClear();
  renderTransactionsList(allTransactionsList, true);
  loadAllTransactionsFromDB(false);
  el('tx-search-input')?.focus();
}

function closeHistoryModal() {
  el('history-modal')?.classList.add('hidden');
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

    const endpoint = userId ? '/ocean-pay/txs/' + userId + '/clear' : '/ocean-pay/api/txs/clear';
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
    const res = await fetch(API_BASE + '/ocean-pay/api/admin/set-balance', {
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
