// Backend REAL: siempre server.js en Render (producción).
// No usar localhost: todas las peticiones van a la DB real de owsdatabase.onrender.com.
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

const TOKEN_KEY = 'ocean_pay_token';
const USER_KEY = 'ocean_pay_user';

let currentUser = null;
let userCards = [];
let selectedCardIndex = 0;

let currentBalances = {
  tides: 0,
  gambits: 0
};

// Historial completo en memoria
let allTransactionsList = [];

// Current Active Step for Transfer (1, 2 or 3)
let currentTransferStep = 1;

// Pending Transfer Payload for Modal Confirmation
let pendingTransferPayload = null;

// =========================================
// FEE ENGINE — Sistema de Comisiones OWS
// =========================================

const FEE_CONFIG = {
  gambits: {
    threshold:   1000,   // Monto mínimo para aplicar comisión
    baseRate:    0.02,   // 2% base
    minRate:     0.005,  // 0.5% mínimo (con todos los descuentos)
    label:       'GAMBITS',
  },
  tides: {
    threshold:   500,    // Tides tiene umbral menor
    baseRate:    0.01,   // 1% base (divisa premium, tarifa ya reducida)
    minRate:     0.002,  // 0.2% mínimo
    label:       'TIDES',
  },
};

// Nº de transferencias gratuitas al mes por usuario (global para todas las divisas)
const FREE_TRANSFERS_PER_MONTH = 5;

// Clave en localStorage para el contador de transferencias del mes
const TX_COUNTER_KEY = 'ocean_pay_global_monthly_tx';

function getMonthlyTxData() {
  const today = new Date();
  const monthKey = today.getFullYear() + '-' + String(today.getMonth() + 1).padStart(2, '0');
  
  try {
    const raw = localStorage.getItem(TX_COUNTER_KEY);
    const parsed = raw ? JSON.parse(raw) : null;
    if (parsed && parsed.month === monthKey) {
      return parsed;
    }
  } catch (_) {}

  return { month: monthKey, count: 0, volume: 0 };
}

function saveMonthlyTxData(data) {
  localStorage.setItem(TX_COUNTER_KEY, JSON.stringify(data));
}

function recordTransferInCounter(currency, amount) {
  const data = getMonthlyTxData();
  data.count  += 1;
  data.volume += amount;
  saveMonthlyTxData(data);
  updateFreeQuotaUI();
}

/**
 * Calcula los días y horas restantes hasta el reinicio del mes (1er día del mes siguiente a las 00:00).
 */
function getTimeUntilMonthReset() {
  const now = new Date();
  const nextMonth = new Date(now.getFullYear(), now.getMonth() + 1, 1, 0, 0, 0);
  const diffMs = nextMonth.getTime() - now.getTime();
  
  const days = Math.floor(diffMs / (1000 * 60 * 60 * 24));
  const hours = Math.floor((diffMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));

  if (days > 0) {
    return `en ${days} ${days === 1 ? 'día' : 'días'}`;
  }
  return `en ${hours} ${hours === 1 ? 'hora' : 'horas'}`;
}

/**
 * Actualiza la tarjeta informativa de cuota gratuita en el dashboard.
 */
function updateFreeQuotaUI() {
  const txData = getMonthlyTxData();
  const count = Math.min(txData.count, FREE_TRANSFERS_PER_MONTH);
  const remaining = Math.max(0, FREE_TRANSFERS_PER_MONTH - txData.count);
  const pct = Math.min(100, Math.round((txData.count / FREE_TRANSFERS_PER_MONTH) * 100));

  const usedEl = document.getElementById('free-quota-used');
  const remainingEl = document.getElementById('free-quota-remaining');
  const resetEl = document.getElementById('free-quota-reset');
  const progressEl = document.getElementById('free-quota-progress');

  if (usedEl) usedEl.textContent = `${count} / ${FREE_TRANSFERS_PER_MONTH}`;
  if (remainingEl) remainingEl.textContent = remaining > 0 ? `${remaining} ${remaining === 1 ? 'envío' : 'envíos'}` : 'Agotadas este mes';
  if (resetEl) resetEl.textContent = getTimeUntilMonthReset();
  if (progressEl) progressEl.style.width = `${pct}%`;
}

/**
 * Calcula el descuento por actividad elevada en los últimos 7 días (0–15%).
 * Cuanto más volumen/transacciones con la misma divisa, mayor descuento.
 */
function calcActivityDiscount(currency) {
  const currencyLabel = (currency === 'tides') ? 'TIDES' : 'GAMBITS';
  const now = Date.now();
  const sevenDaysMs = 7 * 24 * 60 * 60 * 1000;

  const recentTxs = allTransactionsList.filter(function(tx) {
    const txTime = tx.date instanceof Date ? tx.date.getTime() : new Date(tx.date).getTime();
    return (
      tx.currency === currencyLabel &&
      tx.amount < 0 &&
      (now - txTime) <= sevenDaysMs
    );
  });

  const count  = recentTxs.length;
  const volume = recentTxs.reduce(function(sum, tx) { return sum + Math.abs(tx.amount); }, 0);

  const byCount  = Math.min(count / 5, 1);
  const byVolume = Math.min(volume / 5000, 1);
  const factor   = Math.max(byCount, byVolume);

  return Math.round(factor * 15); // 0–15%
}

/**
 * Calcula la comisión completa para un monto y divisa.
 * Retorna: { fee, rate, isFree, reasons[], discountPct }
 */
function calculateFee(currency, amount) {
  const cfg = FEE_CONFIG[currency];
  if (!cfg) return { fee: 0, rate: 0, isFree: true, reasons: ['Divisa sin comisión'], discountPct: 0 };

  if (amount < cfg.threshold) {
    return {
      fee: 0, rate: 0, isFree: true,
      reasons: ['Monto bajo el umbral (' + cfg.threshold.toLocaleString() + ' ' + cfg.label + ')'],
      discountPct: 0,
    };
  }

  const txData = getMonthlyTxData();

  // Regla: 5 transferencias gratuitas globales al mes
  if (txData.count < FREE_TRANSFERS_PER_MONTH) {
    return {
      fee: 0, rate: 0, isFree: true,
      reasons: ['Transferencia gratuita (' + (txData.count + 1) + '/' + FREE_TRANSFERS_PER_MONTH + ' del mes)'],
      discountPct: 100,
    };
  }

  // Descuento por actividad elevada (0–15%)
  const activityDiscount = calcActivityDiscount(currency);

  let effectiveRate = cfg.baseRate * (1 - activityDiscount / 100);
  effectiveRate = Math.max(effectiveRate, cfg.minRate);

  const fee = Math.ceil(amount * effectiveRate);

  const reasons = [];
  if (currency === 'tides') reasons.push('Tides: tarifa reducida (divisa premium)');
  if (activityDiscount > 0) reasons.push('Descuento por actividad reciente: -' + activityDiscount + '%');

  return {
    fee,
    rate:        effectiveRate,
    isFree:      false,
    reasons,
    discountPct: activityDiscount,
    baseRate:    cfg.baseRate,
  };
}

// Initial setup on page load
document.addEventListener('DOMContentLoaded', function() {
  console.log('[Ocean Pay] Inicializado. API_BASE (REAL):', API_BASE, '| protocol:', window.location.protocol);
  if (window.location.protocol === 'file:') {
    console.warn('[Ocean Pay] Abierto como archivo local (file://). API REAL: ' + API_BASE + '. La API seguirá siendo Render aunque sirvas por HTTP.');
  }
  bindOceanPayEvents();
  
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
});

// ═══════════════════════════════════════════════
// EVENTS — binding centralizado (sin inline handlers:
// el WebView de Tauri no compila atributos onclick/*)
// ═══════════════════════════════════════════════
function bindOceanPayEvents() {
  const on = (sel, ev, fn) => {
    const el = typeof sel === 'string' ? document.querySelector(sel) : sel;
    if (el) el.addEventListener(ev, fn);
  };
  const all = (sel, ev, fn) => {
    document.querySelectorAll(sel).forEach((el) => el.addEventListener(ev, fn));
  };

  // Auth: tabs + forms
  all('[data-optab]', 'click', (e) => switchAuthTab(e.currentTarget.getAttribute('data-optab')));
  on('#login-form', 'submit', handleLogin);
  on('#register-form', 'submit', handleRegister);
  on('#btn-back-ows', 'click', () => { window.location.href = '../index.html'; });
  on('#btn-admin-panel', 'click', openAdminModal);
  on('#btn-op-logout', 'click', handleLogout);

  // Tarjeta: selector, flip, copiar (stopPropagation: está dentro del flip)
  on('#card-select-dropdown', 'change', (e) => handleCardSelection(e.target.value));
  on('#virtual-card-wrapper', 'click', toggleCardFlip);
  on('#card-copy-icon', 'click', (e) => { e.stopPropagation(); copyCardNumber(e); });

  // Balances + transferencia
  on('#btn-sync-balances', 'click', loadWalletData);
  on('#transfer-form', 'submit', promptTransferConfirmation);
  all('[data-step]', 'click', (e) => focusStep(Number(e.currentTarget.getAttribute('data-step'))));
  on('#transfer-recipient', 'input', (e) => handleRecipientInput(e.target.value));
  all('[data-currency]', 'click', (e) => selectTransferCurrency(e, e.currentTarget.getAttribute('data-currency')));
  on('#btn-max-amount', 'click', setTransferMaxAmount);
  on('#transfer-amount', 'input', (e) => handleAmountInput(e.target.value));
  all('[data-preset]', 'click', (e) => addAmountPreset(Number(e.currentTarget.getAttribute('data-preset'))));

  // Modales: abrir/cerrar + click en overlay
  all('[data-action="open-history"]', 'click', openHistoryModal);
  const overlayCloser = (overlayId, closeFn) => {
    const ov = document.getElementById(overlayId);
    if (ov) ov.addEventListener('click', (e) => { if (e.target === ov) closeFn(); });
  };
  overlayCloser('confirm-modal', closeConfirmModal);
  overlayCloser('history-modal', closeHistoryModal);
  overlayCloser('admin-modal', closeAdminModal);
  all('[data-close-confirm]', 'click', (e) => { e.stopPropagation(); closeConfirmModal(); });
  all('[data-close-history]', 'click', (e) => { e.stopPropagation(); closeHistoryModal(); });
  all('[data-close-admin]', 'click', (e) => { e.stopPropagation(); closeAdminModal(); });
  on('#btn-final-transfer', 'click', executeFinalTransfer);

  // Historial: filtros + acciones
  on('#tx-search-input', 'input', filterTransactions);
  on('#tx-filter-currency', 'change', filterTransactions);
  on('#tx-auto-clear-period', 'change', (e) => handleAutoClearSettingChange(e.target.value));
  on('#btn-clear-history', 'click', promptClearHistory);
  on('#btn-reload-tx', 'click', loadAllTransactionsFromDB);
  on('#btn-cancel-clear', 'click', closeClearHistoryModal);
  on('#btn-confirm-clear-history', 'click', executeClearHistory);

  // Admin balances
  on('#admin-balance-form', 'submit', handleAdminBalanceSubmit);
}

// Switch Auth Tabs (Login / Register)
function switchAuthTab(tab) {
  const loginForm = document.getElementById('login-form');
  const regForm = document.getElementById('register-form');
  const loginBtn = document.getElementById('tab-login-btn');
  const regBtn = document.getElementById('tab-register-btn');
  hideAlert('auth-alert');

  if (tab === 'login') {
    loginForm.classList.remove('hidden');
    regForm.classList.add('hidden');
    loginBtn.classList.add('active');
    regBtn.classList.remove('active');
  } else {
    loginForm.classList.add('hidden');
    regForm.classList.remove('hidden');
    loginBtn.classList.remove('active');
    regBtn.classList.add('active');
  }
}

// Show / Hide main views
function showAuth() {
  document.getElementById('auth-section').classList.remove('hidden');
  document.getElementById('dashboard-section').classList.add('hidden');
}

function showDashboard() {
  document.getElementById('auth-section').classList.add('hidden');
  document.getElementById('dashboard-section').classList.remove('hidden');
  updateTransferStepUI(1);

  if (currentUser) {
    const name = currentUser.username || currentUser.id || 'Jugador';
    const navUser = document.getElementById('nav-user-name');
    const holderUser = document.getElementById('card-holder-name');
    if (navUser) navUser.textContent = name;
    if (holderUser) holderUser.textContent = name.toUpperCase();
    
    // Verificación estricta para Panel Admin
    checkAdminPrivileges();
  }
  displaySelectedCard();
  updateFreeQuotaUI();
}

function checkAdminPrivileges() {
  const adminBtn = document.getElementById('btn-admin-panel');
  if (!adminBtn) return;

  const currentName = String(currentUser?.username || '').trim().toLowerCase();
  if (currentName === 'oceanandwild') {
    adminBtn.classList.remove('hidden');
  } else {
    adminBtn.classList.add('hidden');
  }
}

// Authentication Handlers
async function handleLogin(e) {
  if (e && e.preventDefault) e.preventDefault();
  hideAlert('auth-alert');

  const usernameInput = document.getElementById('login-username');
  const passwordInput = document.getElementById('login-password');
  const submitBtn = document.getElementById('btn-login-submit');

  const username = usernameInput ? usernameInput.value.trim() : '';
  const password = passwordInput ? passwordInput.value.trim() : '';

  if (!username || !password) {
    showAlert('auth-alert', 'Por favor ingresa usuario y contraseña.', 'error');
    return;
  }

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = 'Conectando con OWS...';
  }

  try {
    const res = await fetch(API_BASE + '/ocean-pay/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: username, password: password })
    });

    const data = await res.json().catch(function() { return {}; });

    if (!res.ok) {
      throw new Error(data.error || ('Error en el servidor (' + res.status + ')'));
    }

    if (!data.token) {
      throw new Error('No se recibió token de acceso');
    }

    currentUser = data.user || { id: data.id, username: username };
    localStorage.setItem(TOKEN_KEY, data.token);
    localStorage.setItem(USER_KEY, JSON.stringify(currentUser));
    
    showToast('¡Bienvenido ' + username + '!');
    showDashboard();
    await loadWalletData();
  } catch (err) {
    console.error('[Ocean Pay] Error login:', err, '| API_BASE:', API_BASE);
    let friendly = err.message || 'Error de conexión con el servidor.';
    if (String(err.message || '').includes('Failed to fetch') || err instanceof TypeError) {
      friendly = 'No se pudo conectar con el servidor (' + API_BASE + '). Revisa tu internet o que el backend esté en línea.';
    }
    showAlert('auth-alert', friendly, 'error');
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Entrar a Ocean Pay';
    }
  }
}

async function handleRegister(e) {
  if (e && e.preventDefault) e.preventDefault();
  hideAlert('auth-alert');

  const username = document.getElementById('reg-username').value.trim();
  const password = document.getElementById('reg-password').value.trim();

  if (!username || !password) {
    showAlert('auth-alert', 'Completa todos los campos.', 'error');
    return;
  }

  try {
    const res = await fetch(API_BASE + '/ocean-pay/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: username, password: password })
    });

    const data = await res.json().catch(function() { return {}; });
    if (!res.ok) throw new Error(data.error || 'No se pudo crear la cuenta');

    showAlert('auth-alert', 'Cuenta creada con éxito. Ya puedes iniciar sesión.', 'success');
    switchAuthTab('login');
    document.getElementById('login-username').value = username;
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
  allTransactionsList = [];
  currentTransferStep = 1;
  closeHistoryModal();
  closeConfirmModal();
  showToast('Sesión cerrada');
  showAuth();
}

// Fetch Full Wallet Info & Balances
async function loadWalletData() {
  const token = localStorage.getItem(TOKEN_KEY);
  if (!token) return handleLogout();

  // Actualizar UI inicial con usuario en cache inmediatamente
  if (currentUser) {
    const username = currentUser.username || currentUser.id || 'Jugador';
    const navUser = document.getElementById('nav-user-name');
    const holderUser = document.getElementById('card-holder-name');
    if (navUser) navUser.textContent = username;
    if (holderUser) holderUser.textContent = username.toUpperCase();
  }
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

    if (res.status === 401) {
      return handleLogout();
    }

    const data = await res.json().catch(function() { return {}; });
    
    currentUser = data.user || currentUser || {};
    if (data.id && !currentUser.id) currentUser.id = data.id;
    if (currentUser.id) {
      localStorage.setItem(USER_KEY, JSON.stringify(currentUser));
    }

    userCards = data.cards || [];

    // Update Nav & Holder
    const finalName = currentUser.username || 'Jugador';
    document.getElementById('nav-user-name').textContent = finalName;
    document.getElementById('card-holder-name').textContent = finalName.toUpperCase();

    // Populate Cards Dropdown
    populateCardsDropdown();
    displaySelectedCard();

    // Extract Gambits & Tides
    const balances = data.balances || {};
    currentBalances.tides = Number(balances.tides || 0);
    currentBalances.gambits = Number(balances.gambits || 0);

    // Direct balance verification
    try {
      const [tidesRes, gambitsRes] = await Promise.allSettled([
        fetch(API_BASE + '/ocean-pay/tides/balance', { headers: { 'Authorization': 'Bearer ' + token } }),
        fetch(API_BASE + '/ocean-pay/gambits/balance', { headers: { 'Authorization': 'Bearer ' + token } })
      ]);
      if (tidesRes.status === 'fulfilled' && tidesRes.value.ok) {
        const tData = await tidesRes.value.json().catch(function() { return {}; });
        if (typeof tData.tides === 'number') currentBalances.tides = tData.tides;
      }
      if (gambitsRes.status === 'fulfilled' && gambitsRes.value.ok) {
        const gData = await gambitsRes.value.json().catch(function() { return {}; });
        if (typeof gData.gambits === 'number') currentBalances.gambits = gData.gambits;
      }
    } catch (_) {}

    updateBalanceDisplay();
    updatePillsBalances();
    updateTransferPreview();
    updateFreeQuotaUI();

    // Pre-cargar transacciones
    if (currentUser.id) {
      loadAllTransactionsFromDB();
    }
  } catch (err) {
    console.error('Error cargando wallet:', err);
    populateCardsDropdown();
    displaySelectedCard();
    updateBalanceDisplay();
    updatePillsBalances();
    updateTransferPreview();
    updateFreeQuotaUI();
    showToast('Datos locales cargados');
  }
}

function updateBalanceDisplay() {
  document.getElementById('balance-tides').textContent = currentBalances.tides.toLocaleString();
  document.getElementById('balance-gambits').textContent = currentBalances.gambits.toLocaleString();
}

function updatePillsBalances() {
  const gBalElem = document.getElementById('pill-gambits-bal');
  const tBalElem = document.getElementById('pill-tides-bal');
  if (gBalElem) gBalElem.textContent = 'Disp: ' + currentBalances.gambits.toLocaleString();
  if (tBalElem) tBalElem.textContent = 'Disp: ' + currentBalances.tides.toLocaleString();
}

// 3D Card Interactions
function toggleCardFlip() {
  const cardElem = document.getElementById('virtual-card-element');
  if (cardElem) {
    cardElem.classList.toggle('flipped');
  }
}

function copyCardNumber(e) {
  if (e && e.stopPropagation) e.stopPropagation();
  const card = userCards[selectedCardIndex] || userCards[0];
  const num = card ? String(card.card_number || '') : '';
  if (num) {
    navigator.clipboard.writeText(num).then(function() {
      showToast('¡Número de tarjeta copiado al portapapeles!');
    }).catch(function() {
      showToast('Tarjeta: ' + formatCardNumber(num));
    });
  }
}

// State for Recipient Verification
let isRecipientValid = false;
let verifiedRecipientUser = null;
let recipientCheckTimeout = null;

// =========================================
// STEP-BY-STEP PROGRESSION LOGIC
// =========================================

function updateTransferStepUI(activeStep) {
  currentTransferStep = activeStep;

  const step1 = document.getElementById('step-wrapper-1');
  const step2 = document.getElementById('step-wrapper-2');
  const step3 = document.getElementById('step-wrapper-3');
  const submitBtn = document.getElementById('btn-submit-transfer');

  const amountVal = parseInt(document.getElementById('transfer-amount')?.value, 10) || 0;

  if (activeStep === 1) {
    step1.className = 'transfer-step step-active';
    step2.className = 'transfer-step step-inactive';
    step3.className = 'transfer-step step-inactive';
  } else if (activeStep === 2) {
    step1.className = 'transfer-step step-completed';
    step2.className = 'transfer-step step-active';
    step3.className = 'transfer-step step-inactive';
  } else if (activeStep >= 3) {
    step1.className = 'transfer-step step-completed';
    step2.className = 'transfer-step step-completed';
    step3.className = 'transfer-step step-active';
  }

  if (submitBtn) {
    const isReady = isRecipientValid && amountVal > 0;
    submitBtn.disabled = !isReady;
  }
}

function handleRecipientInput(val) {
  const clean = val.trim();
  const badge = document.getElementById('recipient-status-badge');
  const spinner = document.getElementById('recipient-spinner');
  const feedback = document.getElementById('recipient-feedback-msg');

  // Cancelar chequeo previo si el usuario sigue escribiendo
  if (recipientCheckTimeout) clearTimeout(recipientCheckTimeout);

  isRecipientValid = false;
  verifiedRecipientUser = null;

  if (!clean || clean.length < 2) {
    if (badge) badge.style.display = 'none';
    if (spinner) spinner.style.display = 'none';
    if (feedback) feedback.style.display = 'none';
    updateTransferStepUI(1);
    return;
  }

  // Prevenir transferirse a uno mismo
  if (currentUser && currentUser.username && clean.toLowerCase() === currentUser.username.toLowerCase()) {
    if (badge) {
      badge.textContent = '❌ No permitido';
      badge.style.color = 'var(--danger, #f87171)';
      badge.style.display = 'inline-block';
    }
    if (spinner) spinner.style.display = 'none';
    if (feedback) {
      feedback.textContent = 'No puedes transferir fondos a tu propia cuenta.';
      feedback.style.color = 'var(--danger, #f87171)';
      feedback.style.display = 'block';
    }
    updateTransferStepUI(1);
    return;
  }

  // Mostrar estado verificando
  if (badge) {
    badge.textContent = 'Verificando...';
    badge.style.color = 'var(--text-muted, #94a3b8)';
    badge.style.display = 'inline-block';
  }
  if (spinner) spinner.style.display = 'inline-block';
  if (feedback) feedback.style.display = 'none';

  // Debounce de 400ms para no saturar con peticiones mientras escribe
  recipientCheckTimeout = setTimeout(function() {
    verifyRecipientExists(clean);
  }, 400);
}

async function verifyRecipientExists(username) {
  const badge = document.getElementById('recipient-status-badge');
  const spinner = document.getElementById('recipient-spinner');
  const feedback = document.getElementById('recipient-feedback-msg');
  const token = localStorage.getItem(TOKEN_KEY);

  try {
    // Verificación contra server.js: GET /ocean-pay/api/users/check
    // (responde 200 con { exists, user }; nunca 404 por usuario inexistente)
    let userExists = false;
    let verifiedName = username;

    const res = await fetch(API_BASE + '/ocean-pay/api/users/check?username=' + encodeURIComponent(username), {
      headers: {
        'Authorization': 'Bearer ' + (token || '')
      }
    });

    if (!res.ok) {
      throw new Error('Error del servidor (' + res.status + ')');
    }
    const data = await res.json().catch(function() { return {}; });
    if (data.exists && data.user) {
      userExists = true;
      verifiedName = data.user.username || username;
    }

    if (spinner) spinner.style.display = 'none';

    if (userExists) {
      isRecipientValid = true;
      verifiedRecipientUser = { username: verifiedName };

      if (badge) {
        badge.textContent = '✓ Usuario verificado';
        badge.style.color = 'var(--success, #34d399)';
        badge.style.display = 'inline-block';
      }
      if (feedback) {
        feedback.textContent = 'Destinatario: @' + verifiedName;
        feedback.style.color = 'var(--success, #34d399)';
        feedback.style.display = 'block';
      }

      if (currentTransferStep <= 2) {
        updateTransferStepUI(2);
      }
    } else {
      isRecipientValid = false;
      verifiedRecipientUser = null;

      if (badge) {
        badge.textContent = '✕ No existe';
        badge.style.color = 'var(--danger, #f87171)';
        badge.style.display = 'inline-block';
      }
      if (feedback) {
        feedback.textContent = 'El usuario @' + username + ' no existe en OWS.';
        feedback.style.color = 'var(--danger, #f87171)';
        feedback.style.display = 'block';
      }

      updateTransferStepUI(1);
    }
  } catch (err) {
    console.error('Error al verificar usuario:', err);
    if (spinner) spinner.style.display = 'none';
    if (badge) {
      badge.textContent = '⚠️ Error red';
      badge.style.color = 'var(--accent-gold, #f59e0b)';
      badge.style.display = 'inline-block';
    }
  }
}

function selectTransferCurrency(e, currency) {
  // Manejo flexible de parámetros (e puede ser el evento o directamente el currency string)
  if (typeof e === 'string') {
    currency = e;
    e = null;
  }
  if (e && e.stopPropagation) {
    e.stopPropagation();
  }

  if (!isRecipientValid) {
    showToast('Ingresa un usuario destinatario válido primero');
    document.getElementById('transfer-recipient')?.focus();
    return;
  }

  const transferCurInput = document.getElementById('transfer-currency');
  const pillGambits = document.getElementById('pill-gambits');
  const pillTides = document.getElementById('pill-tides');
  const suffixLabel = document.getElementById('amount-suffix-label');

  if (transferCurInput) transferCurInput.value = currency;

  if (currency === 'gambits') {
    pillGambits?.classList.add('active');
    pillTides?.classList.remove('active');
    if (suffixLabel) suffixLabel.textContent = 'GAMBITS';
  } else {
    pillTides?.classList.add('active');
    pillGambits?.classList.remove('active');
    if (suffixLabel) suffixLabel.textContent = 'TIDES';
  }

  updateTransferPreview();
  updateTransferStepUI(3);
  
  setTimeout(function() {
    const amtInput = document.getElementById('transfer-amount');
    if (amtInput) amtInput.focus();
  }, 50);
}

function handleAmountInput(val) {
  const amount = parseInt(val, 10) || 0;
  updateTransferPreview();
  const submitBtn = document.getElementById('btn-submit-transfer');

  if (submitBtn) {
    submitBtn.disabled = !(isRecipientValid && amount > 0);
  }
}

function focusStep(stepNum) {
  if (stepNum >= 2 && !isRecipientValid) {
    document.getElementById('transfer-recipient')?.focus();
    return;
  }
  updateTransferStepUI(stepNum);
}

// Preset Amounts & Max Button
function addAmountPreset(delta) {
  const amountInput = document.getElementById('transfer-amount');
  if (!amountInput) return;
  const currentVal = parseInt(amountInput.value, 10) || 0;
  amountInput.value = currentVal + delta;
  handleAmountInput(amountInput.value);
  updateTransferStepUI(3);
}

function setTransferMaxAmount() {
  const currency = document.getElementById('transfer-currency')?.value || 'gambits';
  const maxAvailable = currentBalances[currency] || 0;
  const amountInput = document.getElementById('transfer-amount');
  if (amountInput) {
    amountInput.value = maxAvailable > 0 ? maxAvailable : 0;
    handleAmountInput(amountInput.value);
    updateTransferStepUI(3);
  }
}

function updateTransferPreview() {
  const currencyRaw = document.getElementById('transfer-currency')?.value || 'gambits';
  const currency    = currencyRaw.toUpperCase();
  const amount      = parseInt(document.getElementById('transfer-amount')?.value, 10) || 0;

  const feeData = calculateFee(currencyRaw, amount);

  // — Comisión label —
  const feeRow   = document.querySelector('.summary-row .free-tag') ||
                   document.querySelector('[id="fee-value-display"]');
  const feeLabel = document.querySelector('.summary-row span:first-child');

  // Actualizar texto de comisión en el resumen
  const feeValueEl = document.getElementById('fee-value-display');
  const feeLabelEl = document.getElementById('fee-label-display');
  const feeHintEl  = document.getElementById('fee-hint-display');
  const totalEl    = document.getElementById('summary-total-display');

  if (feeValueEl) {
    if (feeData.isFree) {
      feeValueEl.textContent  = '0.00 (Gratis)';
      feeValueEl.className    = 'free-tag';
    } else {
      const pct = Math.round(feeData.rate * 100 * 100) / 100; // 2 decimales
      feeValueEl.textContent = '+' + feeData.fee.toLocaleString() + ' ' + currency +
        ' (' + pct + '%)';
      feeValueEl.className   = 'fee-tag';
    }
  }

  // Razones de descuento / info
  if (feeHintEl) {
    if (feeData.reasons && feeData.reasons.length > 0) {
      feeHintEl.textContent  = '✦ ' + feeData.reasons.join(' · ');
      feeHintEl.style.display = '';
    } else {
      feeHintEl.style.display = 'none';
    }
  }

  // Total a debitar = amount + fee
  if (totalEl) {
    const total = amount + feeData.fee;
    totalEl.textContent = total.toLocaleString() + ' ' + currency;
  }
}


// =========================================
// CONFIRMATION MODAL & SAFE EXECUTION
// =========================================

function promptTransferConfirmation(e) {
  if (e && e.preventDefault) e.preventDefault();
  hideAlert('operation-alert');

  const recipient = document.getElementById('transfer-recipient').value.trim();
  const currency  = document.getElementById('transfer-currency').value;
  const amount    = parseInt(document.getElementById('transfer-amount').value, 10);

  if (!recipient || !isRecipientValid) {
    return showAlert('operation-alert', 'Debes ingresar y verificar un usuario destinatario válido.', 'error');
  }
  if (!amount || amount <= 0) {
    return showAlert('operation-alert', 'El monto debe ser mayor a 0.', 'error');
  }

  // Calcular comisión
  const feeData    = calculateFee(currency, amount);
  const totalDebit = amount + feeData.fee;

  if ((currentBalances[currency] || 0) < totalDebit) {
    const msg = feeData.fee > 0
      ? 'Saldo insuficiente. Necesitás ' + totalDebit.toLocaleString() + ' ' + currency.toUpperCase() +
        ' (' + amount.toLocaleString() + ' + ' + feeData.fee.toLocaleString() + ' de comisión).'
      : 'Saldo insuficiente de ' + currency.toUpperCase() + '.';
    return showAlert('operation-alert', msg, 'error');
  }

  const currencyLabel = currency === 'tides' ? 'TIDES' : 'GAMBITS';
  pendingTransferPayload = {
    recipient, currency, amount, currencyLabel,
    fee:        feeData.fee,
    totalDebit: totalDebit,
    feeReasons: feeData.reasons,
    feeIsFree:  feeData.isFree,
    feeRate:    feeData.rate,
  };

  // Textos del modal
  document.getElementById('confirm-amount-text').textContent =
    amount.toLocaleString() + ' ' + currencyLabel;
  document.getElementById('confirm-recipient-text').textContent = '@' + recipient;
  document.getElementById('confirm-currency-text').textContent  = currencyLabel;

  // Comisión en modal
  const modalFeeEl = document.getElementById('confirm-fee-text');
  if (modalFeeEl) {
    if (feeData.isFree) {
      modalFeeEl.textContent = '0.00 (Gratis)';
      modalFeeEl.style.color = 'var(--success)';
    } else {
      const pct = Math.round(feeData.rate * 100 * 100) / 100;
      modalFeeEl.textContent = '+' + feeData.fee.toLocaleString() + ' ' + currencyLabel + ' (' + pct + '%)';
      modalFeeEl.style.color = 'var(--accent-gold, #f59e0b)';
    }
  }

  // Total a debitar en modal
  const modalTotalEl = document.getElementById('confirm-total-text');
  if (modalTotalEl) {
    modalTotalEl.textContent = totalDebit.toLocaleString() + ' ' + currencyLabel;
  }

  // Razón de descuento en modal
  const modalDiscountEl = document.getElementById('confirm-discount-text');
  if (modalDiscountEl) {
    if (feeData.reasons && feeData.reasons.length > 0) {
      modalDiscountEl.textContent  = '✦ ' + feeData.reasons.join(' · ');
      modalDiscountEl.style.display = '';
    } else {
      modalDiscountEl.style.display = 'none';
    }
  }

  document.getElementById('confirm-modal')?.classList.remove('hidden');
}

function closeConfirmModal() {
  document.getElementById('confirm-modal')?.classList.add('hidden');
  pendingTransferPayload = null;
}

function handleConfirmOverlayClick(e) {
  if (e.target.id === 'confirm-modal') {
    closeConfirmModal();
  }
}

async function executeFinalTransfer() {
  if (!pendingTransferPayload) return;

  const token = localStorage.getItem(TOKEN_KEY);
  if (!token) return handleLogout();

  const payload = pendingTransferPayload;
  const btn = document.getElementById('btn-final-transfer');
  if (btn) {
    btn.disabled    = true;
    btn.textContent = 'Enviando...';
  }

  try {
    // Debitar amount + fee del remitente
    const subRes = await fetch(API_BASE + '/ocean-pay/currency/change', {
      method:  'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
      },
      body: JSON.stringify({
        currencyType: payload.currency,
        amount:       -payload.totalDebit,
        concepto:     'Transferencia enviada a @' + payload.recipient +
                      (payload.fee > 0 ? ' (incluye comisión: ' + payload.fee + ' ' + payload.currencyLabel + ')' : ''),
        origen: 'Ocean Pay P2P'
      })
    });

    const subData = await subRes.json().catch(function() { return {}; });
    if (!subRes.ok) throw new Error(subData.error || 'No se pudo debitar el monto');

    // Registrar transferencia para el contador mensual (descuentos futuros)
    recordTransferInCounter(payload.currency, payload.amount);

    closeConfirmModal();

    const feeMsg = payload.fee > 0
      ? ' (comisión: ' + payload.fee + ' ' + payload.currencyLabel + ')'
      : ' (sin comisión)';
    showAlert('operation-alert',
      'Envío exitoso: -' + payload.totalDebit + ' ' + payload.currencyLabel +
      ' a @' + payload.recipient + feeMsg,
      'success'
    );
    showToast('¡Transferencia enviada con éxito!');

    // Añadir al historial en memoria
    allTransactionsList.unshift({
      id:       Date.now(),
      concepto: 'Transferencia enviada a @' + payload.recipient,
      amount:   -payload.totalDebit,
      currency: payload.currencyLabel,
      origen:   'Ocean Pay P2P',
      date:     new Date()
    });

    // Reset form
    document.getElementById('transfer-recipient').value = '';
    document.getElementById('transfer-amount').value    = '';
    updateTransferPreview();
    updateTransferStepUI(1);

    await loadWalletData();
  } catch (err) {
    closeConfirmModal();
    showAlert('operation-alert', err.message || 'Error en la transferencia', 'error');
  } finally {
    if (btn) {
      btn.disabled    = false;
      btn.textContent = 'Sí, Transferir';
    }
  }
}

// Cargar todas las transacciones desde DB
async function loadAllTransactionsFromDB() {
  const token = localStorage.getItem(TOKEN_KEY);
  if (!token) return;

  let userId = currentUser ? (currentUser.id || currentUser.uid) : null;
  if (!userId) {
    const stored = localStorage.getItem(USER_KEY);
    if (stored) {
      try { userId = JSON.parse(stored).id; } catch(_) {}
    }
  }

  if (!userId) {
    renderTransactionsList(allTransactionsList);
    return;
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(function() { controller.abort(); }, 8000);

    const res = await fetch(API_BASE + '/ocean-pay/txs/' + userId, {
      headers: { 'Authorization': 'Bearer ' + token },
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    if (!res.ok) {
      renderTransactionsList(allTransactionsList);
      return;
    }

    const data = await res.json().catch(function() { return []; });
    const rawTxs = Array.isArray(data) ? data : (data.rows || []);

    const dbList = rawTxs.map(function(tx) {
      return {
        id: tx.id,
        concepto: tx.concepto || 'Movimiento OWS',
        amount: Number(tx.monto || 0),
        currency: (tx.moneda || 'GAMBITS').toUpperCase(),
        origen: tx.origen || 'Ocean Pay',
        date: tx.created_at ? new Date(tx.created_at) : new Date()
      };
    });

    const mergedMap = new Map();
    allTransactionsList.forEach(function(item) { if (item.id) mergedMap.set(String(item.id), item); });
    dbList.forEach(function(item) { mergedMap.set(String(item.id), item); });

    allTransactionsList = Array.from(mergedMap.values()).sort(function(a, b) {
      return b.date.getTime() - a.date.getTime();
    });

    renderTransactionsList(allTransactionsList);
    updateTransferPreview();
  } catch (e) {
    renderTransactionsList(allTransactionsList);
  }
}

// Renderizar lista en el modal
function renderTransactionsList(listToRender) {
  const container = document.getElementById('modal-activity-list');
  const countBadge = document.getElementById('modal-tx-count');
  if (!container) return;

  if (countBadge) {
    countBadge.textContent = listToRender.length + (listToRender.length === 1 ? ' movimiento' : ' movimientos');
  }

  container.innerHTML = '';

  if (!listToRender || listToRender.length === 0) {
    container.innerHTML = '<div class=\"empty-state\">No hay movimientos registrados en tu cuenta todavía.</div>';
    return;
  }

  listToRender.forEach(function(tx) {
    const el = createActivityElement(tx);
    container.appendChild(el);
  });
}

// Filtrar transacciones por buscador y moneda
function filterTransactions() {
  const searchVal = (document.getElementById('tx-search-input')?.value || '').trim().toLowerCase();
  const filterCurrency = (document.getElementById('tx-filter-currency')?.value || 'all').toLowerCase();

  const filtered = allTransactionsList.filter(function(tx) {
    if (filterCurrency === 'gambits' && !tx.currency.includes('GAMBIT')) return false;
    if (filterCurrency === 'tides' && !tx.currency.includes('TIDE')) return false;

    if (searchVal) {
      const matchConcepto = tx.concepto.toLowerCase().includes(searchVal);
      const matchOrigen = tx.origen.toLowerCase().includes(searchVal);
      const matchCurrency = tx.currency.toLowerCase().includes(searchVal);
      const matchDate = tx.date.toLocaleDateString().includes(searchVal);
      return matchConcepto || matchOrigen || matchCurrency || matchDate;
    }

    return true;
  });

  renderTransactionsList(filtered);
}

// Modal Handlers
function openHistoryModal() {
  const modal = document.getElementById('history-modal');
  if (modal) {
    modal.classList.remove('hidden');
    syncAutoClearDropdownUI();
    checkAndExecuteAutoClear();
    renderTransactionsList(allTransactionsList);
    loadAllTransactionsFromDB();
  }
}

function closeHistoryModal() {
  const modal = document.getElementById('history-modal');
  if (modal) modal.classList.add('hidden');
}

function handleModalOverlayClick(e) {
  if (e.target.id === 'history-modal') {
    closeHistoryModal();
  }
}

// =========================================
// AUTO-CLEAR & HISTORIAL MANAGEMENT
// =========================================

const AUTO_CLEAR_PREF_KEY = 'ocean_pay_auto_clear_period';
const LAST_CLEAR_TIMESTAMP_KEY = 'ocean_pay_last_clear_time';

function getAutoClearPeriod() {
  return localStorage.getItem(AUTO_CLEAR_PREF_KEY) || 'never';
}

function syncAutoClearDropdownUI() {
  const select = document.getElementById('tx-auto-clear-period');
  if (select) {
    select.value = getAutoClearPeriod();
  }
}

function handleAutoClearSettingChange(period) {
  localStorage.setItem(AUTO_CLEAR_PREF_KEY, period);
  if (period !== 'never') {
    showToast(`Auto-limpieza configurada: ${period === '7d' ? 'cada 7 días' : period === '15d' ? 'cada 15 días' : 'cada 30 días'} ⏱️`);
    checkAndExecuteAutoClear();
  } else {
    showToast('Auto-limpieza periódica desactivada');
  }
}

async function checkAndExecuteAutoClear() {
  const period = getAutoClearPeriod();
  if (period === 'never') return;

  const now = Date.now();
  const lastClear = Number(localStorage.getItem(LAST_CLEAR_TIMESTAMP_KEY) || 0);

  const periodDaysMap = { '7d': 7, '15d': 15, '30d': 30 };
  const days = periodDaysMap[period] || 0;
  if (!days) return;

  const intervalMs = days * 24 * 60 * 60 * 1000;

  if (lastClear === 0) {
    localStorage.setItem(LAST_CLEAR_TIMESTAMP_KEY, String(now));
    return;
  }

  if (now - lastClear >= intervalMs) {
    console.log(`[Ocean Pay] Ejecutando auto-limpieza periódica (${period})...`);
    await executeClearHistory(true);
    localStorage.setItem(LAST_CLEAR_TIMESTAMP_KEY, String(now));
  }
}

function promptClearHistory() {
  document.getElementById('clear-history-confirm-modal')?.classList.remove('hidden');
}

function closeClearHistoryModal() {
  document.getElementById('clear-history-confirm-modal')?.classList.add('hidden');
}

async function executeClearHistory(isAuto = false) {
  const token = localStorage.getItem(TOKEN_KEY);
  if (!token) return;

  const btn = document.getElementById('btn-confirm-clear-history');
  if (btn && !isAuto) {
    btn.disabled = true;
    btn.textContent = 'Eliminando...';
  }

  try {
    let userId = currentUser ? (currentUser.id || currentUser.uid) : null;
    if (!userId) {
      const stored = localStorage.getItem(USER_KEY);
      if (stored) {
        try { userId = JSON.parse(stored).id; } catch(_) {}
      }
    }

    // server.js: DELETE /ocean-pay/txs/:userId/clear y /ocean-pay/api/txs/clear
    const endpoint = userId ? `/ocean-pay/txs/${userId}/clear` : '/ocean-pay/api/txs/clear';
    const res = await fetch(API_BASE + endpoint, {
      method: 'DELETE',
      headers: {
        'Authorization': 'Bearer ' + token
      }
    });
    const data = await res.json().catch(function() { return {}; });
    if (!res.ok || data.success === false) {
      throw new Error(data.error || 'El servidor no pudo eliminar el historial (' + res.status + ')');
    }

    // Vaciar lista local en memoria inmediatamente
    allTransactionsList = [];
    renderTransactionsList(allTransactionsList);
    updateTransferPreview();

    localStorage.setItem(LAST_CLEAR_TIMESTAMP_KEY, String(Date.now()));
    closeClearHistoryModal();

    const deleted = Number(data.deletedCount || 0);
    if (!isAuto) {
      showToast(deleted > 0
        ? `¡Historial eliminado correctamente! 🗑️ (${deleted} movimientos)`
        : '¡Historial de movimientos eliminado correctamente! 🗑️');
    } else {
      showToast('Auto-limpieza de historial completada ⏱️');
    }
  } catch (err) {
    console.error('Error al eliminar historial:', err);
    closeClearHistoryModal();
    showAlert('operation-alert', err.message || 'No se pudo eliminar el historial en el servidor.', 'error');
    showToast('No se pudo limpiar el historial del servidor');
  } finally {
    if (btn && !isAuto) {
      btn.disabled = false;
      btn.textContent = 'Sí, Eliminar Historial';
    }
  }
}

// Populate card switcher select element
function populateCardsDropdown() {
  const select = document.getElementById('card-select-dropdown');
  if (!select) return;
  select.innerHTML = '';

  if (userCards.length === 0) {
    const opt = document.createElement('option');
    opt.value = '0';
    opt.textContent = 'Tarjeta Principal (Predeterminada)';
    select.appendChild(opt);
    return;
  }

  userCards.forEach(function(card, idx) {
    const opt = document.createElement('option');
    opt.value = String(idx);
    const cardName = card.card_name || ('Tarjeta ' + (idx + 1));
    const lastDigits = card.card_number ? ('•• ' + String(card.card_number).slice(-4)) : '';
    opt.textContent = cardName + (card.is_primary ? ' (Principal)' : '') + (lastDigits ? ' - ' + lastDigits : '');
    select.appendChild(opt);
  });

  select.value = String(selectedCardIndex);
}

// Handle user switching active card in UI
function handleCardSelection(indexStr) {
  selectedCardIndex = parseInt(indexStr, 10) || 0;
  displaySelectedCard();
}

function displaySelectedCard() {
  const card = userCards[selectedCardIndex] || userCards[0];
  const cardNameElem = document.getElementById('card-name-display');
  const numberElem = document.getElementById('card-number-display');
  const expiryElem = document.getElementById('card-expiry-display');
  const cvvElem = document.getElementById('card-cvv-display');

  if (card) {
    if (cardNameElem) cardNameElem.textContent = (card.card_name || 'OCEAN PAY').toUpperCase();
    if (numberElem) numberElem.textContent = formatCardNumber(card.card_number || '4000123456789010');
    if (expiryElem) expiryElem.textContent = card.expiry_date || '12/30';
    if (cvvElem) cvvElem.textContent = card.cvv || '•••';
  } else {
    if (cardNameElem) cardNameElem.textContent = 'OCEAN PAY';
    if (numberElem) numberElem.textContent = '4000 •••• •••• ••••';
    if (expiryElem) expiryElem.textContent = '12/30';
    if (cvvElem) cvvElem.textContent = '•••';
  }
}

function formatCardNumber(num) {
  const clean = String(num).replace(/\D/g, '');
  if (clean.length === 16) {
    return clean.replace(/(\d{4})(\d{4})(\d{4})(\d{4})/, '   ');
  }
  return num;
}

// Helpers
function createActivityElement(info) {
  const item = document.createElement('div');
  item.className = 'activity-item';

  const isPositive = info.amount > 0;
  const sign = isPositive ? '+' : (info.amount < 0 ? '-' : '');
  const absAmount = Math.abs(info.amount).toLocaleString();
  const formattedDate = info.date.toLocaleDateString() + ' • ' + info.date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const badgeClass = isPositive ? 'badge-pos' : 'badge-neg';
  const icon = isPositive ? '📥' : '📤';

  item.innerHTML = 
    '<div class=\"activity-left\">' +
      '<div class=\"activity-icon-box\">' + icon + '</div>' +
      '<div class=\"activity-details\">' +
        '<div class=\"activity-title\">' + info.concepto + '</div>' +
        '<div class=\"activity-meta\">' +
          '<span class=\"activity-time\">' + formattedDate + '</span>' +
          '<span class=\"activity-origen-tag\">' + (info.origen || 'Ocean Pay') + '</span>' +
        '</div>' +
      '</div>' +
    '</div>' +
    '<div class=\"activity-right\">' +
      '<span class=\"activity-badge ' + badgeClass + '\">' + sign + absAmount + ' ' + info.currency.toUpperCase() + '</span>' +
    '</div>';

  return item;
}

function showAlert(elementId, msg, type) {
  type = type || 'error';
  const box = document.getElementById(elementId);
  if (!box) return;
  box.textContent = msg;
  box.className = 'alert-box alert-' + type;
  box.classList.remove('hidden');
}

function hideAlert(elementId) {
  const box = document.getElementById(elementId);
  if (box) box.classList.add('hidden');
}

function showToast(msg) {
  const toast = document.getElementById('toast');
  if (!toast) return;
  toast.textContent = msg;
  toast.classList.remove('hidden');
  setTimeout(function() { toast.classList.add('hidden'); }, 3500);
}

// =========================================
// ADMIN PANEL (EXCLUSIVO OCEANANDWILD)
// =========================================

function openAdminModal() {
  const currentName = String(currentUser?.username || '').trim().toLowerCase();
  if (currentName !== 'oceanandwild') {
    showToast('Acceso no autorizado');
    return;
  }

  hideAlert('admin-alert');
  document.getElementById('admin-modal')?.classList.remove('hidden');
}

function closeAdminModal() {
  document.getElementById('admin-modal')?.classList.add('hidden');
  hideAlert('admin-alert');
}

function handleAdminOverlayClick(e) {
  if (e.target.id === 'admin-modal') {
    closeAdminModal();
  }
}

async function handleAdminBalanceSubmit(e) {
  if (e && e.preventDefault) e.preventDefault();
  hideAlert('admin-alert');

  const token = localStorage.getItem(TOKEN_KEY);
  if (!token) return handleLogout();

  const targetUser = (document.getElementById('admin-target-user')?.value || '').trim();
  const currency   = document.getElementById('admin-currency-select')?.value || 'tides';
  const amount     = Number(document.getElementById('admin-amount-input')?.value || 0);
  const mode       = document.querySelector('input[name="admin-mode-radio"]:checked')?.value || 'set';
  const submitBtn  = document.getElementById('btn-submit-admin');

  if (!targetUser) {
    showAlert('admin-alert', 'Ingresa el nombre del usuario destino.', 'error');
    return;
  }
  if (isNaN(amount) || amount < 0) {
    showAlert('admin-alert', 'Ingresa una cantidad válida (0 o mayor).', 'error');
    return;
  }

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = 'Actualizando base de datos...';
  }

  try {
    // server.js: POST /ocean-pay/api/admin/set-balance (existe en producción)
    const res = await fetch(API_BASE + '/ocean-pay/api/admin/set-balance', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
      },
      body: JSON.stringify({
        targetUsername: targetUser,
        currency: currency,
        amount: amount,
        mode: mode
      })
    });

    const data = await res.json().catch(function() { return {}; });

    if (!res.ok) {
      throw new Error(data.error || 'Error al actualizar el saldo en el servidor');
    }

    showAlert('admin-alert', data.message || `Saldo de ${currency.toUpperCase()} actualizado exitosamente a ${amount.toLocaleString()}.`, 'success');
    showToast(`¡Saldo de ${currency.toUpperCase()} actualizado! ⚡`);

    // Si modificamos nuestro propio saldo, recargar la billetera
    if (targetUser.toLowerCase() === 'oceanandwild') {
      await loadWalletData();
    }

    setTimeout(function() {
      closeAdminModal();
      document.getElementById('admin-amount-input').value = '';
    }, 1200);

  } catch (err) {
    console.error('Error en admin set-balance:', err);
    showAlert('admin-alert', err.message || 'Error al conectar con la base de datos.', 'error');
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = '⚡ Aplicar a Base de Datos';
    }
  }
}
