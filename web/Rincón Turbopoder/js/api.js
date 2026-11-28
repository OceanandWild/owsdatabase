/* ==========================================================================
   RINCÓN TURBOPODER — cliente de la API
   Base: mismo origen cuando el sitio se sirve desde OWS, o Render si es estático.
   Override: ?api=https://mi-api  |  localStorage.turbopoder_api_base
   ========================================================================== */

(function () {
  'use strict';

  const REMOTE = 'https://owsdatabase.onrender.com';
  const KEYS = {
    token: 'turbopoder_token',
    user: 'turbopoder_user',
    base: 'turbopoder_api_base',
    email: 'turbopoder_last_email'
  };

  function trimBase(value) {
    return String(value || '').replace(/\/+$/, '');
  }

  function detectBase() {
    if (window.TURBOPODER_API) return trimBase(window.TURBOPODER_API);
    try {
      const params = new URLSearchParams(window.location.search);
      const fromQuery = params.get('api');
      if (fromQuery) {
        const clean = trimBase(fromQuery);
        localStorage.setItem(KEYS.base, clean);
        return clean;
      }
      const saved = localStorage.getItem(KEYS.base);
      if (saved) return trimBase(saved);
    } catch (error) {}

    if (window.location.protocol !== 'file:' && /^\/rincon-turbopoder/.test(window.location.pathname)) {
      return window.location.origin;
    }
    return REMOTE;
  }

  const base = detectBase();

  function getToken() {
    try { return localStorage.getItem(KEYS.token) || ''; } catch (error) { return ''; }
  }

  function getUser() {
    try {
      const raw = localStorage.getItem(KEYS.user);
      return raw ? JSON.parse(raw) : null;
    } catch (error) { return null; }
  }

  function setSession(token, user) {
    try {
      if (token) localStorage.setItem(KEYS.token, token);
      if (user) localStorage.setItem(KEYS.user, JSON.stringify(user));
    } catch (error) {}
  }

  function clearSession() {
    try {
      localStorage.removeItem(KEYS.token);
      localStorage.removeItem(KEYS.user);
    } catch (error) {}
  }

  function lastEmail(value) {
    try {
      if (value == null) return localStorage.getItem(KEYS.email) || '';
      localStorage.setItem(KEYS.email, String(value));
    } catch (error) { return ''; }
    return String(value);
  }

  async function request(path, options) {
    const opts = options || {};
    const headers = Object.assign({ Accept: 'application/json' }, opts.headers || {});
    const body = opts.body;
    if (body && !(typeof FormData !== 'undefined' && body instanceof FormData)) {
      headers['Content-Type'] = 'application/json';
    }
    const token = getToken();
    if (token) headers.Authorization = 'Bearer ' + token;

    const controller = new AbortController();
    const timeout = setTimeout(function () { controller.abort(); }, opts.timeout || 20000);

    let response;
    try {
      response = await fetch(base + '/turbopoder' + path, {
        method: opts.method || 'GET',
        headers: headers,
        body: body && !(typeof FormData !== 'undefined' && body instanceof FormData) ? JSON.stringify(body) : body,
        signal: controller.signal
      });
    } catch (error) {
      clearTimeout(timeout);
      const err = new Error(error.name === 'AbortError'
        ? 'El servidor tardó demasiado en responder. Probá de nuevo.'
        : 'No pudimos conectar con el servidor. Revisá tu conexión.');
      err.offline = true;
      throw err;
    }
    clearTimeout(timeout);

    const raw = await response.text();
    let data = null;
    if (raw) { try { data = JSON.parse(raw); } catch (error) { data = null; } }

    if (!response.ok) {
      const message = (data && (data.error || data.message)) || ('El servidor respondió ' + response.status + '.');
      const err = new Error(message);
      err.status = response.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  function qs(params) {
    const search = new URLSearchParams();
    Object.keys(params || {}).forEach(function (key) {
      const value = params[key];
      if (value === undefined || value === null || value === '') return;
      search.set(key, value);
    });
    const text = search.toString();
    return text ? '?' + text : '';
  }

  function json(method, payload) {
    return { method: method, body: payload };
  }

  const api = {
    base: base,
    request: request,
    qs: qs,
    getToken: getToken,
    getUser: getUser,
    setSession: setSession,
    clearSession: clearSession,
    lastEmail: lastEmail,

    health: function () { return request('/health', { timeout: 8000 }); },
    meta: function () { return request('/meta'); },

    register: function (payload) { return request('/register', json('POST', payload)); },
    login: function (payload) { return request('/login', json('POST', payload)); },
    me: function () { return request('/me'); },

    stores: function (params) { return request('/stores' + qs(params)); },
    store: function (slug) { return request('/stores/' + encodeURIComponent(slug)); },
    createStore: function (payload) { return request('/stores', json('POST', payload)); },
    updateStore: function (id, payload) { return request('/stores/' + id, json('PATCH', payload)); },

    products: function (params) { return request('/products' + qs(params)); },
    product: function (id) { return request('/products/' + id); },
    createProduct: function (formData) { return request('/products', { method: 'POST', body: formData }); },
    updateProduct: function (id, payload) { return request('/products/' + id, json('PATCH', payload)); },
    deleteProduct: function (id) { return request('/products/' + id, { method: 'DELETE' }); },
    addReview: function (id, payload) { return request('/products/' + id + '/reviews', json('POST', payload)); },

    checkout: function (payload) { return request('/orders', json('POST', payload)); },
    orderByCode: function (code, email) { return request('/orders/' + encodeURIComponent(code) + qs({ email: email })); },
    myOrders: function () { return request('/orders'); },
    sellerSummary: function () { return request('/seller/summary'); },
    sellerProducts: function (storeId) { return request('/seller/products' + qs({ storeId: storeId })); },
    sellerOrders: function () { return request('/seller/orders'); },
    updateOrderStatus: function (id, status) { return request('/orders/' + id + '/status', json('PATCH', { status: status })); }
  };

  window.TPApi = api;
})();
