/* ============================================================================
 * OWS API FAILOVER — v2 (2026-10-26)
 * ----------------------------------------------------------------------------
 * Respaldo automático entre el servidor API principal y su espejo:
 *
 *    Principal : https://owsdatabase.onrender.com
 *    Espejo    : https://owsdatabase2.onrender.com
 *
 * Qué hace (sin tocar ningún endpoint):
 *    - Envuelve window.fetch. Si la URL apunta a una base conocida, reintenta
 *      la MISMA petición contra la otra base cuando hay error de red/CORS
 *      (típico de Render suspendido) o respuesta 502/503/504.
 *    - Si la página se sirve desde una base conocida (por ejemplo el espejo),
 *      esa misma base va primero. Así la primera petición no choca contra la
 *      principal suspendida.
 *    - Recuerda la última base que respondió y la usa primero. Una sonda de
 *      salud cada 45 s vuelve sola a la principal cuando se recupera.
 *    - Expone window.OWS_API_FAILOVER para construir URLs (links de descarga,
 *      window.open, invoke) contra la base sana actual.
 *
 * Reglas:
 *    - El override de pruebas (?api=... / localStorage.ows_api_base) manda.
 *    - Peticiones canceladas por la app (AbortError) no se reintentan.
 *    - Hosts externos (GitHub, Cloudinary, itch.io, ...) pasan de largo.
 *
 * Debe cargarse ANTES de cualquier script que use fetch.
 * ========================================================================== */
(function () {
  'use strict';

  var PRIMARY = 'https://owsdatabase.onrender.com';
  var MIRRORS = ['https://owsdatabase2.onrender.com'];
  var KNOWN = [PRIMARY].concat(MIRRORS);
  var HEALTH_PATH = '/ecoconsole/health';
  var LAST_GOOD_KEY = 'ows_api_last_good_base';
  var PROBE_EVERY_MS = 45000;

  var nativeFetch = window.fetch ? window.fetch.bind(window) : null;
  if (!nativeFetch) return;

  // Origen actual de la página (si es una base conocida, manda al arrancar).
  var SELF = '';
  try {
    SELF = String(window.location.origin || '').replace(/\/+$/, '');
  } catch (_) {}

  // Orden de intento en memoria. Arranca por la última base sana conocida en
  // esta pestaña (sessionStorage); si no hay, por la principal.
  var activeOrder = KNOWN.slice();
  try {
    var lastGood = sessionStorage.getItem(LAST_GOOD_KEY);
    if (lastGood && KNOWN.indexOf(lastGood) !== -1 && lastGood !== PRIMARY) {
      activeOrder = [lastGood].concat(KNOWN.filter(function (b) { return b !== lastGood; }));
    }
  } catch (_) {}

  // Mismo origen primero: si la página se sirve desde el espejo, no tiene
  // sentido intentar la principal suspendida en la primera petición.
  if (SELF && KNOWN.indexOf(SELF) !== -1) {
    activeOrder = [SELF].concat(KNOWN.filter(function (b) { return b !== SELF; }));
  }

  // Override de pruebas: si apunta a una base conocida, arranca por ahí.
  try {
    var params = new URLSearchParams(window.location.search || '');
    var override = String(params.get('api') || localStorage.getItem('ows_api_base') || '')
      .trim().replace(/\/+$/, '');
    if (override && KNOWN.indexOf(override) !== -1) {
      activeOrder = [override].concat(KNOWN.filter(function (b) { return b !== override; }));
    }
  } catch (_) {}

  var probeTimer = null;

  function baseOf(url) {
    for (var i = 0; i < KNOWN.length; i++) {
      var b = KNOWN[i];
      if (url === b || url.indexOf(b + '/') === 0) return b;
    }
    return null;
  }

  function swapBase(url, from, to) {
    return to + url.slice(from.length);
  }

  function isGatewayDown(res) {
    return !!res && (res.status === 502 || res.status === 503 || res.status === 504);
  }

  function setActive(base, persist) {
    var was = activeOrder[0];
    activeOrder = [base].concat(KNOWN.filter(function (b) { return b !== base; }));
    if (persist) {
      try { sessionStorage.setItem(LAST_GOOD_KEY, base); } catch (_) {}
    }
    if (base === PRIMARY) stopProbe(); else startProbe();
    if (was !== base) {
      try {
        console.info('[OWS/API] Base activa: ' + base +
          (base === PRIMARY ? ' (principal)' : ' (espejo de respaldo)'));
      } catch (_) {}
    }
  }

  function markGood(base) {
    if (activeOrder[0] !== base) setActive(base, true);
  }

  function startProbe() {
    if (probeTimer) return;
    probeTimer = setInterval(function () {
      nativeFetch(PRIMARY + HEALTH_PATH, { cache: 'no-store' })
        .then(function (res) { if (res && res.ok) setActive(PRIMARY, true); })
        .catch(function () {});
    }, PROBE_EVERY_MS);
  }

  function stopProbe() {
    if (probeTimer) { clearInterval(probeTimer); probeTimer = null; }
  }

  function owsFailoverFetch(input, init) {
    var isRequest = (typeof Request !== 'undefined') && (input instanceof Request);
    var rawUrl = isRequest ? input.url : String(input);

    var originalBase = baseOf(rawUrl);
    if (!originalBase) return nativeFetch(input, init); // host externo: intacto

    // Orden para esta petición: base sana primero; la del URL queda incluida.
    var order = activeOrder.slice();
    if (order.indexOf(originalBase) === -1) order.push(originalBase);

    function attempt(index, lastError, lastResponse) {
      if (index >= order.length) {
        // Si al menos una base contestó (p. ej. un 503), se devuelve esa
        // respuesta para conservar la semántica normal de fetch.
        if (lastResponse) return Promise.resolve(lastResponse);
        return Promise.reject(lastError || new TypeError('Failed to fetch'));
      }
      if (init && init.signal && init.signal.aborted) {
        return Promise.reject(lastError || new DOMException('The operation was aborted.', 'AbortError'));
      }

      var target = order[index];
      var targetUrl = swapBase(rawUrl, originalBase, target);
      var call;
      try {
        call = isRequest ? nativeFetch(new Request(targetUrl, input)) : nativeFetch(targetUrl, init);
      } catch (_) {
        // No se pudo reconstruir la petición (body ya consumido, etc.):
        // se hace el intento original tal cual, sin más reintentos.
        return nativeFetch(input, init);
      }

      return call.then(
        function (res) {
          if (isGatewayDown(res)) {
            return attempt(index + 1,
              new Error('OWS API ' + target + ' respondio HTTP ' + res.status), res);
          }
          markGood(target);
          return res;
        },
        function (err) {
          // Cancelación explícita de la app: no revivir lo cancelado.
          if (err && err.name === 'AbortError') throw err;
          return attempt(index + 1, err, lastResponse);
        }
      );
    }

    return attempt(0, null, null);
  }

  window.fetch = owsFailoverFetch;

  // ── API pública para flujos que generan URLs (links, window.open, invoke) ──
  window.OWS_API_FAILOVER = {
    primary: PRIMARY,
    mirrors: MIRRORS.slice(),
    knownBases: KNOWN.slice(),
    isKnown: function (url) { return !!baseOf(String(url)); },
    clientBase: function () { return activeOrder[0] || PRIMARY; },
    preferredUrl: function (url) {
      var u = String(url);
      var b = baseOf(u);
      if (!b) return u;
      return swapBase(u, b, activeOrder[0] || PRIMARY);
    },
    probePrimary: function () {
      return nativeFetch(PRIMARY + HEALTH_PATH, { cache: 'no-store' })
        .then(function (res) {
          var ok = !!(res && res.ok);
          if (ok) setActive(PRIMARY, true);
          return ok;
        })
        .catch(function () { return false; });
    }
  };

  // Sonda inicial (no bloquea): con la principal caída, hasta los links de
  // descarga construidos antes de la primera petición apuntan al espejo.
  // Si arrancamos en el espejo por mismo origen, la sonda periódica queda
  // activa para volver a la principal cuando se recupere.
  if (activeOrder[0] !== PRIMARY) startProbe();
  try {
    nativeFetch(PRIMARY + HEALTH_PATH, { cache: 'no-store' })
      .then(function (res) {
        if (res && res.ok) return;
        if (activeOrder[0] === PRIMARY) setActive(MIRRORS[0], false);
      })
      .catch(function () {
        if (activeOrder[0] === PRIMARY) setActive(MIRRORS[0], false);
      });
  } catch (_) {}
})();
