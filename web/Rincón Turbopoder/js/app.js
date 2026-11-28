/* ==========================================================================
   RINCÓN TURBOPODER — aplicación
   SPA con hash router, carrito local y sesión contra la API de OWS.
   ========================================================================== */

(function () {
  'use strict';

  const UI = window.TPUI;
  const Api = window.TPApi;
  const esc = UI.escapeHtml;
  const money = UI.money;
  const icon = UI.icon;

  const CART_KEY = 'turbopoder_cart';
  const SHIPPING = { flat: 2500, freeFrom: 30000 };
  const CATEGORY_EMOJI = {
    'Tecnología': '💻', 'Hogar': '🛋️', 'Moda': '👕', 'Comida': '🥐', 'Juguetes': '🧸',
    'Arte': '🎨', 'Deportes': '🛹', 'Música': '🎸', 'Libros': '📚', 'Jardín': '🌿',
    'Coleccionables': '🃏', 'Servicios': '🛠️', 'Otros': '📦'
  };
  const STORE_EMOJIS = ['🧰', '🛸', '🎧', '🌿', '🍊', '🎸', '📚', '🛹', '🎨', '🪴', '☕', '🃏', '👟', '💡', '🧵', '🪐', '🐈', '🐕'];
  const ACCENTS = ['#d9ff3c', '#ff3d8b', '#35e0ff', '#ffb340', '#a78bfa', '#3ddc97', '#ff6b4a', '#f2ead6'];

  const state = {
    user: Api.getUser(),
    meta: null,
    cart: loadCart(),
    productIndex: {},
    renderSeq: 0,
    lastOrders: readLastOrders()
  };

  let metaPromise = null;

  /* ------------------------------- carrito -------------------------------- */

  function loadCart() {
    try {
      const raw = localStorage.getItem(CART_KEY);
      const parsed = raw ? JSON.parse(raw) : [];
      if (!Array.isArray(parsed)) return [];
      return parsed.filter(function (item) {
        return item && Number(item.id) > 0 && Number(item.qty) > 0;
      }).map(function (item) {
        return {
          id: Number(item.id),
          qty: Math.min(20, Number(item.qty)),
          name: String(item.name || 'Producto'),
          price: Number(item.price) || 0,
          emoji: String(item.emoji || '📦'),
          imageUrl: String(item.imageUrl || ''),
          stock: Number(item.stock) || 0,
          storeId: Number(item.storeId) || 0,
          storeName: String(item.storeName || ''),
          storeSlug: String(item.storeSlug || ''),
          storeAccent: String(item.storeAccent || '#d9ff3c')
        };
      });
    } catch (error) { return []; }
  }

  function saveCart() {
    try { localStorage.setItem(CART_KEY, JSON.stringify(state.cart)); } catch (error) {}
    updateCartBadge();
  }

  function updateCartBadge() {
    const badge = document.getElementById('cartCount');
    if (!badge) return;
    const count = state.cart.reduce(function (sum, item) { return sum + item.qty; }, 0);
    badge.textContent = count > 99 ? '99+' : String(count);
    badge.hidden = count === 0;
  }

  function cartCount() {
    return state.cart.reduce(function (sum, item) { return sum + item.qty; }, 0);
  }

  function cartGroups() {
    const groups = new Map();
    state.cart.forEach(function (item) {
      if (!groups.has(item.storeId)) {
        groups.set(item.storeId, {
          storeId: item.storeId,
          storeName: item.storeName,
          storeSlug: item.storeSlug,
          storeAccent: item.storeAccent,
          lines: [],
          subtotal: 0
        });
      }
      const group = groups.get(item.storeId);
      group.lines.push(item);
      group.subtotal += item.price * item.qty;
    });
    return Array.from(groups.values()).map(function (group) {
      const free = group.subtotal >= shippingFreeFrom();
      group.shipping = free ? 0 : shippingFlat();
      group.total = group.subtotal + group.shipping;
      return group;
    });
  }

  function cartTotals() {
    const groups = cartGroups();
    const subtotal = groups.reduce(function (sum, g) { return sum + g.subtotal; }, 0);
    const shipping = groups.reduce(function (sum, g) { return sum + g.shipping; }, 0);
    return { groups: groups, subtotal: subtotal, shipping: shipping, total: subtotal + shipping };
  }

  function shippingFlat() {
    return state.meta && state.meta.shipping ? Number(state.meta.shipping.flat) : SHIPPING.flat;
  }

  function shippingFreeFrom() {
    return state.meta && state.meta.shipping ? Number(state.meta.shipping.freeFrom) : SHIPPING.freeFrom;
  }

  function snapshot(product) {
    return {
      id: Number(product.id),
      name: product.name,
      price: Number(product.price),
      emoji: product.emoji || '📦',
      imageUrl: product.imageUrl || '',
      stock: Number(product.stock) || 0,
      storeId: Number(product.storeId) || 0,
      storeName: product.storeName || '',
      storeSlug: product.storeSlug || '',
      storeAccent: product.storeAccent || '#d9ff3c'
    };
  }

  function addToCart(product, qty) {
    const amount = Math.max(1, Number(qty) || 1);
    const existing = state.cart.find(function (item) { return item.id === Number(product.id); });
    const stock = Number(product.stock) || 0;
    if (existing) {
      existing.qty = Math.min(20, stock || 20, existing.qty + amount);
    } else {
      const item = snapshot(product);
      item.qty = Math.min(20, stock || 20, amount);
      state.cart.push(item);
    }
    saveCart();
    UI.toast(product.name + ' entró al carrito.', 'success');
  }

  function setCartQty(id, qty) {
    const item = state.cart.find(function (entry) { return entry.id === Number(id); });
    if (!item) return;
    if (qty <= 0) {
      state.cart = state.cart.filter(function (entry) { return entry.id !== Number(id); });
    } else {
      item.qty = Math.min(20, item.stock || 20, qty);
    }
    saveCart();
  }

  function removeFromCart(id) {
    state.cart = state.cart.filter(function (entry) { return entry.id !== Number(id); });
    saveCart();
  }

  /* -------------------------------- sesión -------------------------------- */

  function updateAccount() {
    const btn = document.getElementById('accountBtn');
    if (!btn) return;
    if (state.user) {
      btn.setAttribute('href', '#/panel');
      btn.setAttribute('aria-label', 'Mi panel: ' + state.user.name);
      btn.classList.add('is-user');
    } else {
      btn.setAttribute('href', '#/entrar');
      btn.setAttribute('aria-label', 'Mi cuenta');
      btn.classList.remove('is-user');
    }
  }

  function applySession(user, token) {
    state.user = user;
    Api.setSession(token, user);
    updateAccount();
  }

  function logout() {
    Api.clearSession();
    state.user = null;
    updateAccount();
    UI.toast('Cerré tu sesión. Nos vemos en el rincón.');
    navigate('/');
  }

  async function ensureUser() {
    if (!Api.getToken()) { state.user = null; updateAccount(); return null; }
    if (state.user) return state.user;
    try {
      const data = await Api.me();
      state.user = data.user;
      Api.setSession(Api.getToken(), data.user);
      updateAccount();
    } catch (error) {
      if (error.status === 401) {
        Api.clearSession();
        state.user = null;
        updateAccount();
      }
    }
    return state.user;
  }
    /* ------------------------------ utilidades ------------------------------ */

  async function getMeta() {
    if (state.meta) return state.meta;
    if (!metaPromise) {
      metaPromise = Api.meta().then(function (data) {
        state.meta = data;
        return data;
      }).catch(function (error) {
        metaPromise = null;
        throw error;
      });
    }
    return metaPromise;
  }

  function setView(html) {
    const view = document.getElementById('view');
    view.innerHTML = html;
  }

  function sectionHead(title, subtitle, href, label) {
    return (
      '<div class="section-head">' +
        '<div><h2>' + title + '</h2>' + (subtitle ? '<p>' + subtitle + '</p>' : '') + '</div>' +
        (href ? '<a class="link-arrow" href="' + href + '">' + label + ' ' + icon('arrowRight', 14) + '</a>' : '') +
      '</div>'
    );
  }

  function productGrid(products, options) {
    if (!products.length) return '';
    products.forEach(function (product) { state.productIndex[product.id] = product; });
    return '<div class="product-grid">' + products.map(function (product) {
      return UI.productTile(product, options);
    }).join('') + '</div>';
  }

  function categoryTiles(categories) {
    const items = categories.filter(function (category) { return category !== 'Otros'; });
    return '<div class="cat-strip">' + items.map(function (category) {
      return '<a class="cat-tile" href="#/catalogo?cat=' + encodeURIComponent(category) + '">' +
        '<span class="emoji" aria-hidden="true">' + (CATEGORY_EMOJI[category] || '📦') + '</span>' +
        '<b>' + esc(category) + '</b>' +
        '<small>Ver productos</small>' +
      '</a>';
    }).join('') + '<a class="cat-tile" href="#/catalogo">' +
      '<span class="emoji" aria-hidden="true">🧭</span><b>Todo el catálogo</b><small>Sin filtro</small></a></div>';
  }

  function errorBlock(error, retryLabel) {
    const offline = error && (error.offline || error.name === 'TypeError');
    return '<div class="error-state">' +
      '<span class="emoji" aria-hidden="true">' + (offline ? '📡' : '🧯') + '</span>' +
      '<h3>' + (offline ? 'Se cortó la señal del rincón' : 'Algo se trabó de este lado') + '</h3>' +
      '<p>' + esc(error && error.message ? error.message : 'Probá de nuevo en un rato.') + '</p>' +
      '<button class="btn btn-turbo" type="button" data-action="retry">' + (retryLabel || 'Reintentar') + '</button>' +
      '</div>';
  }

  function emptyBlock(emoji, title, text, href, label) {
    return '<div class="empty-state">' +
      '<span class="emoji" aria-hidden="true">' + emoji + '</span>' +
      '<h3>' + title + '</h3>' +
      '<p>' + text + '</p>' +
      (href ? '<a class="btn btn-turbo" href="' + href + '">' + label + '</a>' : '') +
      '</div>';
  }

  function pageHead(title, subtitle, extra) {
    return '<div class="page-head"><h1>' + title + '</h1>' + (subtitle ? '<p>' + subtitle + '</p>' : '') + (extra || '') + '</div>';
  }

  function queryFromHash() {
    const raw = window.location.hash.replace(/^#/, '');
    const index = raw.indexOf('?');
    if (index === -1) return { path: raw || '/', params: new URLSearchParams() };
    return { path: raw.slice(0, index), params: new URLSearchParams(raw.slice(index + 1)) };
  }

  /* --------------------------------- home --------------------------------- */

  async function viewHome() {
    const meta = await getMeta();
    const results = await Promise.all([
      Api.products({ sort: 'vendidos', limit: 8 }),
      Api.stores({ limit: 4 }),
      Api.products({ sort: 'recientes', limit: 4 })
    ]);
    const featured = results[0].products || [];
    const stores = results[1].stores || [];
    const fresh = (results[2].products || []).filter(function (product) {
      return !featured.some(function (other) { return other.id === product.id; });
    }).slice(0, 4);
    const stats = meta.stats || {};

    const heroCards = [featured[0], featured[2], fresh[1] || featured[4]].filter(Boolean);
    const artCards = ['c1', 'c2', 'c3'].map(function (klass, index) {
      const product = heroCards[index];
      if (!product) return '';
      return '<div class="hero-card ' + klass + '">' +
        '<span class="emoji" aria-hidden="true">' + esc(product.emoji) + '</span>' +
        '<div><b>' + esc(product.name) + '</b><br /><small>' + esc(UI.truncate(product.storeName, 24)) + '</small></div>' +
      '</div>';
    }).join('');

    setView(
      '<section class="hero"><div class="container hero-grid">' +
        '<div>' +
          '<span class="eyebrow">Mercado abierto · ' + (stats.stores || 0) + ' rincones</span>' +
          '<h1>Vendé lo que sea. Comprá lo que <span class="mark">no sabías</span> que necesitabas.</h1>' +
          '<p class="hero-lede">Tiendas de barrio, talleres y coleccionistas en la misma vereda. Entrá, mirá y llevate algo raro: acá no hay góndola que te diga qué buscar.</p>' +
          '<div class="hero-actions"><a class="btn btn-turbo" href="#/catalogo">Recorrer el catálogo ' + icon('arrowRight', 15) + '</a>' +
          '<a class="btn btn-ghost" href="#/vender">Abrir mi rincón</a></div>' +
          '<form class="hero-search" id="homeSearch" role="search">' + icon('search', 17) +
            '<input type="search" name="q" placeholder="Buscá una lámpara, un vinilo, un teclado…" aria-label="Buscar productos" />' +
            '<button class="btn btn-turbo btn-sm" type="submit">Buscar</button></form>' +
          '<div class="hero-stats">' +
            '<div class="hero-stat"><strong>' + (stats.stores || 0) + '</strong><span>rincones abiertos</span></div>' +
            '<div class="hero-stat"><strong>' + (stats.products || 0) + '</strong><span>productos en vidriera</span></div>' +
            '<div class="hero-stat"><strong>' + (stats.categories || 0) + '</strong><span>categorías</span></div>' +
          '</div>' +
        '</div>' +
        '<div class="hero-art" aria-hidden="true">' +
          '<div class="hero-orbit"></div>' + artCards +
          '<div class="hero-sticker">Envío gratis<br />desde<b>' + money(shippingFreeFrom()) + '</b></div>' +
        '</div>' +
      '</div></section>' +

      '<section class="section container">' +
        sectionHead('Cada cosa tiene su rincón', 'Elegí por dónde entrar. Siempre hay algo que no esperabas.', '#/catalogo', 'Ver todo') +
        categoryTiles(meta.categories || []) +
      '</section>' +

      (featured.length ? '<section class="section container">' +
        sectionHead('Lo que más circula', 'Lo que la gente se lleva sin pensarlo dos veces.', '#/catalogo?sort=vendidos', 'Ver más') +
        productGrid(featured, {}) + '</section>' : '') +

      (stores.length ? '<section class="section container">' +
        sectionHead('Rincones que valen la pena', 'Tiendas con nombre propio y algo para mostrar.', '#/tiendas', 'Todas las tiendas') +
        '<div class="store-grid">' + stores.map(UI.storeCard).join('') + '</div></section>' : '') +

      (fresh.length ? '<section class="section container">' +
        sectionHead('Recién colgados', 'Lo último que entró a la vidriera.', '#/catalogo', 'Ver catálogo') +
        productGrid(fresh, {}) + '</section>' : '') +

      '<section class="section container" id="pasos">' +
        sectionHead('Abrir tu rincón, en tres movimientos', 'Sin formularios eternos ni comisiones de bienvenida.') +
        '<div class="steps">' +
          '<article class="step"><div class="num">01</div><h3>Poné nombre y onda</h3><p>Elegí cómo se llama tu tienda, qué vendés y con qué color te identificás. Tarda menos que preparar un café.</p></article>' +
          '<article class="step"><div class="num">02</div><h3>Cargá lo primero</h3><p>Un producto alcanza para arrancar. Foto o emoji, precio y stock: después sumás el resto cuando quieras.</p></article>' +
          '<article class="step"><div class="num">03</div><h3>Que circule</h3><p>Compartí el link de tu rincón. Los pedidos te llegan al panel y los coordinás directo con quien compra.</p></article>' +
        '</div></section>' +

      '<section class="container"><div class="cta-band">' +
        '<div><h2>Tu rincón puede estar abierto esta tarde.</h2>' +
        '<p>No hace falta un catálogo enorme. Con ganas y una idea alcanza para empezar a vender.</p></div>' +
        '<a class="btn btn-turbo" href="#/vender">Abrir mi tienda ' + icon('arrowRight', 15) + '</a>' +
      '</div></section>'
    );

    const search = document.getElementById('homeSearch');
    if (search) {
      search.addEventListener('submit', function (event) {
        event.preventDefault();
        const value = search.querySelector('input').value.trim();
        navigate('/catalogo' + (value ? '?q=' + encodeURIComponent(value) : ''));
      });
    }
  }
  /* ------------------------------- catálogo -------------------------------- */

  function catalogHref(options) {
    const params = new URLSearchParams();
    if (options.cat) params.set('cat', options.cat);
    if (options.q) params.set('q', options.q);
    if (options.sort && options.sort !== 'recientes') params.set('sort', options.sort);
    const text = params.toString();
    return '#/catalogo' + (text ? '?' + text : '');
  }

  function catalogBar(categories, activeCat, query, sort) {
    const chips = ['Todos'].concat(categories).map(function (category) {
      const isActive = category === 'Todos' ? !activeCat : category === activeCat;
      const catValue = category === 'Todos' ? '' : category;
      return '<a class="chip' + (isActive ? ' is-active' : '') + '" href="' + catalogHref({ cat: catValue, q: query, sort: sort }) + '">' +
        esc(category) + '</a>';
    }).join('');
    return '<div class="catalog-bar">' +
      '<form class="catalog-search" id="catalogSearch" role="search">' + icon('search', 16) +
        '<input type="search" name="q" value="' + esc(query) + '" placeholder="Buscar en el rincón…" aria-label="Buscar productos" />' +
        '<button type="submit" aria-label="Buscar">' + icon('arrowRight', 15) + '</button></form>' +
      '<select class="select" id="catalogSort" aria-label="Ordenar resultados">' +
        [['recientes', 'Recién llegados'], ['vendidos', 'Los más vendidos'], ['precio-asc', 'Menor precio'], ['precio-desc', 'Mayor precio'], ['nombre', 'Nombre A-Z']].map(function (pair) {
          return '<option value="' + pair[0] + '"' + (sort === pair[0] ? ' selected' : '') + '>' + pair[1] + '</option>';
        }).join('') +
      '</select>' +
      '<span class="results-meta" id="catalogCount"></span>' +
    '</div>' +
    '<div class="chip-row" style="margin-bottom:24px">' + chips + '</div>';
  }

  async function viewCatalog(params) {
    const meta = await getMeta();
    const query = (params.get('q') || '').trim();
    const category = params.get('cat') || '';
    const sort = params.get('sort') || 'recientes';
    const title = category || (query ? 'Resultados para “' + query + '”' : 'Todo el catálogo');

    setView(
      '<div class="container">' +
        pageHead(title, category || query ? 'Los productos que coinciden con tu búsqueda.' : 'Lo que está en la vidriera ahora mismo, de todos los rincones.') +
        catalogBar(meta.categories || [], category, query, sort) +
        '<div id="catalogResults">' + UI.skeletonGrid(8) + '</div>' +
      '</div>'
    );

    const form = document.getElementById('catalogSearch');
    if (form) {
      form.addEventListener('submit', function (event) {
        event.preventDefault();
        const value = form.querySelector('input').value.trim();
        navigate('/catalogo' + (function () {
          const search = new URLSearchParams();
          if (category) search.set('cat', category);
          if (value) search.set('q', value);
          if (sort !== 'recientes') search.set('sort', sort);
          const text = search.toString();
          return text ? '?' + text : '';
        })());
      });
    }

    const select = document.getElementById('catalogSort');
    if (select) {
      select.addEventListener('change', function () {
        navigate(catalogHref({ cat: category, q: query, sort: select.value }));
      });
    }

    const results = document.getElementById('catalogResults');
    const countLabel = document.getElementById('catalogCount');
    let offset = 0;
    let lastCount = 0;

    async function loadMore() {
      const data = await Api.products({ search: query, category: category, sort: sort, limit: 12, offset: offset });
      const products = data.products || [];
      lastCount = products.length;
      offset += products.length;
      if (!products.length && offset === 0) {
        results.innerHTML = emptyBlock('🔍', 'Ese rincón está vacío', 'No encontramos nada con esos filtros. Probá con otra palabra o mirá todo el catálogo.', '#/catalogo', 'Ver todo');
        if (countLabel) countLabel.textContent = 'Sin resultados';
        return;
      }
      if (offset === products.length) {
        results.innerHTML = '<div class="product-grid" id="catalogGrid"></div><div class="load-more-wrap" id="loadMoreWrap"></div>';
      }
      const grid = document.getElementById('catalogGrid');
      grid.insertAdjacentHTML('beforeend', products.map(function (product) {
        state.productIndex[product.id] = product;
        return UI.productTile(product, {});
      }).join(''));
      if (countLabel) countLabel.textContent = offset + (products.length === 12 ? '+' : '') + (offset === 1 ? ' producto' : ' productos');
      const wrap = document.getElementById('loadMoreWrap');
      wrap.innerHTML = products.length === 12
        ? '<button class="btn btn-dark" type="button" id="loadMoreBtn">Ver más productos</button>'
        : '<span class="tiny muted">Eso es todo por acá.</span>';
      const button = document.getElementById('loadMoreBtn');
      if (button) {
        button.addEventListener('click', function () {
          button.disabled = true;
          button.textContent = 'Cargando…';
          loadMore().catch(function (error) {
            UI.toast(error.message, 'error');
            button.disabled = false;
            button.textContent = 'Ver más productos';
          });
        });
      }
    }

    try {
      await loadMore();
    } catch (error) {
      results.innerHTML = errorBlock(error);
    }
  }

  /* -------------------------------- tiendas -------------------------------- */

  async function viewStores(params) {
    const query = (params.get('q') || '').trim();
    setView(
      '<div class="container">' +
        pageHead('Los rincones', 'Tiendas con nombre, color y algo para vender. Entrá a la que te llame.') +
        '<form class="catalog-search" id="storeSearch" style="margin-bottom:24px" role="search">' + icon('search', 16) +
        '<input type="search" name="q" value="' + esc(query) + '" placeholder="Buscar una tienda…" aria-label="Buscar tiendas" />' +
        '<button type="submit" aria-label="Buscar">' + icon('arrowRight', 15) + '</button></form>' +
        '<div id="storesResults">' + UI.skeletonGrid(6) + '</div>' +
      '</div>'
    );

    const form = document.getElementById('storeSearch');
    if (form) {
      form.addEventListener('submit', function (event) {
        event.preventDefault();
        const value = form.querySelector('input').value.trim();
        navigate('/tiendas' + (value ? '?q=' + encodeURIComponent(value) : ''));
      });
    }

    const box = document.getElementById('storesResults');
    try {
      const data = await Api.stores({ search: query, limit: 60 });
      const stores = data.stores || [];
      box.innerHTML = stores.length
        ? '<div class="store-grid">' + stores.map(UI.storeCard).join('') + '</div>'
        : emptyBlock('🏚️', 'No hay rincones con ese nombre', 'Probá con otra palabra. O abrí el tuyo y quedate con el nombre primero.', '#/vender', 'Abrir mi tienda');
    } catch (error) {
      box.innerHTML = errorBlock(error);
    }
  }
  /* -------------------------------- tienda --------------------------------- */

  async function viewStore(params, slug) {
    const data = await Api.store(decodeURIComponent(slug));
    const store = data.store;
    const products = data.products || [];
    state.currentStore = store;
    const isOwner = state.user && Number(store.ownerId) === Number(state.user.id);
    const rating = store.reviewCount ? UI.ratingLabel(store.rating, store.reviewCount) : '<span class="rating">Sin opiniones todavía</span>';

    setView(
      '<div class="container">' +
        '<nav class="breadcrumb"><a href="#/">Inicio</a><span>/</span><a href="#/tiendas">Tiendas</a><span>/</span><span>' + esc(store.name) + '</span></nav>' +
        '<section class="store-hero" style="--accent:' + esc(store.accent) + '">' +
          '<div class="store-hero-inner">' +
            '<span class="store-emoji" aria-hidden="true">' + esc(store.emoji) + '</span>' +
            '<div style="min-width:0">' +
              '<div class="store-cat">' + esc(store.category) + '</div>' +
              '<h1>' + esc(store.name) + '</h1>' +
              '<p>' + esc(store.tagline || '') + '</p>' +
              (store.description ? '<p class="tiny" style="opacity:.72">' + esc(store.description) + '</p>' : '') +
              '<div class="store-hero-meta">' +
                '<span>' + icon('package', 14) + products.length + ' productos</span>' +
                '<span>' + icon('user', 14) + (store.ownerName ? 'A cargo de ' + esc(store.ownerName) : 'Rincón independiente') + '</span>' +
                '<span>' + rating + '</span>' +
                (store.createdAt ? '<span>Abierto desde ' + UI.dateShort(store.createdAt) + '</span>' : '') +
              '</div>' +
            '</div>' +
            '<div class="store-hero-actions">' +
              (isOwner
                ? '<button class="btn btn-dark btn-sm" type="button" data-action="edit-store" data-id="' + store.id + '">Editar tienda</button>' +
                  '<button class="btn btn-turbo btn-sm" type="button" data-action="new-product" data-store="' + store.id + '">Sumar producto</button>'
                : '<button class="btn btn-ghost btn-sm" type="button" data-action="share-store" data-slug="' + esc(store.slug) + '">Compartir rincón</button>') +
            '</div>' +
          '</div>' +
        '</section>' +

        '<section class="section">' +
          (products.length
            ? sectionHead('Todo lo que hay acá', products.length + (products.length === 1 ? ' producto en la vidriera.' : ' productos en la vidriera.')) + productGrid(products, {})
            : emptyBlock('📦', 'La vidriera está esperando', isOwner ? 'Cargá tu primer producto y empezá a mostrarlo.' : 'Este rincón todavía no colgó nada. Volvé en un rato.', isOwner ? '' : '#/catalogo', 'Seguir mirando')) +
        '</section>' +
      '</div>'
    );

    const share = document.querySelector('[data-action="share-store"]');
    if (share) {
      share.addEventListener('click', function () {
        const url = window.location.origin + window.location.pathname + '#/tienda/' + store.slug;
        copyText(url).then(function () { UI.toast('Link del rincón copiado.', 'success'); });
      });
    }
  }

  /* ------------------------------- producto -------------------------------- */

  async function viewProduct(params, id) {
    const data = await Api.product(id);
    const product = data.product;
    const reviews = data.reviews || [];
    const related = data.related || [];
    const out = Number(product.stock) <= 0;
    const low = product.stock > 0 && product.stock <= 5;
    const stockClass = out ? 'out' : (low ? 'low' : '');
    const stockText = out ? 'Sin stock por ahora' : (low ? 'Quedan ' + product.stock + ' unidades' : product.stock + ' disponibles');
    state.productIndex[product.id] = product;

    const reviewLocks = reviews.map(function (review) {
      return '<article class="review"><div class="review-head"><b>' + esc(review.author) + '</b>' +
        '<small>' + UI.dateShort(review.createdAt) + ' · ' + '★'.repeat(review.rating) + '</small></div>' +
        (review.comment ? '<p>' + esc(review.comment) + '</p>' : '<p class="tiny muted">Sin comentario, solo la puntuación.</p>') +
        '</article>';
    }).join('');

    const reviewForm = state.user
      ? '<form id="reviewForm" class="mt-16" style="padding:18px;border:1px solid var(--line);border-radius:16px;background:rgba(255,255,255,.02)">' +
        '<div class="form-grid">' +
          '<div class="field full"><span>Tu puntuación</span><div class="star-input" id="starInput">' +
            [1, 2, 3, 4, 5].map(function (value) {
              return '<button type="button" class="star-btn' + (value <= 5 ? ' is-on' : '') + '" data-star="' + value + '" aria-label="' + value + ' de 5">★</button>';
            }).join('') +
          '</div><input type="hidden" name="rating" value="5" /></div>' +
          '<div class="field full"><span>Comentario (opcional)</span><textarea class="textarea" name="comment" maxlength="600" placeholder="¿Cómo llegó? ¿Era lo que esperabas?"></textarea></div>' +
        '</div>' +
        '<div class="modal-foot" style="margin-top:14px"><button class="btn btn-turbo btn-sm" type="submit">Publicar opinión</button></div>' +
        '</form>'
      : '<div class="row mt-16"><button class="btn btn-dark btn-sm" type="button" id="reviewLogin">Entrá para dejar tu opinión</button></div>';

    setView(
      '<div class="container">' +
        '<nav class="breadcrumb"><a href="#/catalogo">Catálogo</a><span>/</span><a href="#/tienda/' + esc(product.storeSlug) + '">' + esc(product.storeName) + '</a></nav>' +
        '<div class="product-layout">' +
          '<div class="product-hero-media" style="--glow:' + esc(product.storeAccent) + '">' +
            (product.imageUrl ? '<img src="' + esc(product.imageUrl) + '" alt="' + esc(product.name) + '" />' : '<span class="tile-emoji" aria-hidden="true">' + esc(product.emoji) + '</span>') +
          '</div>' +
          '<div class="product-info">' +
            '<a class="seller-chip" href="#/tienda/' + esc(product.storeSlug) + '" style="--accent:' + esc(product.storeAccent) + '">' +
              '<span class="store-emoji" aria-hidden="true">' + esc(product.storeEmoji) + '</span>' +
              '<span>' + esc(product.storeName) + '<br /><small class="muted">' + esc(product.storeTagline || 'Rincón independiente') + '</small></span>' +
            '</a>' +
            '<h1>' + esc(product.name) + '</h1>' +
            '<div class="row">' + (product.reviewCount ? UI.ratingLabel(product.rating, product.reviewCount) : '<span class="rating">Todavía sin opiniones</span>') +
              '<span class="tiny muted">·</span><span class="tiny muted">' + product.sales + ' vendidos</span></div>' +
            '<div class="product-price-row"><span class="price">' + money(product.price) + '</span>' +
              '<span class="stock-pill ' + stockClass + '">' + esc(stockText) + '</span></div>' +
            '<p class="product-desc">' + (product.description ? esc(product.description) : 'El vendedor no sumó una descripción, pero podés escribirle desde el panel del rincón si necesitás un detalle.') + '</p>' +
            '<div class="buy-row">' +
              '<div class="stepper"><button type="button" data-qty-minus aria-label="Restar">−</button><span id="detailQty">1</span><button type="button" data-qty-plus aria-label="Sumar">+</button></div>' +
              '<button class="btn btn-turbo" type="button" id="detailAdd"' + (out ? ' disabled' : '') + '>' + icon('cart', 16) + ' Agregar al carrito</button>' +
              '<button class="btn btn-ghost" type="button" id="detailBuy"' + (out ? ' disabled' : '') + '>Comprar ya</button>' +
            '</div>' +
            '<p class="shipping-note">' + icon('package', 15) + ' Envío ' + money(shippingFlat()) + ' por tienda · gratis desde ' + money(shippingFreeFrom()) + '</p>' +
            '<div class="row" style="border-top:1px solid var(--line);padding-top:16px">' +
              '<span class="tiny muted">Categoría: <a href="#/catalogo?cat=' + encodeURIComponent(product.category) + '" style="color:var(--turbo)">' + esc(product.category) + '</a></span>' +
              '<span class="spacer"></span>' +
              '<span class="tiny muted">Publicado ' + UI.dateShort(product.createdAt) + '</span>' +
            '</div>' +
          '</div>' +
        '</div>' +

        '<section class="section" id="opiniones">' +
          sectionHead('Lo que dicen', reviews.length ? 'Opiniones de gente que ya lo llevó.' : 'Todavía nadie se animó a opinar.') +
          '<div class="review-list">' + (reviewLocks || '<p class="tiny muted">Sin opiniones por ahora.</p>') + '</div>' + reviewForm +
        '</section>' +

        (related.length ? '<section class="section">' + sectionHead('Del mismo rincón', 'Otros productos de ' + esc(product.storeName) + '.') + productGrid(related, {}) + '</section>' : '') +
      '</div>'
    );

    let qty = 1;
    const qtyLabel = document.getElementById('detailQty');
    const minus = document.querySelector('[data-qty-minus]');
    const plus = document.querySelector('[data-qty-plus]');
    function paintQty() { if (qtyLabel) qtyLabel.textContent = String(qty); }
    if (minus) minus.addEventListener('click', function () { qty = Math.max(1, qty - 1); paintQty(); });
    if (plus) plus.addEventListener('click', function () { qty = Math.min(Math.max(1, product.stock), 20, qty + 1); paintQty(); });

    const addBtn = document.getElementById('detailAdd');
    if (addBtn && !out) addBtn.addEventListener('click', function () { addToCart(product, qty); });
    const buyBtn = document.getElementById('detailBuy');
    if (buyBtn && !out) buyBtn.addEventListener('click', function () { addToCart(product, qty); navigate('/carrito'); });

    const starWrap = document.getElementById('starInput');
    if (starWrap) {
      const ratingInput = starWrap.parentElement.querySelector('input[name="rating"]');
      starWrap.addEventListener('click', function (event) {
        const button = event.target.closest('[data-star]');
        if (!button) return;
        const value = Number(button.getAttribute('data-star'));
        if (ratingInput) ratingInput.value = String(value);
        starWrap.querySelectorAll('[data-star]').forEach(function (star) {
          star.classList.toggle('is-on', Number(star.getAttribute('data-star')) <= value);
        });
      });
    }

    const reviewFormEl = document.getElementById('reviewForm');
    if (reviewFormEl) {
      reviewFormEl.addEventListener('submit', async function (event) {
        event.preventDefault();
        const button = reviewFormEl.querySelector('button[type="submit"]');
        button.disabled = true;
        try {
          const payload = UI.formDataToObject(reviewFormEl);
          await Api.addReview(product.id, { rating: payload.rating, comment: payload.comment || '' });
          UI.toast('Tu opinión quedó publicada.', 'success');
          await viewProduct(params, id);
        } catch (error) {
          UI.toast(error.message, 'error');
          button.disabled = false;
        }
      });
    }

    const reviewLogin = document.getElementById('reviewLogin');
    if (reviewLogin) {
      reviewLogin.addEventListener('click', function () {
        openAuthModal('login').then(function (user) {
          if (user) viewProduct(params, id);
        });
      });
    }
  }
  /* -------------------------------- carrito -------------------------------- */

  function cartItemHtml(item) {
    return '<div class="cart-item">' +
      '<a class="cart-thumb" href="#/producto/' + item.id + '" style="--glow:' + esc(item.storeAccent) + '">' +
        (item.imageUrl ? '<img src="' + esc(item.imageUrl) + '" alt="' + esc(item.name) + '" />' : esc(item.emoji)) +
      '</a>' +
      '<div class="cart-item-info">' +
        '<b><a href="#/producto/' + item.id + '">' + esc(item.name) + '</a></b>' +
        '<small><a href="#/tienda/' + esc(item.storeSlug) + '">' + esc(item.storeName) + '</a> · ' + money(item.price) + ' c/u</small>' +
        '<div class="qty-inline" style="width:fit-content">' +
          '<button type="button" data-action="cart-minus" data-id="' + item.id + '" aria-label="Restar uno">−</button>' +
          '<span>' + item.qty + '</span>' +
          '<button type="button" data-action="cart-plus" data-id="' + item.id + '" aria-label="Sumar uno">+</button>' +
        '</div>' +
      '</div>' +
      '<div class="cart-item-actions">' +
        '<span class="price">' + money(item.price * item.qty) + '</span>' +
        '<button class="remove-link" type="button" data-action="cart-remove" data-id="' + item.id + '">Quitar</button>' +
      '</div>' +
    '</div>';
  }

  async function viewCart() {
    await getMeta().catch(function () {});
    if (!state.cart.length) {
      setView('<div class="container">' + pageHead('El carrito', 'Todavía no elegiste nada. El rincón tiene de todo, aunque no lo parezca.') +
        emptyBlock('🛒', 'Carrito vacío, mente abierta', 'Cuando algo te guste, sumalo y volvé. Guardamos todo acá.', '#/catalogo', 'Ir al catálogo') + '</div>');
      return;
    }

    const totals = cartTotals();
    const user = state.user || {};
    const savedEmail = Api.lastEmail() || user.email || '';
    const shippingLines = totals.groups.map(function (group) {
      return '<div class="summary-row"><span>' + esc(group.storeName) + '</span><strong>' + (group.shipping ? money(group.shipping) : 'Gratis') + '</strong></div>';
    }).join('');

    setView(
      '<div class="container">' +
        pageHead('El carrito', cartCount() + (cartCount() === 1 ? ' producto esperando.' : ' productos esperando.')) +
        '<div class="cart-layout">' +
          '<div>' +
            '<div class="cart-list">' + state.cart.map(cartItemHtml).join('') + '</div>' +
            '<form id="checkoutForm" class="summary-card" style="position:static;margin-top:22px" novalidate>' +
              '<h2>Datos de entrega</h2>' +
              '<div class="form-grid">' +
                '<label class="field"><span>Nombre y apellido</span><input class="input" name="buyerName" required minlength="2" value="' + esc(user.name || '') + '" placeholder="Quién recibe" /></label>' +
                '<label class="field"><span>Correo</span><input class="input" name="buyerEmail" type="email" required value="' + esc(savedEmail) + '" placeholder="vos@correo.com" /></label>' +
                '<label class="field"><span>Teléfono</span><input class="input" name="buyerPhone" value="" placeholder="Opcional, para coordinar" /></label>' +
                '<label class="field"><span>Dirección</span><input class="input" name="address" required minlength="5" placeholder="Calle, número, piso" /></label>' +
                '<label class="field full"><span>Nota para el vendedor</span><textarea class="textarea" name="note" maxlength="500" placeholder="Horarios, referencias, algún detalle"></textarea></label>' +
              '</div>' +
              '<p class="tiny muted mt-16">El pedido se registra y cada tienda lo coordina con vos. El pago se arregla directo al recibir o por el medio que acuerden.</p>' +
            '</form>' +
          '</div>' +
          '<aside class="summary-card">' +
            '<h2>Resumen</h2>' +
            '<div class="summary-row"><span>Productos</span><strong>' + money(totals.subtotal) + '</strong></div>' +
            shippingLines +
            '<div class="summary-total"><span>Total</span><span>' + money(totals.total) + '</span></div>' +
            '<button class="btn btn-turbo btn-block mt-16" type="submit" form="checkoutForm" id="checkoutBtn">Confirmar pedido</button>' +
            '<p class="tiny muted mt-8">Sin pagos online: coordinás con cada rincón.</p>' +
            '<a class="link-arrow mt-16" href="#/catalogo" style="font-size:11px">Seguir mirando</a>' +
          '</aside>' +
        '</div>' +
      '</div>'
    );

    const form = document.getElementById('checkoutForm');
    const button = document.getElementById('checkoutBtn');
    if (!form || !button) return;
    form.addEventListener('submit', async function (event) {
      event.preventDefault();
      if (!form.reportValidity()) return;
      button.disabled = true;
      button.textContent = 'Confirmando…';
      try {
        const payload = UI.formDataToObject(form);
        const data = await Api.checkout({
          items: state.cart.map(function (item) { return { productId: item.id, qty: item.qty }; }),
          buyerName: payload.buyerName,
          buyerEmail: payload.buyerEmail,
          buyerPhone: payload.buyerPhone,
          address: payload.address,
          note: payload.note
        });
        const orders = data.orders || [];
        Api.lastEmail(payload.buyerEmail);
        state.lastOrders = { codes: orders.map(function (order) { return order.code; }), email: payload.buyerEmail, at: Date.now() };
        try { sessionStorage.setItem('turbopoder_last_orders', JSON.stringify(state.lastOrders)); } catch (error) {}
        state.cart = [];
        saveCart();
        UI.toast('Pedido confirmado. Te dejamos el detalle.', 'success');
        if (orders.length) navigate('/pedido/' + orders[0].code + '?email=' + encodeURIComponent(payload.buyerEmail));
        else navigate('/');
      } catch (error) {
        UI.toast(error.message, 'error');
        button.disabled = false;
        button.textContent = 'Confirmar pedido';
      }
    });
  }
  /* -------------------------------- pedidos -------------------------------- */

  function readLastOrders() {
    try {
      const raw = sessionStorage.getItem('turbopoder_last_orders');
      return raw ? JSON.parse(raw) : null;
    } catch (error) { return null; }
  }

  function orderTrack(status) {
    const steps = ['pendiente', 'confirmado', 'enviado', 'entregado'];
    const labels = { pendiente: 'Recibido', confirmado: 'Confirmado', enviado: 'En camino', entregado: 'Entregado' };
    const current = steps.indexOf(status);
    if (status === 'cancelado') {
      return '<div class="cancelled-note">Este pedido quedó cancelado. Si fue un error, escribile a la tienda.</div>';
    }
    return '<div class="order-track">' + steps.map(function (step, index) {
      const stateClass = index < current ? 'done' : (index === current ? 'current' : 'todo');
      return '<div class="track-step ' + stateClass + '"><span class="track-dot">' + (index < current ? '✓' : String(index + 1)) + '</span>' +
        '<span class="track-label">' + labels[step] + '</span></div>';
    }).join('') + '</div>';
  }

  async function viewOrder(params, code) {
    const email = (params.get('email') || Api.lastEmail() || '').trim();
    const orderCode = decodeURIComponent(code).toUpperCase();

    if (!email) {
      setView('<div class="container">' + pageHead('Seguí tu pedido', 'Necesitamos el código que te dimos al confirmar y el correo de la compra.') +
        trackingFormHtml(orderCode) + '</div>');
      bindTrackingForm();
      return;
    }

    let order;
    try {
      const data = await Api.orderByCode(orderCode, email);
      order = data.order;
    } catch (error) {
      setView('<div class="container">' + pageHead('Ese pedido no aparece', 'Puede que el correo no coincida o que el código esté mal escrito.') +
        trackingFormHtml(orderCode) + errorBlock(error) + '</div>');
      bindTrackingForm();
      return;
    }

    const last = state.lastOrders || readLastOrders();
    const isFresh = last && (last.codes || []).indexOf(order.code) !== -1 && Date.now() - Number(last.at || 0) < 1000 * 60 * 60 * 12;
    const itemRows = (order.items || []).map(function (item) {
      return '<div class="summary-row"><span>' + item.qty + ' × ' + esc(item.name) + '</span><strong>' + money(Number(item.price) * Number(item.qty)) + '</strong></div>';
    }).join('');

    setView(
      '<div class="container">' +
        '<nav class="breadcrumb"><a href="#/">Inicio</a><span>/</span><span>Seguimiento</span></nav>' +
        (isFresh ? '<div class="order-flash"><span class="flash-check">✓</span><div><b>Pedido confirmado</b><p>Guarda el código ' + esc(order.code) + ': con eso y tu correo podés seguirlo cuando quieras.</p></div></div>' : '') +
        '<div class="page-head" style="padding-top:0"><div class="row"><h1>Pedido ' + esc(order.code) + '</h1><span class="status-pill ' + esc(order.status) + '">' + esc(order.status) + '</span></div>' +
        '<p>' + UI.dateLong(order.createdAt) + ' · ' + esc(order.storeName) + '</p></div>' +
        orderTrack(order.status) +
        '<div class="order-layout">' +
          '<div class="summary-card" style="position:static">' +
            '<h2>Lo que pediste</h2>' + itemRows +
            '<div class="summary-row" style="border-top:1px solid var(--line);margin-top:8px;padding-top:12px"><span>Subtotal</span><strong>' + money(order.subtotal) + '</strong></div>' +
            '<div class="summary-row"><span>Envío</span><strong>' + (Number(order.shipping) ? money(order.shipping) : 'Gratis') + '</strong></div>' +
            '<div class="summary-total"><span>Total</span><span>' + money(order.total) + '</span></div>' +
          '</div>' +
          '<div class="summary-card" style="position:static">' +
            '<h2>Entrega</h2>' +
            '<div class="summary-row"><span>Recibe</span><strong>' + esc(order.buyerName) + '</strong></div>' +
            '<div class="summary-row"><span>Correo</span><strong>' + esc(order.buyerEmail) + '</strong></div>' +
            (order.buyerPhone ? '<div class="summary-row"><span>Teléfono</span><strong>' + esc(order.buyerPhone) + '</strong></div>' : '') +
            '<div class="summary-row"><span>Dirección</span><strong style="text-align:right;max-width:60%">' + esc(order.address) + '</strong></div>' +
            (order.note ? '<p class="tiny muted mt-16">Nota: ' + esc(order.note) + '</p>' : '') +
            '<a class="btn btn-dark btn-block mt-16" href="#/tienda/' + esc(order.storeSlug) + '">Ir al rincón de ' + esc(order.storeName) + '</a>' +
          '</div>' +
        '</div>' +
        '<div class="row mt-24" style="justify-content:center">' +
          '<button class="btn btn-ghost btn-sm" type="button" id="copyCode">Copiar código</button>' +
          '<a class="btn btn-turbo btn-sm" href="#/catalogo">Seguir mirando</a>' +
        '</div>' +
      '</div>'
    );

    const copy = document.getElementById('copyCode');
    if (copy) copy.addEventListener('click', function () {
      copyText(order.code).then(function () { UI.toast('Código copiado.', 'success'); });
    });
  }

  function trackingFormHtml(prefillCode) {
    return '<form id="trackingForm" class="summary-card" style="position:static;max-width:560px">' +
      '<div class="form-grid">' +
        '<label class="field full"><span>Código de pedido</span><input class="input" name="code" required value="' + esc(prefillCode || '') + '" placeholder="RT-XXXXXX" autocomplete="off" /></label>' +
        '<label class="field full"><span>Correo de la compra</span><input class="input" name="email" type="email" required value="' + esc(Api.lastEmail()) + '" placeholder="vos@correo.com" /></label>' +
      '</div>' +
      '<button class="btn btn-turbo btn-block mt-16" type="submit">Buscar pedido</button>' +
    '</form>';
  }

  function bindTrackingForm() {
    const form = document.getElementById('trackingForm');
    if (!form) return;
    form.addEventListener('submit', function (event) {
      event.preventDefault();
      if (!form.reportValidity()) return;
      const data = UI.formDataToObject(form);
      navigate('/pedido/' + encodeURIComponent(String(data.code).trim().toUpperCase()) + '?email=' + encodeURIComponent(String(data.email).trim()));
    });
  }

  async function viewTracking() {
    setView('<div class="container">' + pageHead('Seguí tu pedido', 'Poné el código y el correo con el que compraste. Te mostramos en qué anda.') +
      trackingFormHtml('') + '</div>');
    bindTrackingForm();
  }
  /* -------------------------------- cuenta --------------------------------- */

  function authCardHtml(mode, bare) {
    const isLogin = mode !== 'register';
    return '<div class="' + (bare ? '' : 'auth-card') + '">' +
      '<div class="tabs" role="tablist">' +
        '<button type="button" data-auth-mode="login" class="' + (isLogin ? 'is-active' : '') + '">Entrar</button>' +
        '<button type="button" data-auth-mode="register" class="' + (!isLogin ? 'is-active' : '') + '">Crear cuenta</button>' +
      '</div>' +
      '<form class="auth-form" data-mode="login"' + (isLogin ? '' : ' hidden') + '>' +
        '<label class="field"><span>Correo</span><input class="input" name="email" type="email" required autocomplete="email" placeholder="vos@correo.com" /></label>' +
        '<label class="field"><span>Contraseña</span><input class="input" name="password" type="password" required autocomplete="current-password" placeholder="Tu contraseña" /></label>' +
        '<p class="form-error" data-auth-error></p>' +
        '<button class="btn btn-turbo btn-block" type="submit">Entrar al rincón</button>' +
      '</form>' +
      '<form class="auth-form" data-mode="register"' + (!isLogin ? '' : ' hidden') + '>' +
        '<label class="field"><span>Tu nombre</span><input class="input" name="name" required minlength="2" autocomplete="name" placeholder="Cómo te llamás" /></label>' +
        '<label class="field"><span>Correo</span><input class="input" name="email" type="email" required autocomplete="email" placeholder="vos@correo.com" /></label>' +
        '<label class="field"><span>Contraseña</span><input class="input" name="password" type="password" required minlength="6" autocomplete="new-password" placeholder="Al menos 6 caracteres" /></label>' +
        '<p class="form-error" data-auth-error></p>' +
        '<button class="btn btn-turbo btn-block" type="submit">Crear mi cuenta</button>' +
      '</form>' +
      '<p class="tiny muted mt-16">Con tu cuenta abrís tiendas, cargás productos y seguís tus pedidos.</p>' +
    '</div>';
  }

  function bindAuth(root, onSuccess) {
    if (!root) return;
    const tabs = root.querySelectorAll('[data-auth-mode]');
    const forms = root.querySelectorAll('.auth-form');
    function show(mode) {
      tabs.forEach(function (tab) { tab.classList.toggle('is-active', tab.getAttribute('data-auth-mode') === mode); });
      forms.forEach(function (form) { form.hidden = form.getAttribute('data-mode') !== mode; });
      const first = root.querySelector('.auth-form[data-mode="' + mode + '"] input');
      if (first) first.focus();
    }
    tabs.forEach(function (tab) {
      tab.addEventListener('click', function () { show(tab.getAttribute('data-auth-mode')); });
    });
    forms.forEach(function (form) {
      form.addEventListener('submit', async function (event) {
        event.preventDefault();
        const button = form.querySelector('button[type="submit"]');
        const errorBox = form.querySelector('[data-auth-error]');
        if (errorBox) errorBox.textContent = '';
        if (!form.reportValidity()) return;
        button.disabled = true;
        const original = button.textContent;
        button.textContent = 'Un segundo…';
        try {
          const mode = form.getAttribute('data-mode');
          const payload = UI.formDataToObject(form);
          const data = mode === 'register'
            ? await Api.register({ name: payload.name, email: payload.email, password: payload.password })
            : await Api.login({ email: payload.email, password: payload.password });
          applySession(data.user, data.token);
          const firstName = String(data.user.name || '').split(' ')[0];
          UI.toast('Hola, ' + firstName + '. Ya estás adentro.', 'success');
          onSuccess(data.user);
        } catch (error) {
          if (errorBox) errorBox.textContent = error.message;
          UI.toast(error.message, 'error');
          button.disabled = false;
          button.textContent = original;
        }
      });
    });
  }

  function openAuthModal(mode) {
    return new Promise(function (resolve) {
      let done = false;
      const dialog = UI.modal('<div id="authModalBody">' + authCardHtml(mode || 'login', true) + '</div>', {
        title: 'Entrá al rincón',
        subtitle: 'Tu cuenta te deja abrir tiendas y seguir tus pedidos.',
        label: 'Cuenta'
      });
      bindAuth(document.getElementById('authModalBody'), function (user) {
        done = true;
        dialog.close();
        resolve(user);
      });
      const root = document.getElementById('modalRoot');
      const observer = new MutationObserver(function () {
        if (!done && !root.querySelector('.modal')) {
          observer.disconnect();
          resolve(null);
        }
      });
      observer.observe(root, { childList: true });
    });
  }

  async function viewAuth(params) {
    await getMeta().catch(function () {});
    if (state.user) {
      const initial = String(state.user.name || '?').trim().charAt(0).toUpperCase();
      setView('<div class="container">' + pageHead('Tu cuenta', 'Acá tenés todo lo tuyo: tus tiendas, tus compras y tus datos.') +
        '<div class="auth-card"><div class="account-head">' +
        '<div class="avatar">' + esc(initial) + '</div>' +
        '<div><h2>' + esc(state.user.name) + '</h2><p class="muted">' + esc(state.user.email) + '</p></div></div>' +
        '<div class="row mt-24"><a class="btn btn-turbo" href="#/panel">Ir a mi panel</a>' +
        '<a class="btn btn-ghost" href="#/vender">Abrir otra tienda</a></div>' +
        '<button class="btn btn-ghost mt-16" type="button" data-action="logout">Cerrar sesión</button></div></div>');
      return;
    }
    const next = params.get('next') || '/panel';
    const mode = params.get('mode') === 'register' ? 'register' : 'login';
    setView('<div class="container">' + pageHead('Entrá al rincón', 'Una cuenta, todos tus rincones y tus compras en un mismo lugar.') +
      '<div id="authPage">' + authCardHtml(mode) + '</div></div>');
    bindAuth(document.getElementById('authPage'), function () { navigate(next); });
  }

  /* -------------------------------- vender --------------------------------- */

  function sellPitchHtml() {
    return '<div class="sell-pitch">' +
      '<span class="eyebrow">Para vendedores</span>' +
      '<h2>Tu rincón, tus reglas.</h2>' +
      '<p>Abrí una tienda con el nombre que quieras, cargá lo que tengas y empezá a recibir pedidos. Sin comisiones por publicar y sin letra chica.</p>' +
      '<ul class="check-list">' +
        '<li>Tienda propia con link para compartir</li>' +
        '<li>Productos con foto o emoji, stock y precio</li>' +
        '<li>Pedidos y estados en un panel simple</li>' +
        '<li>Hasta 5 tiendas por cuenta</li>' +
      '</ul>' +
      '<div class="sell-note">El pago lo coordinás directo con quien compra. Acá solo se registra el pedido y se descuenta stock.</div>' +
    '</div>';
  }

  function sellInfoHtml() {
    return '<div class="steps" style="margin-top:34px">' +
      '<article class="step"><div class="num">$</div><h3>Publicar no cuesta</h3><p>Crear la tienda y subir productos es gratis. No te cobramos por estar en la vidriera.</p></article>' +
      '<article class="step"><div class="num">↔</div><h3>El envío lo arreglás vos</h3><p>Cada tienda define cómo entrega. El sitio sugiere $2.500 de envío y gratis desde $30.000.</p></article>' +
      '<article class="step"><div class="num">◎</div><h3>Todo queda registrado</h3><p>Cuando alguien compra, el pedido aparece en tu panel con los datos de entrega y el stock ya descontado.</p></article>' +
    '</div>';
  }
  async function viewSell() {
    const meta = await getMeta();
    if (!state.user) {
      setView('<div class="container">' + pageHead('Abrí tu rincón', 'Un nombre, un color y algo para vender. El resto se acomoda.') +
        '<div class="sell-layout">' + sellPitchHtml() + '<div id="sellAuth">' + authCardHtml('register') + '</div></div>' +
        sellInfoHtml() + '</div>');
      bindAuth(document.getElementById('sellAuth'), function () { viewSell(); });
      return;
    }

    let myStores = [];
    try {
      const data = await Api.stores({ owner: 'me', limit: 20 });
      myStores = data.stores || [];
    } catch (error) {}

    const limit = meta.limits ? meta.limits.storesPerOwner : 5;
    const categories = meta.categories || [];
    const accents = meta.accents || ACCENTS;
    const emojis = STORE_EMOJIS;

    const mineHtml = myStores.length
      ? '<div class="row" style="margin-bottom:18px"><span class="tiny muted">Tus rincones:</span>' + myStores.map(function (store) {
          return '<a class="chip" href="#/tienda/' + esc(store.slug) + '">' + esc(store.emoji) + ' ' + esc(store.name) + '</a>';
        }).join('') + '<a class="chip" href="#/panel">Ir al panel →</a></div>'
      : '';

    const formHtml = myStores.length >= limit
      ? '<div class="empty-state" style="padding:40px 24px"><span class="emoji">🏪</span><h3>Ya tenés ' + limit + ' rincones</h3><p>Es el máximo por cuenta. Podés administrar los que ya abriste desde el panel.</p><a class="btn btn-turbo" href="#/panel">Ir al panel</a></div>'
      : '<form id="storeForm" class="summary-card" style="position:static">' +
        '<h2>Abrí un rincón nuevo</h2>' +
        '<div class="form-grid">' +
          '<label class="field"><span>Nombre de la tienda</span><input class="input" name="name" required minlength="3" maxlength="60" placeholder="Ej. Bazar Nueve Vidas" /></label>' +
          '<label class="field"><span>Categoría</span><select name="category">' + categories.map(function (category) {
            return '<option value="' + esc(category) + '"' + (category === 'Tecnología' ? ' selected' : '') + '>' + esc(category) + '</option>';
          }).join('') + '</select></label>' +
          '<label class="field full"><span>Frase corta</span><input class="input" name="tagline" required minlength="6" maxlength="140" placeholder="Qué vendés y por qué vale la pena entrar" /></label>' +
          '<label class="field full"><span>Descripción</span><textarea class="textarea" name="description" maxlength="700" placeholder="Contá un poco más: de dónde sale lo que vendés, cómo trabajás, qué te gusta."></textarea></label>' +
          '<div class="field full"><span>Emoji de portada</span><div class="emoji-picker" id="emojiPicker">' + emojis.map(function (emoji, index) {
            return '<button type="button" data-emoji="' + emoji + '"' + (index === 0 ? ' class="is-active"' : '') + ' aria-label="Elegir ' + emoji + '">' + emoji + '</button>';
          }).join('') + '</div><input type="hidden" name="emoji" value="' + emojis[0] + '" /></div>' +
          '<div class="field full"><span>Color del rincón</span><div class="accent-picker" id="accentPicker">' + accents.map(function (accent, index) {
            return '<button type="button" data-accent="' + esc(accent) + '" style="background:' + esc(accent) + '"' + (index === 0 ? ' class="is-active"' : '') + ' aria-label="Elegir color"></button>';
          }).join('') + '</div><input type="hidden" name="accent" value="' + esc(accents[0]) + '" /></div>' +
        '</div>' +
        '<button class="btn btn-turbo btn-block mt-16" type="submit">Abrir mi tienda</button>' +
      '</form>';

    setView('<div class="container">' + pageHead('Abrí tu rincón', 'Un nombre, un color y algo para vender. El resto se acomoda.') +
      sellInfoHtml() + mineHtml +
      '<div class="form-layout mt-24">' + formHtml +
      '<aside class="preview-wrap"><p class="tiny muted">Así se va a ver</p>' +
      '<div class="store-card" id="storePreview" style="--accent:' + esc(accents[0]) + '">' +
        '<div class="store-top"><span class="store-emoji" id="prevEmoji">' + emojis[0] + '</span><div><div class="store-cat" id="prevCat">Tecnología</div><div class="store-name" id="prevName">Tu rincón</div></div></div>' +
        '<p class="store-tagline" id="prevTagline">La frase que te describe.</p>' +
        '<div class="store-foot"><span class="mini">0 productos</span><span class="mini">Nuevo</span></div>' +
      '</div><p class="tiny muted mt-16">El nombre se convierte en el link de tu tienda.</p></aside></div>' +
      '</div>');

    const form = document.getElementById('storeForm');
    if (!form) return;
    const preview = document.getElementById('storePreview');
    const prevName = document.getElementById('prevName');
    const prevTagline = document.getElementById('prevTagline');
    const prevCat = document.getElementById('prevCat');
    const prevEmoji = document.getElementById('prevEmoji');
    const nameInput = form.querySelector('[name="name"]');
    const taglineInput = form.querySelector('[name="tagline"]');
    const categorySelect = form.querySelector('[name="category"]');
    const emojiInput = form.querySelector('[name="emoji"]');
    const accentInput = form.querySelector('[name="accent"]');

    function paint() {
      if (prevName) prevName.textContent = nameInput.value.trim() || 'Tu rincón';
      if (prevTagline) prevTagline.textContent = taglineInput.value.trim() || 'La frase que te describe.';
      if (prevCat) prevCat.textContent = categorySelect.value;
      if (prevEmoji) prevEmoji.textContent = emojiInput.value;
      if (preview) preview.style.setProperty('--accent', accentInput.value);
    }
    [nameInput, taglineInput].forEach(function (input) { input.addEventListener('input', paint); });
    categorySelect.addEventListener('change', paint);

    document.getElementById('emojiPicker').addEventListener('click', function (event) {
      const button = event.target.closest('[data-emoji]');
      if (!button) return;
      emojiInput.value = button.getAttribute('data-emoji');
      document.querySelectorAll('#emojiPicker button').forEach(function (item) { item.classList.toggle('is-active', item === button); });
      paint();
    });
    document.getElementById('accentPicker').addEventListener('click', function (event) {
      const button = event.target.closest('[data-accent]');
      if (!button) return;
      accentInput.value = button.getAttribute('data-accent');
      document.querySelectorAll('#accentPicker button').forEach(function (item) { item.classList.toggle('is-active', item === button); });
      paint();
    });

    form.addEventListener('submit', async function (event) {
      event.preventDefault();
      if (!form.reportValidity()) return;
      const button = form.querySelector('button[type="submit"]');
      button.disabled = true;
      button.textContent = 'Abriendo el rincón…';
      try {
        const data = await Api.createStore(UI.formDataToObject(form));
        UI.toast('Tu rincón está abierto. Ahora cargá algo.', 'success');
        navigate('/tienda/' + data.store.slug);
      } catch (error) {
        UI.toast(error.message, 'error');
        button.disabled = false;
        button.textContent = 'Abrir mi tienda';
      }
    });
  }
  /* -------------------------------- panel ---------------------------------- */

  function panelHref(tab, storeId) {
    const params = new URLSearchParams();
    params.set('tab', tab);
    if (storeId) params.set('store', storeId);
    return '#/panel?' + params.toString();
  }

  function statCard(label, value, accent) {
    return '<div class="stat-card' + (accent ? ' accent' : '') + '"><span>' + label + '</span><strong>' + value + '</strong></div>';
  }

  function panelProductsHtml(products, stores) {
    if (!products.length) {
      return emptyBlock('📦', 'Todavía no hay productos', 'Sumá el primero y empezá a mostrarlo en tu vidriera.', '', '') +
        '<div class="row mt-16" style="justify-content:center"><button class="btn btn-turbo" type="button" data-action="new-product" data-store="' + (stores[0] ? stores[0].id : '') + '">Sumar producto</button></div>';
    }
    return '<div class="row mb-16"><span class="tiny muted">' + products.length + (products.length === 1 ? ' producto' : ' productos') + '</span>' +
      '<span class="spacer"></span><button class="btn btn-turbo btn-sm" type="button" data-action="new-product" data-store="' + (stores[0] ? stores[0].id : '') + '">+ Sumar producto</button></div>' +
      '<div class="admin-list">' + products.map(function (product) {
        const thumb = product.imageUrl
          ? '<img src="' + esc(product.imageUrl) + '" alt="" />'
          : esc(product.emoji);
        return '<div class="admin-row">' +
          '<a class="cart-thumb" href="#/producto/' + product.id + '" style="--glow:' + esc(product.storeAccent) + '">' + thumb + '</a>' +
          '<div class="admin-row-info"><b>' + esc(product.name) + (product.status === 'pausado' ? ' <span class="tiny muted">· pausado</span>' : '') + '</b>' +
          '<small>' + esc(product.storeName) + ' · ' + money(product.price) + ' · ' + product.stock + ' en stock</small></div>' +
          '<div class="admin-row-actions">' +
            '<button class="mini-icon" type="button" data-action="toggle-product" data-id="' + product.id + '" title="' + (product.status === 'activo' ? 'Pausar' : 'Activar') + '">' + icon(product.status === 'activo' ? 'eye' : 'pause', 15) + '</button>' +
            '<button class="mini-icon" type="button" data-action="edit-product" data-id="' + product.id + '" title="Editar">' + icon('edit', 15) + '</button>' +
            '<button class="mini-icon danger" type="button" data-action="delete-product" data-id="' + product.id + '" title="Eliminar">' + icon('trash', 15) + '</button>' +
          '</div></div>';
      }).join('') + '</div>';
  }

  async function viewPanel(params) {
    await getMeta().catch(function () {});
    const user = await ensureUser();
    if (!user) {
      setView('<div class="container">' + pageHead('Tu panel', 'Entrá para ver tus tiendas, tus productos y los pedidos.') +
        '<div id="panelAuth">' + authCardHtml('login') + '</div></div>');
      bindAuth(document.getElementById('panelAuth'), function () { viewPanel(params); });
      return;
    }

    const tab = params.get('tab') === 'pedidos' ? 'pedidos' : (params.get('tab') === 'compras' ? 'compras' : 'productos');
    const storeFilter = Number(params.get('store') || 0);
    setView('<div class="container">' + pageHead('Tu panel', 'Tus rincones, tus productos y los pedidos que van entrando.') +
      '<div class="dash-top" id="panelStats">' + UI.skeletonGrid(5).replace('loading-block', 'loading-block') + '</div>' +
      '<div id="panelBody">' + UI.skeletonGrid(4) + '</div></div>');

    try {
      const [summary, sellerOrders, purchases, sellerProducts] = await Promise.all([
        Api.sellerSummary(),
        Api.sellerOrders(),
        Api.myOrders().catch(function () { return { orders: [] }; }),
        Api.sellerProducts(storeFilter || undefined)
      ]);
      const stores = summary.stores || [];
      const totals = summary.totals || {};
      const products = sellerProducts.products || [];
      const orders = sellerOrders.orders || [];
      const myOrders = purchases.orders || [];
      state.sellerStores = stores;
      state.sellerProducts = products;

      const visibleOrders = storeFilter ? orders.filter(function (order) { return Number(order.storeId) === storeFilter; }) : orders;
      const firstName = String(user.name || '').split(' ')[0];

      const statsHtml = statCard('Tiendas', totals.stores || 0) +
        statCard('Productos', totals.products || 0) +
        statCard('Pedidos', totals.orders || 0) +
        statCard('Pendientes', totals.pending || 0) +
        statCard('Facturado', money(totals.revenue || 0), true);

      const storeSwitch = stores.length ? '<div class="store-switch">' +
        '<a class="chip' + (!storeFilter ? ' is-active' : '') + '" href="' + panelHref(tab, 0) + '">Todos los rincones</a>' +
        stores.map(function (store) {
          return '<a class="chip' + (storeFilter === Number(store.id) ? ' is-active' : '') + '" href="' + panelHref(tab, store.id) + '">' + esc(store.emoji) + ' ' + esc(store.name) + '</a>';
        }).join('') + '<button class="chip" type="button" data-action="new-store">+ Nueva tienda</button></div>' : '';

      let bodyHtml = '';
      if (!stores.length) {
        bodyHtml = emptyBlock('🏪', 'Todavía no abriste un rincón', 'Creá tu primera tienda y en un par de minutos ya podés cargar productos.', '#/vender', 'Abrir mi tienda');
      } else if (tab === 'productos') {
        bodyHtml = panelProductsHtml(products, stores);
      } else if (tab === 'pedidos') {
        bodyHtml = visibleOrders.length
          ? visibleOrders.map(function (order) { return UI.orderCard(order, { editable: true }); }).join('')
          : emptyBlock('🧾', 'No hay pedidos por acá', 'Cuando alguien compre en tus rincones, el pedido aparece en esta lista.', '', '');
      } else {
        bodyHtml = myOrders.length
          ? myOrders.map(function (order) { return UI.orderCard(order, {}); }).join('')
          : emptyBlock('🛍️', 'Todavía no compraste nada', 'Cuando lo hagas, todos tus pedidos quedan acá con su estado.', '#/catalogo', 'Ver catálogo');
      }

      const body = '<div class="row mb-24" style="justify-content:space-between">' +
        '<p class="muted" style="font-size:14px">Hola de nuevo, ' + esc(firstName) + '.</p>' +
        '<div class="row"><button class="btn btn-ghost btn-sm" type="button" data-action="new-store">Nueva tienda</button>' +
        '<button class="btn btn-turbo btn-sm" type="button" data-action="new-product" data-store="' + (storeFilter || (stores[0] ? stores[0].id : '')) + '">Nuevo producto</button></div></div>' +
        '<div class="dash-tabs">' +
        '<a class="' + (tab === 'productos' ? 'is-active' : '') + '" href="' + panelHref('productos', storeFilter) + '">Productos</a>' +
        '<a class="' + (tab === 'pedidos' ? 'is-active' : '') + '" href="' + panelHref('pedidos', storeFilter) + '">Pedidos <span class="tiny muted">' + orders.length + '</span></a>' +
        '<a class="' + (tab === 'compras' ? 'is-active' : '') + '" href="' + panelHref('compras', 0) + '">Mis compras</a>' +
        '</div>' + storeSwitch + bodyHtml;

      const stats = document.getElementById('panelStats');
      if (stats) stats.innerHTML = statsHtml;
      const container = document.getElementById('panelBody');
      if (container) {
        container.innerHTML = body;
        container.querySelectorAll('.dash-tabs a').forEach(function (link) {
          link.addEventListener('click', function () {});
        });
      }
    } catch (error) {
      const container = document.getElementById('panelBody');
      if (container) container.innerHTML = errorBlock(error);
    }
  }
  /* ------------------------------- modales --------------------------------- */

  const PRODUCT_EMOJIS = ['📦', '🎧', '👟', '🪑', '🕯️', '🎸', '📚', '🪴', '🧸', '🃏', '🍫', '☕', '💻', '🛹', '🎨', '🧵', '📷', '🪐', '⌚', '🍊', '💡', '🔌', '🛋️', '🐈'];

  function pickerHtml(items, hiddenName, current, type) {
    const value = current || items[0];
    if (type === 'accent') {
      return '<div class="accent-picker" data-picker="accent">' + items.map(function (item) {
        return '<button type="button" data-value="' + esc(item) + '" style="background:' + esc(item) + '"' + (item === value ? ' class="is-active"' : '') + ' aria-label="Color ' + esc(item) + '"></button>';
      }).join('') + '</div><input type="hidden" name="' + hiddenName + '" value="' + esc(value) + '" />';
    }
    return '<div class="emoji-picker" data-picker="emoji">' + items.map(function (item) {
      return '<button type="button" data-value="' + esc(item) + '"' + (item === value ? ' class="is-active"' : '') + '>' + esc(item) + '</button>';
    }).join('') + '</div><input type="hidden" name="' + hiddenName + '" value="' + esc(value) + '" />';
  }

  function bindPicker(root) {
    root.querySelectorAll('[data-picker]').forEach(function (picker) {
      const hidden = picker.parentElement.querySelector('input[type="hidden"]');
      picker.addEventListener('click', function (event) {
        const button = event.target.closest('[data-value]');
        if (!button) return;
        if (hidden) hidden.value = button.getAttribute('data-value');
        picker.querySelectorAll('[data-value]').forEach(function (item) { item.classList.toggle('is-active', item === button); });
      });
    });
  }

  function storeFormHtml(store, meta) {
    const categories = meta.categories || [];
    const accents = meta.accents || ACCENTS;
    const emojis = STORE_EMOJIS;
    return '<form id="storeModalForm">' +
      '<div class="form-grid">' +
        '<label class="field"><span>Nombre</span><input class="input" name="name" required minlength="3" maxlength="60" value="' + esc(store ? store.name : '') + '" placeholder="Ej. Bazar Nueve Vidas" /></label>' +
        '<label class="field"><span>Categoría</span><select name="category">' + categories.map(function (category) {
          return '<option value="' + esc(category) + '"' + ((store ? store.category : 'Otros') === category ? ' selected' : '') + '>' + esc(category) + '</option>';
        }).join('') + '</select></label>' +
        '<label class="field full"><span>Frase corta</span><input class="input" name="tagline" required minlength="6" maxlength="140" value="' + esc(store ? store.tagline : '') + '" placeholder="Qué vendés y por qué vale la pena entrar" /></label>' +
        '<label class="field full"><span>Descripción</span><textarea class="textarea" name="description" maxlength="700" placeholder="De dónde sale lo que vendés, cómo trabajás…">' + esc(store ? store.description : '') + '</textarea></label>' +
        '<div class="field full"><span>Emoji</span>' + pickerHtml(emojis, 'emoji', store ? store.emoji : emojis[0], 'emoji') + '</div>' +
        '<div class="field full"><span>Color</span>' + pickerHtml(accents, 'accent', store ? store.accent : accents[0], 'accent') + '</div>' +
      '</div>' +
      '<div class="modal-foot"><button class="btn btn-ghost" type="button" data-modal-close>Cancelar</button>' +
      '<button class="btn btn-turbo" type="submit">' + (store ? 'Guardar cambios' : 'Abrir tienda') + '</button></div>' +
    '</form>';
  }

  async function openStoreModal(store) {
    const meta = await getMeta();
    const dialog = UI.modal(storeFormHtml(store || null, meta), {
      title: store ? 'Editar ' + store.name : 'Abrir un rincón',
      subtitle: store ? 'Cambiá lo que quieras: el link se mantiene.' : 'Después podés ajustar todo desde el panel.',
      label: store ? 'Editar tienda' : 'Nueva tienda'
    });
    const form = document.getElementById('storeModalForm');
    if (!form) return;
    bindPicker(form);
    form.addEventListener('submit', async function (event) {
      event.preventDefault();
      if (!form.reportValidity()) return;
      const button = form.querySelector('button[type="submit"]');
      button.disabled = true;
      button.textContent = 'Guardando…';
      try {
        const payload = UI.formDataToObject(form);
        if (store) {
          await Api.updateStore(store.id, payload);
          dialog.close();
          UI.toast('Tienda actualizada.', 'success');
          renderRoute();
        } else {
          const data = await Api.createStore(payload);
          dialog.close();
          UI.toast('Tu rincón está abierto.', 'success');
          navigate('/tienda/' + data.store.slug);
        }
      } catch (error) {
        UI.toast(error.message, 'error');
        button.disabled = false;
        button.textContent = store ? 'Guardar cambios' : 'Abrir tienda';
      }
    });
  }

  function productFormHtml(store, product, meta) {
    const categories = meta.categories || [];
    return '<form id="productModalForm">' +
      '<p class="tiny muted mb-16">En ' + esc(store.name) + '</p>' +
      '<div class="form-grid">' +
        '<label class="field full"><span>Nombre del producto</span><input class="input" name="name" required minlength="2" maxlength="100" value="' + esc(product ? product.name : '') + '" placeholder="Ej. Lámpara de escritorio" /></label>' +
        '<label class="field"><span>Precio</span><input class="input" name="price" type="number" min="1" step="0.01" required value="' + (product ? product.price : '') + '" placeholder="0" /></label>' +
        '<label class="field"><span>Stock</span><input class="input" name="stock" type="number" min="0" max="9999" step="1" required value="' + (product ? product.stock : 1) + '" /></label>' +
        '<label class="field"><span>Categoría</span><select name="category">' + categories.map(function (category) {
          return '<option value="' + esc(category) + '"' + ((product ? product.category : 'Otros') === category ? ' selected' : '') + '>' + esc(category) + '</option>';
        }).join('') + '</select></label>' +
        (product ? '<label class="field"><span>Estado</span><select name="status"><option value="activo"' + (product.status === 'activo' ? ' selected' : '') + '>Activo</option><option value="pausado"' + (product.status === 'pausado' ? ' selected' : '') + '>Pausado</option></select></label>' : '') +
        '<label class="field full"><span>Descripción</span><textarea class="textarea" name="description" maxlength="900" placeholder="Detalles, medidas, estado, lo que sea útil.">' + esc(product ? product.description : '') + '</textarea></label>' +
        '<div class="field full"><span>Emoji (si no subís foto)</span>' + pickerHtml(PRODUCT_EMOJIS, 'emoji', product ? product.emoji : '📦', 'emoji') + '</div>' +
        '<label class="field full"><span>Link de imagen (opcional)</span><input class="input" name="imageUrl" type="url" value="' + esc(product ? product.imageUrl : '') + '" placeholder="https://…" /></label>' +
        (product ? '' : '<label class="file-drop"><input type="file" name="images" accept="image/*" /><span>' + icon('upload', 16) + ' Subir una foto (opcional, hasta 3)</span></label>') +
      '</div>' +
      '<div class="modal-foot"><button class="btn btn-ghost" type="button" data-modal-close>Cancelar</button>' +
      '<button class="btn btn-turbo" type="submit">' + (product ? 'Guardar cambios' : 'Sumar producto') + '</button></div>' +
    '</form>';
  }

  async function openProductModal(store, product) {
    if (!store) {
      UI.toast('Primero abrí una tienda.', 'error');
      return;
    }
    const meta = await getMeta();
    const dialog = UI.modal(productFormHtml(store, product || null, meta), {
      title: product ? 'Editar producto' : 'Sumar producto',
      subtitle: 'Lo que cargues aparece en tu vidriera al instante.',
      label: product ? 'Editar producto' : 'Nuevo producto'
    });
    const form = document.getElementById('productModalForm');
    if (!form) return;
    bindPicker(form);
    const file = form.querySelector('input[type="file"]');
    if (file) {
      file.addEventListener('change', function () {
        const label = file.parentElement.querySelector('span');
        if (label && file.files.length) label.textContent = file.files[0].name;
      });
    }
    form.addEventListener('submit', async function (event) {
      event.preventDefault();
      if (!form.reportValidity()) return;
      const button = form.querySelector('button[type="submit"]');
      button.disabled = true;
      button.textContent = 'Guardando…';
      try {
        if (product) {
          await Api.updateProduct(product.id, UI.formDataToObject(form));
        } else {
          await Api.createProduct(new FormData(form));
        }
        dialog.close();
        UI.toast(product ? 'Producto actualizado.' : 'Producto sumado a la vidriera.', 'success');
        renderRoute();
      } catch (error) {
        UI.toast(error.message, 'error');
        button.disabled = false;
        button.textContent = product ? 'Guardar cambios' : 'Sumar producto';
      }
    });
  }
  /* -------------------------------- router --------------------------------- */

  function copyText(value) {
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(value);
    return new Promise(function (resolve) {
      const area = document.createElement('textarea');
      area.value = value;
      area.style.position = 'fixed';
      area.style.opacity = '0';
      document.body.appendChild(area);
      area.select();
      try { document.execCommand('copy'); } catch (error) {}
      area.remove();
      resolve();
    });
  }

  function navigate(path) {
    const next = '#' + (path.charAt(0) === '/' ? path : '/' + path);
    if (window.location.hash === next) { renderRoute(); return; }
    window.location.hash = next;
  }

  function setActiveNav(nav) {
    document.querySelectorAll('[data-nav]').forEach(function (link) {
      link.classList.toggle('is-active', link.getAttribute('data-nav') === nav);
    });
  }

  function closeNav() {
    const head = document.getElementById('siteHead');
    const button = document.getElementById('menuBtn');
    if (head) head.classList.remove('nav-open');
    if (button) button.setAttribute('aria-expanded', 'false');
  }

  const ROUTES = [
    { re: /^\/$/, view: viewHome, nav: 'inicio' },
    { re: /^\/catalogo$/, view: viewCatalog, nav: 'catalogo' },
    { re: /^\/tiendas$/, view: viewStores, nav: 'tiendas' },
    { re: /^\/tienda\/([^/]+)$/, view: viewStore, nav: 'tiendas' },
    { re: /^\/producto\/(\d+)$/, view: viewProduct, nav: 'catalogo' },
    { re: /^\/carrito$/, view: viewCart, nav: 'carrito' },
    { re: /^\/pedido\/([^/]+)$/, view: viewOrder, nav: 'carrito' },
    { re: /^\/seguimiento$/, view: viewTracking, nav: 'carrito' },
    { re: /^\/vender$/, view: viewSell, nav: 'vender' },
    { re: /^\/panel$/, view: viewPanel, nav: 'panel' },
    { re: /^\/entrar$/, view: viewAuth, nav: 'panel' }
  ];

  function notFoundView() {
    setView('<div class="container">' + pageHead('Te perdiste en el rincón', 'Esta dirección no existe o el producto ya no está colgado.') +
      emptyBlock('🧭', 'No hay nada acá', 'Volvé al inicio o mirá el catálogo completo. Siempre hay algo dando vueltas.', '#/catalogo', 'Ir al catálogo') + '</div>');
  }

  async function renderRoute() {
    closeNav();
    const seq = ++state.renderSeq;
    const parsed = queryFromHash();
    const path = (parsed.path.replace(/\/+$/, '') || '/');
    let match = null;
    for (const route of ROUTES) {
      const found = path.match(route.re);
      if (found) { match = { route: route, parts: found }; break; }
    }
    if (!match) { notFoundView(); return; }
    setActiveNav(match.route.nav);
    window.scrollTo(0, 0);
    try {
      await match.route.view(parsed.params, match.parts[1]);
      if (seq !== state.renderSeq) return;
    } catch (error) {
      if (seq !== state.renderSeq) return;
      setView('<div class="container">' + errorBlock(error) + '</div>');
    }
  }

  /* --------------------------- acciones globales --------------------------- */

  function findStore(id) {
    const stores = state.sellerStores || [];
    const found = stores.find(function (store) { return Number(store.id) === Number(id); });
    if (found) return found;
    if (state.currentStore && Number(state.currentStore.id) === Number(id)) return state.currentStore;
    return null;
  }

  document.addEventListener('click', function (event) {
    const trigger = event.target.closest('[data-action]');
    if (!trigger) return;
    const action = trigger.getAttribute('data-action');
    const id = Number(trigger.getAttribute('data-id') || 0);

    if (action === 'add') {
      const product = state.productIndex[id];
      if (product) addToCart(product, 1);
      return;
    }

    if (action === 'cart-plus' || action === 'cart-minus' || action === 'cart-remove') {
      const item = state.cart.find(function (entry) { return entry.id === id; });
      if (!item) return;
      if (action === 'cart-remove') removeFromCart(id);
      else setCartQty(id, item.qty + (action === 'cart-plus' ? 1 : -1));
      if (queryFromHash().path.indexOf('/carrito') === 0) renderRoute();
      return;
    }

    if (action === 'logout') { logout(); return; }
    if (action === 'retry') { renderRoute(); return; }
    if (action === 'new-store') { openStoreModal(); return; }

    if (action === 'edit-store') {
      const store = findStore(id);
      if (store) openStoreModal(store);
      else UI.toast('No encontramos esa tienda. Recargá el panel.', 'error');
      return;
    }

    if (action === 'new-product') {
      const storeId = Number(trigger.getAttribute('data-store') || 0);
      const store = findStore(storeId) || (state.sellerStores || [])[0];
      openProductModal(store);
      return;
    }

    if (action === 'edit-product') {
      const product = (state.sellerProducts || []).find(function (item) { return Number(item.id) === id; });
      if (!product) return;
      const store = findStore(product.storeId);
      openProductModal(store, product);
      return;
    }

    if (action === 'toggle-product') {
      const product = (state.sellerProducts || []).find(function (item) { return Number(item.id) === id; });
      if (!product) return;
      const nextStatus = product.status === 'activo' ? 'pausado' : 'activo';
      trigger.disabled = true;
      Api.updateProduct(id, { status: nextStatus }).then(function () {
        UI.toast(nextStatus === 'activo' ? 'Producto activo de nuevo.' : 'Producto pausado.', 'success');
        renderRoute();
      }).catch(function (error) {
        trigger.disabled = false;
        UI.toast(error.message, 'error');
      });
      return;
    }

    if (action === 'delete-product') {
      const product = (state.sellerProducts || []).find(function (item) { return Number(item.id) === id; });
      if (!product) return;
      UI.confirm({
        title: 'Eliminar producto',
        text: 'Se va a borrar "' + product.name + '" de tu vidriera. No se puede deshacer.',
        confirmLabel: 'Eliminar',
        danger: true
      }).then(function (ok) {
        if (!ok) return;
        Api.deleteProduct(id).then(function () {
          UI.toast('Producto eliminado.', 'success');
          renderRoute();
        }).catch(function (error) { UI.toast(error.message, 'error'); });
      });
    }
  });

  document.addEventListener('change', function (event) {
    const select = event.target.closest('[data-action="order-status"]');
    if (!select) return;
    const id = Number(select.getAttribute('data-id'));
    const status = select.value;
    select.disabled = true;
    Api.updateOrderStatus(id, status).then(function () {
      UI.toast('Pedido marcado como ' + status + '.', 'success');
      renderRoute();
    }).catch(function (error) {
      select.disabled = false;
      UI.toast(error.message, 'error');
    });
  });

  /* --------------------------------- init ---------------------------------- */

  async function refreshStatus() {
    const dot = document.getElementById('apiDot');
    const label = document.getElementById('apiStatus');
    if (!dot || !label) return;
    try {
      await Api.health();
      dot.className = 'dot ok';
      label.textContent = 'Servidor en línea';
    } catch (error) {
      dot.className = 'dot bad';
      label.textContent = 'Sin conexión con el servidor';
    }
  }

  function init() {
    updateCartBadge();
    updateAccount();

    const ticker = document.getElementById('tickerTrack');
    if (ticker) ticker.innerHTML = ticker.innerHTML + ticker.innerHTML;
    const year = document.getElementById('footYear');
    if (year) year.textContent = String(new Date().getFullYear());

    const menuBtn = document.getElementById('menuBtn');
    const head = document.getElementById('siteHead');
    if (menuBtn && head) {
      menuBtn.addEventListener('click', function () {
        const open = head.classList.toggle('nav-open');
        menuBtn.setAttribute('aria-expanded', String(open));
      });
    }

    const headSearch = document.getElementById('headSearch');
    if (headSearch) {
      headSearch.addEventListener('submit', function (event) {
        event.preventDefault();
        const input = headSearch.querySelector('input');
        const value = input.value.trim();
        navigate('/catalogo' + (value ? '?q=' + encodeURIComponent(value) : ''));
        input.blur();
      });
    }

    document.addEventListener('click', function (event) {
      if (head && !head.contains(event.target)) closeNav();
      if (event.target.closest('#headNav a')) closeNav();
    });

    window.addEventListener('hashchange', renderRoute);
    renderRoute();
    refreshStatus();
    getMeta().catch(function () {});
    ensureUser();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
