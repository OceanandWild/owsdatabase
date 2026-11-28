/* ==========================================================================
   RINCÓN TURBOPODER — utilidades de interfaz
   ========================================================================== */

(function () {
  'use strict';

  const ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

  function escapeHtml(value) {
    return String(value == null ? '' : value).replace(/[&<>"']/g, function (ch) { return ESCAPES[ch]; });
  }

  const moneyFormat = new Intl.NumberFormat('es-AR', { minimumFractionDigits: 0, maximumFractionDigits: 2 });

  function money(value) {
    const n = Number(value);
    if (!Number.isFinite(n)) return '$ 0';
    return '$ ' + moneyFormat.format(n);
  }

  function dateShort(value) {
    if (!value) return '';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '';
    return date.toLocaleDateString('es-AR', { day: '2-digit', month: 'short' });
  }

  function dateLong(value) {
    if (!value) return '';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '';
    return date.toLocaleDateString('es-AR', { day: '2-digit', month: 'long', year: 'numeric' });
  }

  function ratingLabel(rating, count) {
    if (!count) return '<span class="rating">Nuevo</span>';
    return '<span class="rating"><span class="star">★</span><b>' + Number(rating).toFixed(1) + '</b> · ' + count + '</span>';
  }
  const ICONS = {
    search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
    cart: '<path d="M4 4h2l2.4 11.2A2 2 0 0 0 10.3 17H19a2 2 0 0 0 2-1.6L22.5 8H6"/><circle cx="10" cy="20" r="1.4"/><circle cx="18" cy="20" r="1.4"/>',
    arrowLeft: '<path d="M19 12H5"/><path d="m11 18-6-6 6-6"/>',
    arrowRight: '<path d="M5 12h14"/><path d="m13 6 6 6-6 6"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    minus: '<path d="M5 12h14"/>',
    trash: '<path d="M4 7h16"/><path d="M9 7V5h6v2"/><path d="M6 7l1 13h10l1-13"/>',
    edit: '<path d="M4 20h4L20 8l-4-4L4 16v4Z"/><path d="m14 6 4 4"/>',
    check: '<path d="m4 12 5 5L20 6"/>',
    close: '<path d="M6 6l12 12M18 6 6 18"/>',
    store: '<path d="M4 10h16"/><path d="M5 10V6h14v4"/><path d="M6 10v10h12V10"/><path d="M10 20v-5h4v5"/>',
    package: '<path d="m12 3 8 4.5v9L12 21l-8-4.5v-9L12 3Z"/><path d="M4 7.5 12 12l8-4.5"/>',
    spark: '<path d="M12 3v5M12 16v5M3 12h5M16 12h5"/>',
    upload: '<path d="M12 16V4"/><path d="m7 9 5-5 5 5"/><path d="M4 20h16"/>',
    external: '<path d="M14 4h6v6"/><path d="m20 4-9 9"/><path d="M18 14v6H4V6h6"/>',
    eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>',
    pause: '<path d="M9 5v14M15 5v14"/>',
    tag: '<path d="M4 4h8l8 8-8 8-8-8V4Z"/><circle cx="8.5" cy="8.5" r="1.4"/>',
    user: '<circle cx="12" cy="8" r="3.6"/><path d="M4.5 20c1.4-4 4.1-6 7.5-6s6.1 2 7.5 6"/>'
  };

  function icon(name, size) {
    const path = ICONS[name] || '';
    const px = size || 18;
    return '<svg viewBox="0 0 24 24" width="' + px + '" height="' + px + '" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + path + '</svg>';
  }

  function toast(message, variant) {
    const stack = document.getElementById('toastStack');
    if (!stack) return;
    const node = document.createElement('div');
    node.className = 'toast' + (variant ? ' ' + variant : '');
    node.innerHTML = '<span>' + escapeHtml(message) + '</span>';
    stack.appendChild(node);
    while (stack.children.length > 3) stack.removeChild(stack.firstElementChild);
    setTimeout(function () {
      node.classList.add('leaving');
      setTimeout(function () { node.remove(); }, 220);
    }, 3800);
  }

  let activeModal = null;

  function closeModal() {
    const root = document.getElementById('modalRoot');
    if (root) root.innerHTML = '';
    document.body.style.overflow = '';
    activeModal = null;
  }
  function modal(innerHtml, options) {
    const settings = options || {};
    const root = document.getElementById('modalRoot');
    if (!root) return { close: function () {} };
    closeModal();
    const title = escapeHtml(settings.title || '');
    const subtitle = settings.subtitle ? '<p>' + escapeHtml(settings.subtitle) + '</p>' : '';
    const label = escapeHtml(settings.label || 'Ventana');
    root.innerHTML =
      '<div class="modal-backdrop" data-modal-backdrop>' +
        '<div class="modal" role="dialog" aria-modal="true" aria-label="' + label + '">' +
          '<div class="modal-head">' +
            '<div><h2>' + title + '</h2>' + subtitle + '</div>' +
            '<button class="modal-close" type="button" data-modal-close aria-label="Cerrar">' + icon('close', 16) + '</button>' +
          '</div>' +
          innerHtml +
        '</div>' +
      '</div>';
    document.body.style.overflow = 'hidden';
    activeModal = root.firstElementChild;
    root.querySelectorAll('[data-modal-close]').forEach(function (btn) {
      btn.addEventListener('click', closeModal);
    });
    if (activeModal) {
      activeModal.addEventListener('click', function (event) {
        if (event.target === activeModal && settings.dismissible !== false) closeModal();
      });
      const focusable = activeModal.querySelector('input, textarea, select') || activeModal.querySelector('button');
      if (focusable) setTimeout(function () { focusable.focus(); }, 40);
    }
    return { close: closeModal, element: activeModal };
  }

  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape' && activeModal) closeModal();
  });

  function confirmDialog(options) {
    const settings = options || {};
    return new Promise(function (resolve) {
      const btnClass = settings.danger ? 'btn-pink' : 'btn-turbo';
      const label = escapeHtml(settings.confirmLabel || 'Confirmar');
      const body =
        '<p class="muted" style="font-size:14px">' + escapeHtml(settings.text || '') + '</p>' +
        '<div class="modal-foot">' +
          '<button class="btn btn-ghost" type="button" data-modal-close>Cancelar</button>' +
          '<button class="btn ' + btnClass + '" type="button" data-confirm>' + label + '</button>' +
        '</div>';
      const dialog = modal(body, { title: settings.title || '¿Seguro?', label: 'Confirmar' });
      const confirmBtn = document.querySelector('[data-confirm]');
      if (confirmBtn) {
        confirmBtn.addEventListener('click', function () {
          dialog.close();
          resolve(true);
        });
      }
      const backdrop = document.getElementById('modalRoot');
      if (backdrop) {
        backdrop.addEventListener('click', function (event) {
          if (event.target.closest('[data-modal-close]')) resolve(false);
        });
      }
    });
  }

  function skeletonGrid(count) {
    let html = '<div class="loading-block">';
    for (let i = 0; i < (count || 8); i += 1) html += '<div class="skeleton"></div>';
    return html + '</div>';
  }

  function debounce(fn, wait) {
    let timer = null;
    return function () {
      const args = arguments;
      clearTimeout(timer);
      timer = setTimeout(function () { fn.apply(null, args); }, wait || 250);
    };
  }

  function truncate(value, max) {
    const str = String(value || '');
    return str.length > max ? str.slice(0, max - 1).trimEnd() + '…' : str;
  }
  function productTile(product, options) {
    const opts = options || {};
    const out = Number(product.stock) <= 0;
    const flag = out
      ? '<span class="product-flag out">Agotado</span>'
      : (Number(product.stock) <= 3 ? '<span class="product-flag low">Quedan ' + product.stock + '</span>' : '');
    const media = product.imageUrl
      ? '<img src="' + escapeHtml(product.imageUrl) + '" alt="' + escapeHtml(product.name) + '" loading="lazy" />'
      : '<span class="tile-emoji" aria-hidden="true">' + escapeHtml(product.emoji || '📦') + '</span>';
    const rating = product.reviewCount ? ratingLabel(product.rating, product.reviewCount) : '';
    const addButton = opts.hideAdd ? '' :
      '<button class="add-btn" type="button" data-action="add" data-id="' + product.id + '"' + (out ? ' disabled' : '') + '>' +
      icon('plus', 14) + 'Agregar</button>';
    return (
      '<article class="product-card">' +
        '<a class="product-media" href="#/producto/' + product.id + '" style="--glow:' + escapeHtml(product.storeAccent || '#d9ff3c') + '">' +
          flag + media +
        '</a>' +
        '<div class="product-body">' +
          '<a class="product-store" href="#/tienda/' + escapeHtml(product.storeSlug) + '">' +
            '<span aria-hidden="true">' + escapeHtml(product.storeEmoji || '🧰') + '</span>' +
            escapeHtml(product.storeName) +
          '</a>' +
          '<h3 class="product-title"><a href="#/producto/' + product.id + '">' + escapeHtml(product.name) + '</a></h3>' +
          rating +
          '<div class="product-foot">' +
            '<span class="price">' + money(product.price) + '</span>' +
            addButton +
          '</div>' +
        '</div>' +
      '</article>'
    );
  }

  function storeCard(store) {
    return (
      '<a class="store-card" href="#/tienda/' + escapeHtml(store.slug) + '" style="--accent:' + escapeHtml(store.accent) + '">' +
        '<div class="store-top">' +
          '<span class="store-emoji" aria-hidden="true">' + escapeHtml(store.emoji) + '</span>' +
          '<div><div class="store-cat">' + escapeHtml(store.category) + '</div>' +
          '<div class="store-name">' + escapeHtml(store.name) + '</div></div>' +
        '</div>' +
        '<p class="store-tagline">' + escapeHtml(truncate(store.tagline || store.description || '', 96)) + '</p>' +
        '<div class="store-foot">' +
          '<span class="mini">' + icon('package', 14) + (store.productCount || 0) + ' productos</span>' +
          '<span class="mini">' + ratingLabel(store.rating, store.reviewCount) + '</span>' +
        '</div>' +
      '</a>'
    );
  }
  function orderCard(order, options) {
    const opts = options || {};
    const items = (order.items || []).map(function (item) {
      return '<span>' + item.qty + ' × ' + escapeHtml(item.name) + ' <span class="muted">· ' + money(Number(item.price) * Number(item.qty)) + '</span></span>';
    }).join('');
    const statuses = ['pendiente', 'confirmado', 'enviado', 'entregado', 'cancelado'];
    const selector = opts.editable
      ? '<select class="status-select" data-action="order-status" data-id="' + order.id + '">' +
        statuses.map(function (status) {
          return '<option value="' + status + '"' + (order.status === status ? ' selected' : '') + '>' + status.charAt(0).toUpperCase() + status.slice(1) + '</option>';
        }).join('') +
        '</select>'
      : '<span class="status-pill ' + escapeHtml(order.status) + '">' + escapeHtml(order.status) + '</span>';

    return (
      '<div class="order-card">' +
        '<div class="order-top">' +
          '<div>' +
            '<div class="order-code">' + escapeHtml(order.code) + '</div>' +
            '<div class="tiny muted">' + escapeHtml(order.storeName) + ' · ' + dateShort(order.createdAt) + '</div>' +
          '</div>' +
          selector +
        '</div>' +
        '<div class="order-items">' + items + '</div>' +
        '<div class="order-bottom">' +
          '<span class="tiny muted">' + escapeHtml(order.buyerName) + ' · ' + escapeHtml(order.buyerEmail) + '</span>' +
          '<strong>' + money(order.total) + '</strong>' +
        '</div>' +
      '</div>'
    );
  }

  function formDataToObject(form) {
    const data = {};
    const fd = new FormData(form);
    fd.forEach(function (value, key) {
      if (typeof File !== 'undefined' && value instanceof File) return;
      data[key] = value;
    });
    return data;
  }

  window.TPUI = {
    escapeHtml: escapeHtml,
    money: money,
    dateShort: dateShort,
    dateLong: dateLong,
    ratingLabel: ratingLabel,
    icon: icon,
    toast: toast,
    modal: modal,
    closeModal: closeModal,
    confirm: confirmDialog,
    skeletonGrid: skeletonGrid,
    debounce: debounce,
    truncate: truncate,
    productTile: productTile,
    storeCard: storeCard,
    orderCard: orderCard,
    formDataToObject: formDataToObject
  };
})();
