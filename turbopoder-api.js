/* ============================================================================
 * RINCÓN TURBOPODER — API multitienda (Océano & Wild Studios)
 * ----------------------------------------------------------------------------
 * Mercado donde cualquiera abre su tienda y vende cualquier cosa. Se monta
 * desde server.js con una sola llamada a registerTurboPoder(app, deps).
 *
 *   /turbopoder/register  /login  /me          sesión de vendedores
 *   /turbopoder/stores    GET / POST / PATCH    tiendas
 *   /turbopoder/products  GET / POST / PATCH    catálogo
 *   /turbopoder/orders    POST / GET            pedidos
 *   /turbopoder/seller/*                        panel de cada tienda
 *
 * Tablas propias (turbopoder_*), aisladas del resto del backend. Las imágenes
 * se suben al mismo Cloudinary que usa el resto del ecosistema.
 * ========================================================================== */

import express from 'express';

const CATEGORIES = [
  'Tecnología', 'Hogar', 'Moda', 'Comida', 'Juguetes', 'Arte', 'Deportes',
  'Música', 'Libros', 'Jardín', 'Coleccionables', 'Servicios', 'Otros'
];

const ACCENTS = ['#d9ff3c', '#ff3d8b', '#35e0ff', '#ffb340', '#a78bfa', '#3ddc97', '#ff6b4a', '#f2ead6'];

const ORDER_STATUSES = ['pendiente', 'confirmado', 'enviado', 'entregado', 'cancelado'];

// Envío plano por pedido. A partir de FREE_SHIPPING_FROM el envío corre por
// cuenta de la tienda. Ambos valores se publican en /turbopoder/meta para
// que el carrito muestre exactamente lo que va a cobrar el servidor.
const SHIPPING_FLAT = 2500;
const FREE_SHIPPING_FROM = 30000;

const MAX_STORES_PER_OWNER = 5;
const MAX_PRODUCTS_PER_STORE = 120;
const MAX_ORDER_ITEMS = 25;

const DEMO_STORES = [
  {
    slug: 'bazar-nueve-vidas',
    name: 'Bazar Nueve Vidas',
    emoji: '🪔',
    accent: '#ffb340',
    category: 'Hogar',
    tagline: 'Objetos que hacen rendir cada rincón de la casa.',
    description: 'Curado entre talleres y ferias: piezas útiles, resistentes y con algo de carácter. Reponemos todas las semanas.',
    products: [
      { name: 'Lámpara de lava orbital', price: 24900, stock: 12, category: 'Hogar', emoji: '🪐', description: 'Base de metal pintado y cúpula de vidrio soplado. Luz cálida regulable en tres intensidades.' },
      { name: 'Set de cuchillos magnéticos', price: 38500, stock: 6, category: 'Hogar', emoji: '🔪', description: 'Tres hojas de acero al carbono con tira magnética de pared. Se agarran solos y no ocupan lugar en el cajón.' },
      { name: 'Organizador de cables nudo cero', price: 7900, stock: 40, category: 'Hogar', emoji: '🧵', description: 'Seis sujetadores de silicona reciclada que se pegan donde haga falta. Adiós al nudo atrás del escritorio.' },
      { name: 'Manta térmica de sofá', price: 19900, stock: 9, category: 'Hogar', emoji: '🛋️', description: 'Polar de doble capa, 130 x 180 cm. Abriga de verdad y entra perfecta en el lavarropas.' }
    ]
  },
  {
    slug: 'frecuencia-kiosko',
    name: 'Frecuencia Kiosko',
    emoji: '📻',
    accent: '#35e0ff',
    category: 'Tecnología',
    tagline: 'Audio y periféricos probados a volumen real.',
    description: 'Equipos que pasaron por la mesa de mezcla antes de llegar a la vidriera. Si algo no suena bien, no se publica.',
    products: [
      { name: 'Audífonos de estudio cerrados', price: 52900, stock: 8, category: 'Tecnología', emoji: '🎧', description: 'Respuesta plana, cable desmontable de 3 m y almohadillas reemplazables. Ideales para mezclar de noche sin molestar.' },
      { name: 'Teclado mecánico compacto', price: 61900, stock: 5, category: 'Tecnología', emoji: '⌨️', description: 'Formato 65% con switches táctiles y perfil bajo. Se conecta por USB-C o Bluetooth y aguanta dos semanas por carga.' },
      { name: 'Parlante de bolsillo', price: 27900, stock: 15, category: 'Tecnología', emoji: '🔊', description: 'Cuerpo de aluminio, 12 horas de batería y correa de tela. Suena mucho más de lo que su tamaño promete.' },
      { name: 'Reloj de mesa con luces', price: 15900, stock: 11, category: 'Tecnología', emoji: '⏰', description: 'Display de puntos, alarma suave y luz ambiente en siete tonos. Se controla con una sola rueda.' }
    ]
  },
  {
    slug: 'taller-pata-de-palo',
    name: 'Taller Pata de Palo',
    emoji: '🎨',
    accent: '#ff3d8b',
    category: 'Arte',
    tagline: 'Piezas hechas de a una, con las manos y sin apuro.',
    description: 'Cerámica, papel y tinta en pequeños lotes. Cada pieza sale distinta porque está hecha así, a mano.',
    products: [
      { name: 'Taza de cerámica torneada', price: 12900, stock: 14, category: 'Arte', emoji: '☕', description: 'Gres cocido a alta temperatura con esmalte satinado. 320 ml, apta para microondas y lavavajillas.' },
      { name: 'Lámina Rincón de pared', price: 8900, stock: 25, category: 'Arte', emoji: '🖼️', description: 'Impresión en papel de algodón 300 g, 30 x 40 cm. Se envía enrollada en tubo rígido.' },
      { name: 'Cuaderno cosido a mano', price: 7400, stock: 30, category: 'Arte', emoji: '📓', description: '96 hojas de papel marfil de 120 g, costura expuesta y tapa de cartón prensado. Abre plano y no se desarma.' },
      { name: 'Set de sellos de goma', price: 11400, stock: 18, category: 'Arte', emoji: '🔖', description: 'Ocho sellos con motivos de taller, almohadilla de tinta y bolsa de tela para guardarlos.' }
    ]
  },
  {
    slug: 'la-despensa-mutante',
    name: 'La Despensa Mutante',
    emoji: '🫙',
    accent: '#3ddc97',
    category: 'Comida',
    tagline: 'Cosas ricas de productores chicos, sin vueltas.',
    description: 'Compramos por lote a quien las hace y despachamos lo que entra. Si no está en la lista, es porque se terminó.',
    products: [
      { name: 'Café de origen 500 g', price: 9800, stock: 22, category: 'Comida', emoji: '☕', description: 'Tueste medio de altura, notas a cacao y naranja. Grano entero o molido a pedido en el checkout.' },
      { name: 'Miel de monte 450 g', price: 7200, stock: 16, category: 'Comida', emoji: '🍯', description: 'Cosecha de primavera, sin pasteurizar. Cristaliza con el frío y vuelve sola con un baño de agua tibia.' },
      { name: 'Conserva de tomate ahumado', price: 5400, stock: 30, category: 'Comida', emoji: '🍅', description: 'Tomates perita cocidos a fuego lento con humo de leña. Frasco de 380 g, rinde para cuatro porciones.' },
      { name: 'Chocolate 70% con sal marina', price: 4600, stock: 45, category: 'Comida', emoji: '🍫', description: 'Barra de 80 g, cacao de fino aroma y un final salado que corta el dulce. Sin leche ni conservantes.' }
    ]
  },
  {
    slug: 'garaje-turbopoder',
    name: 'Garaje Turbopoder',
    emoji: '🛠️',
    accent: '#d9ff3c',
    category: 'Coleccionables',
    tagline: 'Merch oficial del rincón, hecho para durar.',
    description: 'La mesa de merchandising del estudio. Series cortas, materiales honestos y envíos en sobre rígido.',
    products: [
      { name: 'Sticker pack turbocargado', price: 3000, stock: 80, category: 'Coleccionables', emoji: '🏷️', description: 'Doce calcos vinílicos resistentes al agua. Tamaños variados para notebook, botella o puerta del taller.' },
      { name: 'Taza modo turbo', price: 9500, stock: 26, category: 'Coleccionables', emoji: '🥤', description: 'Cerámica de 350 ml con impresión a 360°. Sobrevive al lavavajillas y a las mañanas difíciles.' },
      { name: 'Mochila de herramientas', price: 45900, stock: 4, category: 'Coleccionables', emoji: '🎒', description: 'Lona encerada con veinte bolsillos y base reforzada. Cabe notebook de 15 pulgadas y el destornillador de siempre.' },
      { name: 'Linterna recargable', price: 13900, stock: 20, category: 'Coleccionables', emoji: '🔦', description: 'Aluminio anodizado, 400 lúmenes y carga por USB-C. Tiene imán en la base para dejarla pegada al tablero.' }
    ]
  }
];

/* -------------------------------------------------------------------------- */

function text(value, max) {
  return String(value == null ? '' : value).replace(/[ \t\r\n]+/g, ' ').trim().slice(0, max);
}

function trimmed(value, max) {
  return String(value == null ? '' : value).trim().slice(0, max);
}

function toPrice(value) {
  const n = Number(String(value == null ? '' : value).replace(',', '.'));
  if (!Number.isFinite(n)) return NaN;
  return Math.round(n * 100) / 100;
}

function toInt(value, fallback) {
  const n = parseInt(value, 10);
  return Number.isFinite(n) ? n : fallback;
}

function clampInt(value, min, max, fallback) {
  const n = toInt(value, fallback);
  return Math.min(max, Math.max(min, n));
}

function isEmail(value) {
  const email = String(value || '').trim();
  if (!email || email.length > 160 || email.indexOf(' ') !== -1) return false;
  const at = email.indexOf('@');
  const dot = email.lastIndexOf('.');
  return at > 0 && dot > at + 1 && dot < email.length - 1 && email.indexOf('@', at + 1) === -1;
}

// Normaliza un nombre a slug ASCII: "Rincón de Ñandú" -> "rincon-de-nandu".
function slugify(name) {
  const flat = String(name || '')
    .normalize('NFD')
    .split('')
    .filter(function (ch) { return ch.charCodeAt(0) < 128; })
    .join('')
    .toLowerCase();
  return flat.replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48);
}

function safeHttpUrl(value) {
  const raw = String(value == null ? '' : value).trim();
  if (!raw) return '';
  if (!/^https?:\/\//i.test(raw)) return '';
  if (/[\u0000-\u001F\u007F"'<>`\s]/.test(raw)) return '';
  try {
    const parsed = new URL(raw);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return '';
    return parsed.toString();
  } catch (_) {
    return '';
  }
}

function pickEmoji(value, fallback) {
  const raw = String(value || '').trim();
  if (!raw) return fallback;
  const chars = Array.from(raw);
  return chars.slice(0, 4).join('') || fallback;
}

function orderCode() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 6; i += 1) {
    code += alphabet.charAt(Math.floor(Math.random() * alphabet.length));
  }
  return 'RT-' + code;
}

function sqlMoney(value) {
  return Number(value) || 0;
}

/* -------------------------------------------------------------------------- */

export function registerTurboPoder(app, deps) {
  const options = deps || {};
  const pool = options.pool;
  const upload = options.upload;
  const bcrypt = options.bcrypt;
  const jwt = options.jwt;
  const getStudioSecret = options.getStudioSecret;

  if (!pool || !upload || !bcrypt || !jwt || typeof getStudioSecret !== 'function') {
    console.warn('[TURBOPODER] Faltan dependencias (pool, upload, bcrypt, jwt o secreto); la API no se monta.');
    return;
  }

  const router = express.Router();
  app.use('/turbopoder', router);

  const loginAttempts = new Map();

  function fail(status, message) {
    const error = new Error(message);
    error.exposeStatus = status;
    return error;
  }

  // Envuelve handlers async: cualquier error sale como JSON y nunca tumba el
  // proceso. Los errores de validación ya traen su status.
  function wrap(handler) {
    return function (req, res) {
      Promise.resolve(handler(req, res)).catch(function (error) {
        if (error && error.exposeStatus) {
          if (!res.headersSent) res.status(error.exposeStatus).json({ error: error.message });
          return;
        }
        console.error('[TURBOPODER]', error);
        if (!res.headersSent) {
          res.status(500).json({ error: 'No pudimos completar la operación. Probá de nuevo en un momento.' });
        }
      });
    };
  }

  function readToken(req) {
    const header = String(req.headers.authorization || '');
    if (header.toLowerCase().indexOf('bearer ') !== 0) return null;
    const token = header.slice(7).trim();
    if (!token) return null;
    try {
      const payload = jwt.verify(token, getStudioSecret());
      const id = Number(payload && payload.id);
      if (!id || payload.app !== 'turbopoder') return null;
      return { id: id, email: String(payload.email || '') };
    } catch (_) {
      return null;
    }
  }

  function authOptional(req, _res, next) {
    req.tpUser = readToken(req);
    next();
  }

  function authRequired(req, res, next) {
    req.tpUser = readToken(req);
    if (!req.tpUser) return res.status(401).json({ error: 'Necesitás iniciar sesión para hacer esto.' });
    next();
  }

  async function currentUser(id) {
    const result = await pool.query('SELECT id, name, email, created_at FROM turbopoder_users WHERE id = $1 LIMIT 1', [id]);
    return result.rows[0] || null;
  }

  function throttle(email, req) {
    const key = String(req.ip || '') + '|' + email;
    const now = Date.now();
    const entry = loginAttempts.get(key);
    if (!entry || entry.resetAt < now) {
      loginAttempts.set(key, { count: 0, resetAt: now + 10 * 60 * 1000 });
      return;
    }
    if (entry.count >= 8) {
      throw fail(429, 'Demasiados intentos seguidos. Esperá unos minutos y volvé a probar.');
    }
  }

  function noteAttempt(email, req) {
    const key = String(req.ip || '') + '|' + email;
    const entry = loginAttempts.get(key);
    if (!entry) return;
    entry.count += 1;
  }

  let tablesReady = null;

  async function seedDemo() {
    const meta = await pool.query("SELECT value FROM turbopoder_meta WHERE key = 'seeded' LIMIT 1");
    if (meta.rows.length) return;
    const existing = await pool.query('SELECT COUNT(*)::int AS total FROM turbopoder_stores');
    if ((existing.rows[0] || {}).total === 0) {
      for (const store of DEMO_STORES) {
        const inserted = await pool.query(
          'INSERT INTO turbopoder_stores (owner_id, slug, name, tagline, description, category, emoji, accent) ' +
          'VALUES (NULL, $1, $2, $3, $4, $5, $6, $7) ON CONFLICT (slug) DO NOTHING RETURNING id',
          [store.slug, store.name, store.tagline, store.description, store.category, store.emoji, store.accent]
        );
        if (!inserted.rows.length) continue;
        const storeId = inserted.rows[0].id;
        for (const item of store.products) {
          await pool.query(
            'INSERT INTO turbopoder_products (store_id, name, description, price, stock, category, emoji, status) ' +
            'VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
            [storeId, item.name, item.description, item.price, item.stock, item.category, item.emoji, 'activo']
          );
        }
      }
    }
    await pool.query("INSERT INTO turbopoder_meta (key, value) VALUES ('seeded', '1') ON CONFLICT (key) DO NOTHING");
  }

  function ensureTables() {
    if (!tablesReady) {
      tablesReady = (async function () {
        await pool.query(`
          CREATE TABLE IF NOT EXISTS turbopoder_users (
            id SERIAL PRIMARY KEY,
            name VARCHAR(80) NOT NULL,
            email VARCHAR(160) NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
          )
        `);
        await pool.query(`
          CREATE TABLE IF NOT EXISTS turbopoder_stores (
            id SERIAL PRIMARY KEY,
            owner_id INTEGER REFERENCES turbopoder_users(id) ON DELETE SET NULL,
            slug VARCHAR(80) NOT NULL UNIQUE,
            name VARCHAR(80) NOT NULL,
            tagline VARCHAR(160) NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            category VARCHAR(40) NOT NULL DEFAULT 'Otros',
            emoji VARCHAR(16) NOT NULL DEFAULT '🧰',
            accent VARCHAR(9) NOT NULL DEFAULT '#d9ff3c',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
          )
        `);
        await pool.query(`
          CREATE TABLE IF NOT EXISTS turbopoder_products (
            id SERIAL PRIMARY KEY,
            store_id INTEGER NOT NULL REFERENCES turbopoder_stores(id) ON DELETE CASCADE,
            name VARCHAR(120) NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            price NUMERIC(12,2) NOT NULL CHECK (price >= 0),
            stock INTEGER NOT NULL DEFAULT 1,
            category VARCHAR(40) NOT NULL DEFAULT 'Otros',
            emoji VARCHAR(16) NOT NULL DEFAULT '📦',
            image_url TEXT NOT NULL DEFAULT '',
            status VARCHAR(20) NOT NULL DEFAULT 'activo',
            sales INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
          )
        `);
        await pool.query(`
          CREATE TABLE IF NOT EXISTS turbopoder_orders (
            id SERIAL PRIMARY KEY,
            code VARCHAR(24) NOT NULL UNIQUE,
            store_id INTEGER NOT NULL REFERENCES turbopoder_stores(id) ON DELETE CASCADE,
            buyer_id INTEGER REFERENCES turbopoder_users(id) ON DELETE SET NULL,
            buyer_name VARCHAR(120) NOT NULL,
            buyer_email VARCHAR(160) NOT NULL,
            buyer_phone VARCHAR(40) NOT NULL DEFAULT '',
            address TEXT NOT NULL DEFAULT '',
            note TEXT NOT NULL DEFAULT '',
            subtotal NUMERIC(12,2) NOT NULL,
            shipping NUMERIC(12,2) NOT NULL DEFAULT 0,
            total NUMERIC(12,2) NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'pendiente',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
          )
        `);
        await pool.query(`
          CREATE TABLE IF NOT EXISTS turbopoder_order_items (
            id SERIAL PRIMARY KEY,
            order_id INTEGER NOT NULL REFERENCES turbopoder_orders(id) ON DELETE CASCADE,
            product_id INTEGER REFERENCES turbopoder_products(id) ON DELETE SET NULL,
            name VARCHAR(160) NOT NULL,
            price NUMERIC(12,2) NOT NULL,
            qty INTEGER NOT NULL
          )
        `);
        await pool.query(`
          CREATE TABLE IF NOT EXISTS turbopoder_reviews (
            id SERIAL PRIMARY KEY,
            product_id INTEGER NOT NULL REFERENCES turbopoder_products(id) ON DELETE CASCADE,
            store_id INTEGER NOT NULL REFERENCES turbopoder_stores(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES turbopoder_users(id) ON DELETE SET NULL,
            author VARCHAR(80) NOT NULL,
            rating SMALLINT NOT NULL CHECK (rating BETWEEN 1 AND 5),
            comment TEXT NOT NULL DEFAULT '',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (product_id, user_id)
          )
        `);
        await pool.query(`
          CREATE TABLE IF NOT EXISTS turbopoder_meta (
            key VARCHAR(40) PRIMARY KEY,
            value TEXT NOT NULL
          )
        `);
        await pool.query('CREATE INDEX IF NOT EXISTS idx_tp_products_store ON turbopoder_products(store_id)').catch(function () {});
        await pool.query('CREATE INDEX IF NOT EXISTS idx_tp_orders_store ON turbopoder_orders(store_id)').catch(function () {});
        await pool.query('CREATE INDEX IF NOT EXISTS idx_tp_orders_buyer ON turbopoder_orders(buyer_email)').catch(function () {});
        await seedDemo();
      })().catch(function (error) {
        tablesReady = null;
        throw error;
      });
    }
    return tablesReady;
  }

  function mapStore(row) {
    return {
      id: Number(row.id),
      slug: row.slug,
      name: row.name,
      tagline: row.tagline || '',
      description: row.description || '',
      category: row.category || 'Otros',
      emoji: row.emoji || '🧰',
      accent: row.accent || '#d9ff3c',
      createdAt: row.created_at,
      productCount: Number(row.product_count || 0),
      rating: Number(row.avg_rating || 0),
      reviewCount: Number(row.review_count || 0),
      ownerId: row.owner_id == null ? null : Number(row.owner_id),
      ownerName: row.owner_name || ''
    };
  }

  function mapProduct(row) {
    return {
      id: Number(row.id),
      storeId: Number(row.store_id),
      storeSlug: row.store_slug || '',
      storeName: row.store_name || '',
      storeEmoji: row.store_emoji || '🧰',
      storeAccent: row.store_accent || '#d9ff3c',
      storeTagline: row.store_tagline || '',
      name: row.name,
      description: row.description || '',
      price: sqlMoney(row.price),
      stock: Number(row.stock || 0),
      category: row.category || 'Otros',
      emoji: row.emoji || '📦',
      imageUrl: row.image_url || '',
      status: row.status || 'activo',
      sales: Number(row.sales || 0),
      createdAt: row.created_at,
      rating: Number(row.avg_rating || 0),
      reviewCount: Number(row.review_count || 0)
    };
  }

  function mapOrder(row) {
    return {
      id: Number(row.id),
      code: row.code,
      storeId: Number(row.store_id),
      storeName: row.store_name || '',
      storeSlug: row.store_slug || '',
      storeEmoji: row.store_emoji || '🧰',
      storeAccent: row.store_accent || '#d9ff3c',
      buyerName: row.buyer_name,
      buyerEmail: row.buyer_email,
      buyerPhone: row.buyer_phone || '',
      address: row.address || '',
      note: row.note || '',
      subtotal: sqlMoney(row.subtotal),
      shipping: sqlMoney(row.shipping),
      total: sqlMoney(row.total),
      status: row.status,
      createdAt: row.created_at,
      items: (row.items || []).map(function (item) {
        return { name: item.name, qty: Number(item.qty), price: sqlMoney(item.price) };
      })
    };
  }

  /* ------------------------------- sesión -------------------------------- */

  router.get('/health', function (_req, res) {
    res.json({ status: 'up', service: 'Rincón Turbopoder' });
  });

  router.get('/meta', wrap(async function (_req, res) {
    await ensureTables();
    const stats = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM turbopoder_stores)::int AS stores,
        (SELECT COUNT(*) FROM turbopoder_products WHERE status = 'activo')::int AS products,
        (SELECT COUNT(*) FROM turbopoder_orders)::int AS orders,
        (SELECT COUNT(DISTINCT category) FROM turbopoder_products WHERE status = 'activo')::int AS categories
    `);
    res.json({
      categories: CATEGORIES,
      accents: ACCENTS,
      shipping: { flat: SHIPPING_FLAT, freeFrom: FREE_SHIPPING_FROM },
      limits: { storesPerOwner: MAX_STORES_PER_OWNER, productsPerStore: MAX_PRODUCTS_PER_STORE },
      stats: stats.rows[0] || { stores: 0, products: 0, orders: 0, categories: 0 }
    });
  }));

  router.post('/register', wrap(async function (req, res) {
    await ensureTables();
    const name = text(req.body && req.body.name, 60);
    const email = String((req.body && req.body.email) || '').trim().toLowerCase();
    const password = String((req.body && req.body.password) || '');

    if (name.length < 2) throw fail(400, 'Poné tu nombre (mínimo 2 letras).');
    if (!isEmail(email)) throw fail(400, 'Ese correo no parece válido.');
    if (password.length < 6) throw fail(400, 'La contraseña necesita al menos 6 caracteres.');
    if (password.length > 120) throw fail(400, 'La contraseña es demasiado larga.');

    const duplicate = await pool.query('SELECT 1 FROM turbopoder_users WHERE email = $1 LIMIT 1', [email]);
    if (duplicate.rows.length) throw fail(409, 'Ya hay una cuenta con ese correo. Probá entrar.');

    const hash = await bcrypt.hash(password, 10);
    const inserted = await pool.query(
      'INSERT INTO turbopoder_users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name, email, created_at',
      [name, email, hash]
    );
    const user = inserted.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email, app: 'turbopoder' }, getStudioSecret(), { expiresIn: '30d' });
    res.status(201).json({
      success: true,
      token: token,
      user: { id: Number(user.id), name: user.name, email: user.email, createdAt: user.created_at }
    });
  }));

  router.post('/login', wrap(async function (req, res) {
    await ensureTables();
    const email = String((req.body && req.body.email) || '').trim().toLowerCase();
    const password = String((req.body && req.body.password) || '');
    if (!isEmail(email) || !password) throw fail(400, 'Completá correo y contraseña.');

    throttle(email, req);
    const result = await pool.query('SELECT * FROM turbopoder_users WHERE email = $1 LIMIT 1', [email]);
    const user = result.rows[0];
    const valid = user ? await bcrypt.compare(password, user.password_hash) : false;
    if (!valid) {
      noteAttempt(email, req);
      throw fail(401, 'Correo o contraseña incorrectos.');
    }
    loginAttempts.delete(String(req.ip || '') + '|' + email);
    const token = jwt.sign({ id: user.id, email: user.email, app: 'turbopoder' }, getStudioSecret(), { expiresIn: '30d' });
    res.json({
      success: true,
      token: token,
      user: { id: Number(user.id), name: user.name, email: user.email, createdAt: user.created_at }
    });
  }));

  router.get('/me', authRequired, wrap(async function (req, res) {
    await ensureTables();
    const user = await currentUser(req.tpUser.id);
    if (!user) throw fail(401, 'Tu sesión venció. Volvé a entrar.');
    res.json({ user: { id: Number(user.id), name: user.name, email: user.email, createdAt: user.created_at } });
  }));

  /* ------------------------------- tiendas -------------------------------- */

  router.get('/stores', authOptional, wrap(async function (req, res) {
    await ensureTables();
    const search = text(req.query.search, 60);
    const category = text(req.query.category, 40);
    const onlyMine = String(req.query.owner || '') === 'me';
    const limit = clampInt(req.query.limit, 1, 60, 24);
    const where = [];
    const values = [];

    if (search) {
      values.push('%' + search + '%');
      const n = values.length;
      where.push('(s.name ILIKE $' + n + ' OR s.tagline ILIKE $' + n + ' OR s.description ILIKE $' + n + ' OR s.category ILIKE $' + n + ')');
    }
    if (category && category !== 'Todos') {
      values.push(category);
      where.push('s.category = $' + values.length);
    }
    if (onlyMine) {
      if (!req.tpUser) return res.status(401).json({ error: 'Necesitás iniciar sesión.' });
      values.push(req.tpUser.id);
      where.push('s.owner_id = $' + values.length);
    }

    const sql =
      'SELECT s.*, u.name AS owner_name, ' +
      '(SELECT COUNT(*) FROM turbopoder_products p WHERE p.store_id = s.id AND p.status = \'activo\')::int AS product_count, ' +
      '(SELECT COUNT(*) FROM turbopoder_reviews r WHERE r.store_id = s.id)::int AS review_count, ' +
      'COALESCE((SELECT ROUND(AVG(r.rating)::numeric, 1) FROM turbopoder_reviews r WHERE r.store_id = s.id), 0) AS avg_rating ' +
      'FROM turbopoder_stores s LEFT JOIN turbopoder_users u ON u.id = s.owner_id ' +
      (where.length ? 'WHERE ' + where.join(' AND ') + ' ' : '') +
      'ORDER BY product_count DESC, s.created_at DESC LIMIT ' + limit;

    const result = await pool.query(sql, values);
    res.json({ stores: result.rows.map(mapStore) });
  }));

  router.get('/stores/:slug', authOptional, wrap(async function (req, res) {
    await ensureTables();
    const slug = text(req.params.slug, 80).toLowerCase();
    const result = await pool.query(
      'SELECT s.*, u.name AS owner_name, ' +
      '(SELECT COUNT(*) FROM turbopoder_products p WHERE p.store_id = s.id AND p.status = \'activo\')::int AS product_count, ' +
      '(SELECT COUNT(*) FROM turbopoder_reviews r WHERE r.store_id = s.id)::int AS review_count, ' +
      'COALESCE((SELECT ROUND(AVG(r.rating)::numeric, 1) FROM turbopoder_reviews r WHERE r.store_id = s.id), 0) AS avg_rating ' +
      'FROM turbopoder_stores s LEFT JOIN turbopoder_users u ON u.id = s.owner_id WHERE s.slug = $1 LIMIT 1',
      [slug]
    );
    if (!result.rows.length) throw fail(404, 'Ese rincón todavía no existe.');
    const store = mapStore(result.rows[0]);

    const products = await pool.query(
      'SELECT p.*, s.slug AS store_slug, s.name AS store_name, s.emoji AS store_emoji, s.accent AS store_accent, ' +
      '(SELECT COUNT(*) FROM turbopoder_reviews r WHERE r.product_id = p.id)::int AS review_count, ' +
      'COALESCE((SELECT ROUND(AVG(r.rating)::numeric, 1) FROM turbopoder_reviews r WHERE r.product_id = p.id), 0) AS avg_rating ' +
      'FROM turbopoder_products p JOIN turbopoder_stores s ON s.id = p.store_id ' +
      'WHERE p.store_id = $1 AND p.status = \'activo\' ORDER BY p.created_at DESC LIMIT 120',
      [store.id]
    );
    res.json({ store: store, products: products.rows.map(mapProduct) });
  }));

  router.post('/stores', authRequired, wrap(async function (req, res) {
    await ensureTables();
    const body = req.body || {};
    const name = text(body.name, 60);
    const tagline = text(body.tagline, 140);
    const description = trimmed(body.description, 700);
    const category = CATEGORIES.indexOf(text(body.category, 40)) !== -1 ? text(body.category, 40) : 'Otros';
    const emoji = pickEmoji(body.emoji, '🧰');
    const accent = ACCENTS.indexOf(String(body.accent || '').toLowerCase()) !== -1 ? String(body.accent).toLowerCase() : ACCENTS[0];

    if (name.length < 3) throw fail(400, 'El nombre de la tienda necesita al menos 3 letras.');
    if (tagline.length < 6) throw fail(400, 'Sumale una frase corta que explique qué vendés.');

    const owned = await pool.query('SELECT COUNT(*)::int AS total FROM turbopoder_stores WHERE owner_id = $1', [req.tpUser.id]);
    if ((owned.rows[0] || {}).total >= MAX_STORES_PER_OWNER) {
      throw fail(429, 'Llegaste al máximo de ' + MAX_STORES_PER_OWNER + ' tiendas por cuenta.');
    }

    const baseSlug = slugify(name) || 'rincon';
    let slug = baseSlug;
    for (let attempt = 1; attempt <= 12; attempt += 1) {
      const taken = await pool.query('SELECT 1 FROM turbopoder_stores WHERE slug = $1 LIMIT 1', [slug]);
      if (!taken.rows.length) break;
      slug = baseSlug + '-' + attempt;
    }

    const inserted = await pool.query(
      'INSERT INTO turbopoder_stores (owner_id, slug, name, tagline, description, category, emoji, accent) ' +
      'VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
      [req.tpUser.id, slug, name, tagline, description, category, emoji, accent]
    );
    res.status(201).json({ success: true, store: mapStore(inserted.rows[0]) });
  }));

  router.patch('/stores/:id', authRequired, wrap(async function (req, res) {
    await ensureTables();
    const storeId = toInt(req.params.id, 0);
    if (!storeId) throw fail(400, 'Tienda inválida.');
    const owned = await pool.query('SELECT * FROM turbopoder_stores WHERE id = $1 AND owner_id = $2 LIMIT 1', [storeId, req.tpUser.id]);
    if (!owned.rows.length) throw fail(403, 'Esa tienda no es tuya.');
    const body = req.body || {};
    const current = owned.rows[0];

    const name = body.name === undefined ? current.name : text(body.name, 60);
    const tagline = body.tagline === undefined ? current.tagline : text(body.tagline, 140);
    const description = body.description === undefined ? current.description : trimmed(body.description, 700);
    const category = body.category === undefined
      ? current.category
      : (CATEGORIES.indexOf(text(body.category, 40)) !== -1 ? text(body.category, 40) : current.category);
    const emoji = body.emoji === undefined ? current.emoji : pickEmoji(body.emoji, current.emoji);
    const accent = body.accent === undefined
      ? current.accent
      : (ACCENTS.indexOf(String(body.accent || '').toLowerCase()) !== -1 ? String(body.accent).toLowerCase() : current.accent);

    if (name.length < 3) throw fail(400, 'El nombre de la tienda necesita al menos 3 letras.');

    const updated = await pool.query(
      'UPDATE turbopoder_stores SET name = $1, tagline = $2, description = $3, category = $4, emoji = $5, accent = $6 WHERE id = $7 RETURNING *',
      [name, tagline, description, category, emoji, accent, storeId]
    );
    res.json({ success: true, store: mapStore(updated.rows[0]) });
  }));

  /* ------------------------------ productos ------------------------------- */

  router.get('/products', wrap(async function (req, res) {
    await ensureTables();
    const search = text(req.query.search, 60);
    const category = text(req.query.category, 40);
    const storeSlug = text(req.query.store, 80).toLowerCase();
    const storeId = toInt(req.query.storeId, 0);
    const sort = text(req.query.sort, 24) || 'recientes';
    const limit = clampInt(req.query.limit, 1, 60, 24);
    const offset = clampInt(req.query.offset, 0, 600, 0);
    const where = ["p.status = 'activo'"];
    const values = [];

    if (search) {
      values.push('%' + search + '%');
      const n = values.length;
      where.push('(p.name ILIKE $' + n + ' OR p.description ILIKE $' + n + ' OR s.name ILIKE $' + n + ' OR p.category ILIKE $' + n + ')');
    }
    if (category && category !== 'Todos') {
      values.push(category);
      where.push('p.category = $' + values.length);
    }
    if (storeId) {
      values.push(storeId);
      where.push('p.store_id = $' + values.length);
    } else if (storeSlug) {
      values.push(storeSlug);
      where.push('s.slug = $' + values.length);
    }

    const order = {
      'precio-asc': 'p.price ASC',
      'precio-desc': 'p.price DESC',
      vendidos: 'p.sales DESC, p.created_at DESC',
      nombre: 'p.name ASC'
    }[sort] || 'p.created_at DESC';

    const sql =
      'SELECT p.*, s.slug AS store_slug, s.name AS store_name, s.emoji AS store_emoji, s.accent AS store_accent, ' +
      '(SELECT COUNT(*) FROM turbopoder_reviews r WHERE r.product_id = p.id)::int AS review_count, ' +
      'COALESCE((SELECT ROUND(AVG(r.rating)::numeric, 1) FROM turbopoder_reviews r WHERE r.product_id = p.id), 0) AS avg_rating ' +
      'FROM turbopoder_products p JOIN turbopoder_stores s ON s.id = p.store_id ' +
      'WHERE ' + where.join(' AND ') + ' ORDER BY ' + order + ' LIMIT ' + limit + ' OFFSET ' + offset;

    const result = await pool.query(sql, values);
    res.json({ products: result.rows.map(mapProduct), limit: limit, offset: offset, count: result.rows.length });
  }));

  router.get('/products/:id', authOptional, wrap(async function (req, res) {
    await ensureTables();
    const productId = toInt(req.params.id, 0);
    if (!productId) throw fail(400, 'Producto inválido.');
    const result = await pool.query(
      'SELECT p.*, s.slug AS store_slug, s.name AS store_name, s.emoji AS store_emoji, s.accent AS store_accent, s.tagline AS store_tagline, ' +
      '(SELECT COUNT(*) FROM turbopoder_reviews r WHERE r.product_id = p.id)::int AS review_count, ' +
      'COALESCE((SELECT ROUND(AVG(r.rating)::numeric, 1) FROM turbopoder_reviews r WHERE r.product_id = p.id), 0) AS avg_rating ' +
      'FROM turbopoder_products p JOIN turbopoder_stores s ON s.id = p.store_id WHERE p.id = $1 LIMIT 1',
      [productId]
    );
    if (!result.rows.length) throw fail(404, 'Ese producto ya no está en la vitrina.');
    const product = mapProduct(result.rows[0]);
    product.storeTagline = result.rows[0].store_tagline || '';

    const reviews = await pool.query(
      'SELECT id, author, rating, comment, created_at FROM turbopoder_reviews WHERE product_id = $1 ORDER BY created_at DESC LIMIT 30',
      [productId]
    );
    const related = await pool.query(
      'SELECT p.*, s.slug AS store_slug, s.name AS store_name, s.emoji AS store_emoji, s.accent AS store_accent, ' +
      "(SELECT COUNT(*) FROM turbopoder_reviews r WHERE r.product_id = p.id)::int AS review_count, " +
      'COALESCE((SELECT ROUND(AVG(r.rating)::numeric, 1) FROM turbopoder_reviews r WHERE r.product_id = p.id), 0) AS avg_rating ' +
      "FROM turbopoder_products p JOIN turbopoder_stores s ON s.id = p.store_id WHERE p.store_id = $1 AND p.id <> $2 AND p.status = 'activo' ORDER BY p.created_at DESC LIMIT 4",
      [product.storeId, productId]
    );

    res.json({
      product: product,
      reviews: reviews.rows.map(function (row) {
        return { id: Number(row.id), author: row.author, rating: Number(row.rating), comment: row.comment, createdAt: row.created_at };
      }),
      related: related.rows.map(mapProduct)
    });
  }));

  router.post('/products', authRequired, upload.array('images', 3), wrap(async function (req, res) {
    await ensureTables();
    const body = req.body || {};
    const storeId = toInt(body.storeId, 0);
    if (!storeId) throw fail(400, 'Elegí en qué tienda va el producto.');

    const owned = await pool.query('SELECT * FROM turbopoder_stores WHERE id = $1 AND owner_id = $2 LIMIT 1', [storeId, req.tpUser.id]);
    if (!owned.rows.length) throw fail(403, 'Esa tienda no es tuya.');

    const countResult = await pool.query('SELECT COUNT(*)::int AS total FROM turbopoder_products WHERE store_id = $1', [storeId]);
    if ((countResult.rows[0] || {}).total >= MAX_PRODUCTS_PER_STORE) {
      throw fail(429, 'Esta tienda llegó al máximo de ' + MAX_PRODUCTS_PER_STORE + ' productos.');
    }

    const name = text(body.name, 100);
    const description = trimmed(body.description, 900);
    const price = toPrice(body.price);
    const stock = clampInt(body.stock, 0, 9999, 1);
    const category = CATEGORIES.indexOf(text(body.category, 40)) !== -1 ? text(body.category, 40) : 'Otros';
    const emoji = pickEmoji(body.emoji, '📦');
    const uploaded = req.files && req.files[0] ? req.files[0].path : '';
    const imageUrl = safeHttpUrl(uploaded) || safeHttpUrl(body.imageUrl);

    if (name.length < 2) throw fail(400, 'Poné un nombre de producto.');
    if (!Number.isFinite(price) || price <= 0) throw fail(400, 'El precio tiene que ser mayor a cero.');
    if (price > 5000000) throw fail(400, 'Ese precio se va de rango.');

    const inserted = await pool.query(
      'INSERT INTO turbopoder_products (store_id, name, description, price, stock, category, emoji, image_url, status) ' +
      "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'activo') RETURNING *",
      [storeId, name, description, price, stock, category, emoji, imageUrl]
    );
    const product = mapProduct({
      ...inserted.rows[0],
      store_slug: owned.rows[0].slug,
      store_name: owned.rows[0].name,
      store_emoji: owned.rows[0].emoji,
      store_accent: owned.rows[0].accent
    });
    res.status(201).json({ success: true, product: product });
  }));

  router.patch('/products/:id', authRequired, wrap(async function (req, res) {
    await ensureTables();
    const productId = toInt(req.params.id, 0);
    if (!productId) throw fail(400, 'Producto inválido.');
    const owned = await pool.query(
      'SELECT p.* FROM turbopoder_products p JOIN turbopoder_stores s ON s.id = p.store_id WHERE p.id = $1 AND s.owner_id = $2 LIMIT 1',
      [productId, req.tpUser.id]
    );
    if (!owned.rows.length) throw fail(403, 'Ese producto no está en tus tiendas.');
    const current = owned.rows[0];
    const body = req.body || {};

    const name = body.name === undefined ? current.name : text(body.name, 100);
    const description = body.description === undefined ? current.description : trimmed(body.description, 900);
    let price = current.price;
    if (body.price !== undefined) {
      price = toPrice(body.price);
      if (!Number.isFinite(price) || price <= 0) throw fail(400, 'El precio tiene que ser mayor a cero.');
    }
    const stock = body.stock === undefined ? current.stock : clampInt(body.stock, 0, 9999, current.stock);
    const category = body.category === undefined
      ? current.category
      : (CATEGORIES.indexOf(text(body.category, 40)) !== -1 ? text(body.category, 40) : current.category);
    const emoji = body.emoji === undefined ? current.emoji : pickEmoji(body.emoji, current.emoji);
    const status = body.status === undefined
      ? current.status
      : (['activo', 'pausado'].indexOf(body.status) !== -1 ? body.status : current.status);
    const imageUrl = body.imageUrl === undefined ? current.image_url : (safeHttpUrl(body.imageUrl) || '');

    if (name.length < 2) throw fail(400, 'Poné un nombre de producto.');

    const updated = await pool.query(
      'UPDATE turbopoder_products SET name = $1, description = $2, price = $3, stock = $4, category = $5, emoji = $6, image_url = $7, status = $8 ' +
      'WHERE id = $9 RETURNING *',
      [name, description, price, stock, category, emoji, imageUrl, status, productId]
    );
    res.json({ success: true, product: mapProduct(updated.rows[0]) });
  }));

  router.delete('/products/:id', authRequired, wrap(async function (req, res) {
    await ensureTables();
    const productId = toInt(req.params.id, 0);
    if (!productId) throw fail(400, 'Producto inválido.');
    const deleted = await pool.query(
      'DELETE FROM turbopoder_products p USING turbopoder_stores s WHERE p.id = $1 AND s.id = p.store_id AND s.owner_id = $2 RETURNING p.id',
      [productId, req.tpUser.id]
    );
    if (!deleted.rows.length) throw fail(404, 'No encontramos ese producto en tus tiendas.');
    res.json({ success: true });
  }));

  /* -------------------------------- reviews ------------------------------- */

  router.post('/products/:id/reviews', authRequired, wrap(async function (req, res) {
    await ensureTables();
    const productId = toInt(req.params.id, 0);
    if (!productId) throw fail(400, 'Producto inválido.');
    const rating = clampInt(req.body && req.body.rating, 1, 5, 0);
    const comment = trimmed(req.body && req.body.comment, 600);
    if (!rating) throw fail(400, 'Elegí una puntuación de 1 a 5.');

    const user = await currentUser(req.tpUser.id);
    if (!user) throw fail(401, 'Tu sesión venció. Volvé a entrar.');

    const product = await pool.query('SELECT id, store_id FROM turbopoder_products WHERE id = $1 LIMIT 1', [productId]);
    if (!product.rows.length) throw fail(404, 'Ese producto no existe.');

    const inserted = await pool.query(
      'INSERT INTO turbopoder_reviews (product_id, store_id, user_id, author, rating, comment) ' +
      'VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (product_id, user_id) DO NOTHING RETURNING *',
      [productId, product.rows[0].store_id, user.id, user.name, rating, comment]
    );
    if (!inserted.rows.length) throw fail(409, 'Ya dejaste tu opinión sobre este producto.');
    const row = inserted.rows[0];
    res.status(201).json({
      success: true,
      review: { id: Number(row.id), author: row.author, rating: Number(row.rating), comment: row.comment, createdAt: row.created_at }
    });
  }));

  /* -------------------------------- pedidos ------------------------------- */

  router.post('/orders', authOptional, wrap(async function (req, res) {
    await ensureTables();
    const body = req.body || {};
    const items = Array.isArray(body.items) ? body.items.slice(0, MAX_ORDER_ITEMS) : [];
    if (!items.length) throw fail(400, 'El carrito está vacío.');

    const buyerName = text(body.buyerName, 120);
    const buyerEmail = String(body.buyerEmail || '').trim().toLowerCase();
    const buyerPhone = text(body.buyerPhone, 40);
    const address = trimmed(body.address, 240);
    const note = trimmed(body.note, 500);

    if (buyerName.length < 2) throw fail(400, 'Necesitamos el nombre de quien recibe.');
    if (!isEmail(buyerEmail)) throw fail(400, 'Revisá el correo: no parece válido.');
    if (address.length < 5) throw fail(400, 'Completá la dirección de entrega.');

    const wanted = new Map();
    for (const item of items) {
      const productId = toInt(item && item.productId, 0);
      const qty = clampInt(item && item.qty, 1, 20, 1);
      if (!productId) continue;
      wanted.set(productId, Math.min(20, (wanted.get(productId) || 0) + qty));
    }
    if (!wanted.size) throw fail(400, 'No pudimos leer los productos del carrito.');

    const ids = Array.from(wanted.keys());
    const found = await pool.query(
      'SELECT p.*, s.name AS store_name, s.slug AS store_slug, s.emoji AS store_emoji, s.accent AS store_accent ' +
      "FROM turbopoder_products p JOIN turbopoder_stores s ON s.id = p.store_id WHERE p.id = ANY($1::int[]) AND p.status = 'activo'",
      [ids]
    );
    if (found.rows.length !== ids.length) throw fail(409, 'Algún producto salió de la vitrina mientras comprabas. Actualizá el carrito.');

    const groups = new Map();
    for (const row of found.rows) {
      const qty = wanted.get(Number(row.id)) || 0;
      if (!qty) continue;
      if (Number(row.stock) < qty) throw fail(409, 'Queda menos stock de "' + row.name + '" del que pediste.');
      const storeId = Number(row.store_id);
      if (!groups.has(storeId)) {
        groups.set(storeId, {
          storeId: storeId,
          storeName: row.store_name,
          storeSlug: row.store_slug,
          storeEmoji: row.store_emoji,
          storeAccent: row.store_accent,
          lines: []
        });
      }
      groups.get(storeId).lines.push({ row: row, qty: qty });
    }

    const buyerId = req.tpUser ? req.tpUser.id : null;
    const client = await pool.connect();
    const created = [];
    try {
      await client.query('BEGIN');
      for (const group of groups.values()) {
        let subtotal = 0;
        for (const line of group.lines) {
          subtotal += sqlMoney(line.row.price) * line.qty;
        }
        const shipping = subtotal >= FREE_SHIPPING_FROM ? 0 : SHIPPING_FLAT;
        const total = subtotal + shipping;

        let code = orderCode();
        for (let attempt = 0; attempt < 6; attempt += 1) {
          const clash = await client.query('SELECT 1 FROM turbopoder_orders WHERE code = $1 LIMIT 1', [code]);
          if (!clash.rows.length) break;
          code = orderCode();
        }

        const order = await client.query(
          'INSERT INTO turbopoder_orders (code, store_id, buyer_id, buyer_name, buyer_email, buyer_phone, address, note, subtotal, shipping, total, status) ' +
          "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'pendiente') RETURNING *",
          [code, group.storeId, buyerId, buyerName, buyerEmail, buyerPhone, address, note, subtotal, shipping, total]
        );
        const orderRow = order.rows[0];

        for (const line of group.lines) {
          const stockUpdate = await client.query(
            "UPDATE turbopoder_products SET stock = stock - $1, sales = sales + $1 WHERE id = $2 AND stock >= $1 AND status = 'activo' RETURNING stock",
            [line.qty, line.row.id]
          );
          if (!stockUpdate.rows.length) throw fail(409, 'Se agotó "' + line.row.name + '" mientras confirmabas. Probá de nuevo.');
          await client.query(
            'INSERT INTO turbopoder_order_items (order_id, product_id, name, price, qty) VALUES ($1, $2, $3, $4, $5)',
            [orderRow.id, line.row.id, line.row.name, line.row.price, line.qty]
          );
        }

        created.push({
          ...mapOrder({
            ...orderRow,
            store_name: group.storeName,
            store_slug: group.storeSlug,
            store_emoji: group.storeEmoji,
            store_accent: group.storeAccent,
            items: group.lines.map(function (line) {
              return { name: line.row.name, qty: line.qty, price: line.row.price };
            })
          })
        });
      }
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK').catch(function () {});
      throw error;
    } finally {
      client.release();
    }

    res.status(201).json({
      success: true,
      orders: created,
      total: created.reduce(function (sum, order) { return sum + order.total; }, 0)
    });
  }));

  router.get('/orders/:code', wrap(async function (req, res) {
    await ensureTables();
    const code = text(req.params.code, 24).toUpperCase();
    const email = String(req.query.email || '').trim().toLowerCase();
    if (!code || !email) throw fail(400, 'Necesitamos el código del pedido y el correo de la compra.');
    const result = await pool.query(
      'SELECT o.*, s.name AS store_name, s.slug AS store_slug, s.emoji AS store_emoji, s.accent AS store_accent ' +
      'FROM turbopoder_orders o JOIN turbopoder_stores s ON s.id = o.store_id ' +
      'WHERE o.code = $1 AND LOWER(o.buyer_email) = $2 LIMIT 1',
      [code, email]
    );
    if (!result.rows.length) throw fail(404, 'No encontramos un pedido con esos datos.');
    const items = await pool.query('SELECT name, qty, price FROM turbopoder_order_items WHERE order_id = $1 ORDER BY id', [result.rows[0].id]);
    res.json({ order: mapOrder({ ...result.rows[0], items: items.rows }) });
  }));

  router.get('/orders', authRequired, wrap(async function (req, res) {
    await ensureTables();
    const user = await currentUser(req.tpUser.id);
    if (!user) throw fail(401, 'Tu sesión venció. Volvé a entrar.');
    const result = await pool.query(
      'SELECT o.*, s.name AS store_name, s.slug AS store_slug, s.emoji AS store_emoji, s.accent AS store_accent, ' +
      'COALESCE(json_agg(json_build_object(\'name\', i.name, \'qty\', i.qty, \'price\', i.price) ORDER BY i.id) FILTER (WHERE i.id IS NOT NULL), \'[]\') AS items ' +
      'FROM turbopoder_orders o JOIN turbopoder_stores s ON s.id = o.store_id ' +
      'LEFT JOIN turbopoder_order_items i ON i.order_id = o.id ' +
      'WHERE o.buyer_id = $1 OR LOWER(o.buyer_email) = LOWER($2) ' +
      'GROUP BY o.id, s.name, s.slug, s.emoji, s.accent ORDER BY o.created_at DESC LIMIT 60',
      [user.id, user.email]
    );
    res.json({ orders: result.rows.map(mapOrder) });
  }));

  /* -------------------------------- vendedor ------------------------------ */

  router.get('/seller/products', authRequired, wrap(async function (req, res) {
    await ensureTables();
    const storeId = toInt(req.query.storeId, 0);
    const values = [req.tpUser.id];
    let filter = 's.owner_id = $1';
    if (storeId) {
      values.push(storeId);
      filter += ' AND p.store_id = $2';
    }
    const result = await pool.query(
      'SELECT p.*, s.slug AS store_slug, s.name AS store_name, s.emoji AS store_emoji, s.accent AS store_accent, ' +
      '(SELECT COUNT(*) FROM turbopoder_reviews r WHERE r.product_id = p.id)::int AS review_count, ' +
      'COALESCE((SELECT ROUND(AVG(r.rating)::numeric, 1) FROM turbopoder_reviews r WHERE r.product_id = p.id), 0) AS avg_rating ' +
      'FROM turbopoder_products p JOIN turbopoder_stores s ON s.id = p.store_id ' +
      'WHERE ' + filter + ' ORDER BY p.created_at DESC LIMIT 300',
      values
    );
    res.json({ products: result.rows.map(mapProduct) });
  }));

  router.get('/seller/summary', authRequired, wrap(async function (req, res) {
    await ensureTables();
    const stores = await pool.query(
      'SELECT s.*, ' +
      '(SELECT COUNT(*) FROM turbopoder_products p WHERE p.store_id = s.id)::int AS products, ' +
      '(SELECT COUNT(*) FROM turbopoder_orders o WHERE o.store_id = s.id)::int AS orders, ' +
      "(SELECT COUNT(*) FROM turbopoder_orders o WHERE o.store_id = s.id AND o.status = 'pendiente')::int AS pending, " +
      "COALESCE((SELECT SUM(o.total) FROM turbopoder_orders o WHERE o.store_id = s.id AND o.status <> 'cancelado'), 0) AS revenue " +
      'FROM turbopoder_stores s WHERE s.owner_id = $1 ORDER BY s.created_at DESC',
      [req.tpUser.id]
    );

    const mapped = stores.rows.map(function (row) {
      return {
        ...mapStore(row),
        products: Number(row.products || 0),
        orders: Number(row.orders || 0),
        pending: Number(row.pending || 0),
        revenue: sqlMoney(row.revenue)
      };
    });

    res.json({
      stores: mapped,
      totals: {
        stores: mapped.length,
        products: mapped.reduce(function (sum, s) { return sum + s.products; }, 0),
        orders: mapped.reduce(function (sum, s) { return sum + s.orders; }, 0),
        pending: mapped.reduce(function (sum, s) { return sum + s.pending; }, 0),
        revenue: mapped.reduce(function (sum, s) { return sum + s.revenue; }, 0)
      }
    });
  }));

  router.get('/seller/orders', authRequired, wrap(async function (req, res) {
    await ensureTables();
    const status = text(req.query.status, 24);
    const storeId = toInt(req.query.storeId, 0);
    const values = [req.tpUser.id];
    const filters = ['s.owner_id = $1'];
    if (status && ORDER_STATUSES.indexOf(status) !== -1) {
      values.push(status);
      filters.push('o.status = $' + values.length);
    }
    if (storeId) {
      values.push(storeId);
      filters.push('o.store_id = $' + values.length);
    }

    const result = await pool.query(
      'SELECT o.*, s.name AS store_name, s.slug AS store_slug, s.emoji AS store_emoji, s.accent AS store_accent, ' +
      'COALESCE(json_agg(json_build_object(\'name\', i.name, \'qty\', i.qty, \'price\', i.price) ORDER BY i.id) FILTER (WHERE i.id IS NOT NULL), \'[]\') AS items ' +
      'FROM turbopoder_orders o JOIN turbopoder_stores s ON s.id = o.store_id ' +
      'LEFT JOIN turbopoder_order_items i ON i.order_id = o.id ' +
      'WHERE ' + filters.join(' AND ') + ' ' +
      'GROUP BY o.id, s.name, s.slug, s.emoji, s.accent ORDER BY o.created_at DESC LIMIT 80',
      values
    );
    res.json({ orders: result.rows.map(mapOrder) });
  }));

  router.patch('/orders/:id/status', authRequired, wrap(async function (req, res) {
    await ensureTables();
    const orderId = toInt(req.params.id, 0);
    const status = text(req.body && req.body.status, 24);
    if (!orderId) throw fail(400, 'Pedido inválido.');
    if (ORDER_STATUSES.indexOf(status) === -1) throw fail(400, 'Ese estado no existe.');

    const owned = await pool.query(
      'SELECT o.* FROM turbopoder_orders o JOIN turbopoder_stores s ON s.id = o.store_id WHERE o.id = $1 AND s.owner_id = $2 LIMIT 1',
      [orderId, req.tpUser.id]
    );
    if (!owned.rows.length) throw fail(403, 'Ese pedido no pertenece a tus tiendas.');
    const current = owned.rows[0];
    if (current.status === status) return res.json({ success: true, status: status });

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('UPDATE turbopoder_orders SET status = $1 WHERE id = $2', [status, orderId]);
      if (status === 'cancelado' && current.status !== 'cancelado') {
        const items = await client.query('SELECT product_id, qty FROM turbopoder_order_items WHERE order_id = $1', [orderId]);
        for (const item of items.rows) {
          if (!item.product_id) continue;
          await client.query(
            'UPDATE turbopoder_products SET stock = stock + $1, sales = GREATEST(0, sales - $1) WHERE id = $2',
            [item.qty, item.product_id]
          );
        }
      }
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK').catch(function () {});
      throw error;
    } finally {
      client.release();
    }
    res.json({ success: true, status: status });
  }));

  console.log('[TURBOPODER] API montada en /turbopoder');
}
