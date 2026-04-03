import dotenv from "dotenv";
dotenv.config();

// 1Ã¯Â¸ÂÃ¢Æ’Â£ DespuÃƒÂ©s el resto
import express from "express";
import cors from "cors";
import pg from "pg";
import multer from "multer";
import bcrypt from "bcrypt";
import path from "path";
import fs from "fs";
import jwt from 'jsonwebtoken';
import { Server } from 'socket.io';
import { createServer } from 'http';

// URL FOR THIS DATABASE: https://owsdatabase.onrender.com
// Last deployment trigger: 2026-03-16T00:00 - ensureProjectChangelogSync lee de DB en vez de OWS_PROJECT_RELEASE_SOURCES

/* ===== NAT-MARKET VARS ===== */
import { v2 as cloudinary } from 'cloudinary';
import { CloudinaryStorage } from 'multer-storage-cloudinary';
import { MercadoPagoConfig, Preference } from 'mercadopago';

// ConfiguraciÃƒÂ³n de MercadoPago
const MP_ACCESS_TOKEN = process.env.MP_ACCESS_TOKEN || 'APP_USR-5761093164230281-020117-8a36b5725093b330c07cf54699b7edb1-3171975745';
const mpClient = new MercadoPagoConfig({ accessToken: MP_ACCESS_TOKEN }); // PRODUCCIÃƒâ€œN
// const mpClient = new MercadoPagoConfig({ accessToken: 'TEST-5761093164230281-020117-88b51453f4f07dd0e52e6ae5bb580609-3171975745' }); // PRUEBA (Comentado)

/* ===== NAT-MARKET VARS ===== */
let storage;
const uploadDir = path.join(process.cwd(), 'uploads');

// HARDCODED CREDENTIALS (TEMPORAL - Para asegurar que funcione en Render)
const CLOUD_NAME = 'dwoxdneqa';
const API_KEY = '572422228753764';
const API_SECRET = 'ORuFuHJqy82NxGlHshZo3SBrC8E';

// ConfiguraciÃƒÂ³n INCONDICIONAL de Cloudinary
cloudinary.config({
  cloud_name: CLOUD_NAME,
  api_key: API_KEY,
  api_secret: API_SECRET
});

storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'natmarket',
    allowed_formats: ['jpg', 'png', 'jpeg', 'webp'],
    transformation: [{ width: 1000, crop: "limit" }]
  },
});
console.log('Ã¢ËœÂÃ¯Â¸Â Usando Cloudinary (Hardcoded) para almacenamiento de imÃƒÂ¡genes');

const upload = multer({ storage });

// WildWave avatar uploads (Cloudinary)
const wildwaveAvatarStorage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'wildwave/avatars',
    allowed_formats: ['jpg', 'png', 'jpeg', 'webp'],
    transformation: [{ width: 512, height: 512, crop: 'fill', gravity: 'face' }]
  },
});
const wildwaveAvatarUpload = multer({ storage: wildwaveAvatarStorage });

// WildWave post media uploads (Cloudinary)
const wildwavePostStorage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'wildwave/posts',
    allowed_formats: ['jpg', 'png', 'jpeg', 'webp'],
    transformation: [{ width: 1600, crop: 'limit' }]
  },
});
const wildwavePostUpload = multer({ storage: wildwavePostStorage });

// WildWave video uploads (Cloudinary) — resource_type auto detecta video
const wildwaveVideoStorage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'wildwave/videos',
    resource_type: 'video',
    allowed_formats: ['mp4', 'mov', 'webm'],
    transformation: [{ width: 1280, crop: 'limit', quality: 'auto' }]
  },
});
const wildwaveVideoUpload = multer({
  storage: wildwaveVideoStorage,
  limits: { fileSize: 100 * 1024 * 1024 } // 100 MB máximo
});

// FunciÃƒÂ³n para generar ID ÃƒÂºnico de usuario (100 caracteres)
function generateUserUniqueId() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < 100; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// FunciÃƒÂ³n para generar datos de tarjeta
function generateCardDetails() {
  let cardNumber = '';
  for (let i = 0; i < 16; i++) {
    cardNumber += Math.floor(Math.random() * 10).toString();
  }
  let cvv = '';
  for (let i = 0; i < 3; i++) {
    cvv += Math.floor(Math.random() * 10).toString();
  }
  const now = new Date();
  const month = (now.getMonth() + 1).toString().padStart(2, '0');
  const year = (now.getFullYear() + 3).toString().slice(-2);
  const expiryDate = `${month}/${year}`;

  return { cardNumber, cvv, expiryDate };
}

const { Pool } = pg;
const pool = new Pool(
  process.env.DATABASE_URL
    ? {
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false }
    }
    : {
      user: process.env.PGUSER,
      host: process.env.PGHOST,
      database: process.env.PGDATABASE,
      password: process.env.PGPASSWORD,
      port: process.env.PGPORT,
      ssl: false
    }
);

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

const corsOptions = {
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['X-WT-Reward-Currency', 'X-WT-Reward-Amount', 'X-WT-New-Balance']
};
app.use(cors(corsOptions));
app.options(/.*/, cors(corsOptions));
app.use(express.json());

const ENABLE_LEGACY_BALANCE_RESCUE = process.env.OP_LEGACY_BALANCE_RESCUE === '1';
const USER_WALLET_TABLE = 'ocean_pay_user_balances';
const UNIFIED_WALLET_CURRENCIES = [
  'aquabux', 'appbux', 'ecoxionums', 'wildcredits', 'wildgems', 'ecobooks',
  'amber', 'nxb', 'voltbit', 'ecotokens', 'ecobits', 'mayhemcoins',
  'cosmicdust', 'ecopower', 'coralbits', 'tigrys', 'wildwavetokens',
  'relayshards', 'ecocorebits', 'tides', 'aurex'
];

// --- Ocean Pay Authentication ---
app.post('/ocean-pay/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Faltan datos' });

  try {
    // Check if user exists in OCEAN PAY USERS (Primary Source)
    const existing = await pool.query('SELECT * FROM ocean_pay_users WHERE username = $1', [username]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'El usuario ya existe en Ocean Pay. Intenta iniciar sesiÃƒÂ³n.' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const userUniqueId = generateUserUniqueId();

    // Insert into ocean_pay_users
    // We assume the table has a password column. If not, this might fail, but it's the requested source.
    // We add error handling for missing column to be safe.
    try {
      // Usar pwd_hash que es el est??ndar en la DB
      const newUser = await pool.query(
        'INSERT INTO ocean_pay_users (username, unique_id, pwd_hash, aquabux, ecoxionums, appbux) VALUES ($1, $2, $3, 0, 0, 0) RETURNING *',
        [username, userUniqueId, passwordHash]
      );
      const opUser = newUser.rows[0];

      const secret = process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret';
      const token = jwt.sign({ id: opUser.id, uid: opUser.id, username: opUser.username }, secret, { expiresIn: '7d' });

      res.json({
        success: true,
        token,
        user: { id: opUser.id, uid: opUser.id, username: opUser.username },
        ecoxionums: opUser.ecoxionums || 0
      });
    } catch (dbErr) {
      // Fallback for schema mismatch (e.g. if password column missing)
      console.error("DB Error in OceanPay Register:", dbErr);
      if (dbErr.code === '42703') { // Undefined column 'password'
        return res.status(500).json({ error: 'Error de sistema: La tabla de Ocean Pay no soporta contraseÃƒÂ±as aÃƒÂºn.' });
      }
      throw dbErr;
    }

  } catch (e) {
    console.error('Register error:', e);
    res.status(500).json({ error: 'Error al registrar usuario' });
  }
});

// Endpoint to get current user info (AquaBux, etc.)
// [DUPLICATE ENDPOINT REMOVED] - Redirecting to line ~10663 implementation

app.post('/ocean-pay/login', async (req, res) => {
  let { username, password } = req.body;

  username = username?.trim();
  password = password?.trim();

  if (!username || !password) return res.status(400).json({ error: 'Faltan credenciales.' });

  try {
    console.log(`Login attempt for: "${username}"`);

    // CASE INSENSITIVE SEARCH in ocean_pay_users
    const opRes = await pool.query('SELECT * FROM ocean_pay_users WHERE LOWER(username) = LOWER($1)', [username]);
    let opUser = opRes.rows[0];

    if (!opUser) {
      // Debug fallback: Is it in users_nat? (Just to inform user, not to log in if strict)
      const natCheck = await pool.query('SELECT * FROM users_nat WHERE LOWER(username) = LOWER($1)', [username]);
      if (natCheck.rows.length > 0) {
        console.log(`User ${username} found in users_nat but NOT ocean_pay_users.`);
        return res.status(404).json({ error: 'Usuario encontrado en sistema antiguo (users_nat) pero no en Ocean Pay. Contacta soporte.' });
      }
      return res.status(404).json({ error: 'Usuario no encontrado en Ocean Pay.' });
    }

    // Resolve password field
    const dbPass = opUser.pwd_hash || opUser.password || opUser.password_hash || opUser.pass;

    let match = false;

    // --- SPECIAL RECOVERY FOR OceanandWild ---
    // User cannot access because stored hash/password is likely invalid/old format.
    // If they provide the known correct password, we force access and update DB.
    if (username.toLowerCase() === 'oceanandwild' && password === '59901647') {
      console.log('RECOVERY: Force-fixing OceanandWild password.');
      const newHash = await bcrypt.hash(password, 10);

      // Update DB so next time it works normally
      try {
        await pool.query('UPDATE ocean_pay_users SET password = $1 WHERE id = $2', [newHash, opUser.id]);
      } catch (updErr) {
        console.error('Recovery Update Failed:', updErr);
      }
      match = true;
    }
    else if (dbPass) {
      // 1. Try bcrypt
      match = await bcrypt.compare(password, dbPass);
      // 2. Try plain text
      if (!match && dbPass === password) {
        match = true;
        // Optional: Upgrade to hash if plain text matched?
        // const newHash = await bcrypt.hash(password, 10);
        // await pool.query('UPDATE ocean_pay_users SET password = $1 WHERE id = $2', [newHash, opUser.id]);
      }
    } else {
      console.log(`User ${username} has no password set in DB.`);
    }

    if (match) {
      // Success
      const secret = process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret';
      const token = jwt.sign({ id: opUser.id, uid: opUser.id, username: opUser.username }, secret, { expiresIn: '7d' });

      // 1. Asegurar que el usuario tenga al menos una tarjeta principal
      const { rows: existingCards } = await pool.query('SELECT id FROM ocean_pay_cards WHERE user_id = $1', [opUser.id]);
      if (existingCards.length === 0) {
        // Generar detalles de tarjeta si no existen
        const cardNumber = '4000' + Math.random().toString().slice(2, 14);
        const cvv = Math.floor(100 + Math.random() * 900).toString();
        const expiryDate = '12/28';
        await pool.query(
          'INSERT INTO ocean_pay_cards (user_id, card_number, cvv, expiry_date, is_primary, card_name) VALUES ($1, $2, $3, $4, true, $5)',
          [opUser.id, cardNumber, cvv, expiryDate, 'Tarjeta Principal']
        );
      } else {
        // Asegurar que haya una primaria
        await pool.query(`
          UPDATE ocean_pay_cards SET is_primary = true 
          WHERE id = (SELECT MIN(id) FROM ocean_pay_cards WHERE user_id = $1)
          AND NOT EXISTS (SELECT 1 FROM ocean_pay_cards WHERE user_id = $1 AND is_primary = true)
        `, [opUser.id]);
      }

      // Fetch cards and balances (fuente unificada: ocean_pay_cards.balances)
      const { rows: cardRows } = await pool.query(
        `SELECT c.id, c.card_number, c.cvv, c.expiry_date, c.is_active, c.is_primary, c.card_name, c.balances
         FROM ocean_pay_cards c WHERE c.user_id = $1`,
        [opUser.id]
      );

      const cardsWithBalances = cardRows.map((card) => {
        const raw = card.balances || {};
        const normalized = {};
        Object.keys(raw).forEach((k) => {
          const n = Number(raw[k]);
          normalized[String(k).toLowerCase()] = Number.isFinite(n) ? n : 0;
        });
        if (normalized.tigrys === undefined) normalized.tigrys = 0;
        return { ...card, balances: normalized };
      });

      const totalEcoxionums = cardsWithBalances.reduce((sum, card) => sum + parseFloat(card.balances?.ecoxionums || 0), 0);
      const totalAquabux = cardsWithBalances.reduce((sum, card) => sum + parseFloat(card.balances?.aquabux || 0), 0);
      const aquabuxBalance = Math.max(totalAquabux, parseFloat(opUser.aquabux || 0));

      // WildCredits desde saldos de tarjeta unificados
      const totalWildCredits = cardsWithBalances.reduce((sum, card) => sum + parseFloat(card.balances?.wildcredits || 0), 0);
      const finalWildCredits = totalWildCredits;

      return res.json({
        success: true,
        token,
        ecoxionums: totalEcoxionums,
        wildcredits: finalWildCredits,
        user: {
          id: opUser.id,
          username: opUser.username,
          aquabux: aquabuxBalance,
          wildcredits: finalWildCredits,
          cards: cardsWithBalances
        }
      });
    } else {
      return res.status(401).json({ error: 'ContraseÃƒÂ±a incorrecta.' });
    }

  } catch (e) {
    console.error('Login error:', e);
    if (e.code === '42703') {
      res.status(500).json({ error: 'Error de base de datos (Columna desconocida).' });
    } else {
      res.status(500).json({ error: 'Error en el servidor' });
    }
  }
});

// === REFRESH TOKEN ENDPOINT ===
// Allows clients to silently renew an expired JWT within a 30-day grace window
app.post('/ocean-pay/refresh-token', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
    const oldToken = authHeader.substring(7);
    const secret = process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret';

    // Decode ignoring expiration to get user info
    let decoded;
    try {
      decoded = jwt.verify(oldToken, secret, { ignoreExpiration: true });
    } catch (e) {
      return res.status(401).json({ error: 'Token invÃƒÂ¡lido', code: 'INVALID_TOKEN' });
    }

    // Check grace period: only allow refresh if expired less than 30 days ago
    const expiredAt = decoded.exp ? new Date(decoded.exp * 1000) : null;
    if (expiredAt) {
      const gracePeriodMs = 30 * 24 * 60 * 60 * 1000; // 30 days
      const now = Date.now();
      if (now - expiredAt.getTime() > gracePeriodMs) {
        return res.status(401).json({ error: 'SesiÃƒÂ³n expirada hace demasiado tiempo. Inicia sesiÃƒÂ³n de nuevo.', code: 'GRACE_EXPIRED' });
      }
    }

    // Verify user still exists in DB
    const userId = decoded.id || decoded.uid;
    const { rows } = await pool.query('SELECT id, username FROM ocean_pay_users WHERE id = $1', [userId]);
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Usuario no encontrado', code: 'USER_NOT_FOUND' });
    }

    const user = rows[0];
    const newToken = jwt.sign({ id: user.id, uid: user.id, username: user.username }, secret, { expiresIn: '7d' });

    console.log(`Ã°Å¸â€â€ž Token refreshed for user: ${user.username} (ID: ${user.id})`);

    res.json({
      success: true,
      token: newToken,
      user: { id: user.id, username: user.username }
    });

  } catch (e) {
    console.error('Refresh token error:', e);
    res.status(500).json({ error: 'Error al renovar sesiÃƒÂ³n' });
  }
});

function getTigerTasksUserFromAuthHeader(authHeader) {
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  try {
    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    const tigerUserId = Number(decoded.tid || 0);
    if (!Number.isFinite(tigerUserId) || tigerUserId <= 0) return null;
    return { id: tigerUserId, username: decoded.username || '' };
  } catch (_e) {
    return null;
  }
}

app.post('/tigertasks/auth/register', async (req, res) => {
  try {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '').trim();
    if (!username || !password) return res.status(400).json({ error: 'Faltan credenciales' });
    if (username.length < 3) return res.status(400).json({ error: 'Usuario demasiado corto' });
    if (password.length < 4) return res.status(400).json({ error: 'Contrase?a demasiado corta' });

    const { rows: exists } = await pool.query(
      'SELECT id FROM tiger_tasks_users WHERE LOWER(username)=LOWER($1) LIMIT 1',
      [username]
    );
    if (exists.length) return res.status(400).json({ error: 'La cuenta Tiger Tasks ya existe' });

    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      `INSERT INTO tiger_tasks_users (username, pwd_hash)
       VALUES ($1, $2)
       RETURNING id, username`,
      [username, hash]
    );
    const user = rows[0];
    const token = jwt.sign(
      { tid: user.id, username: user.username, source: 'tigertasks' },
      process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret',
      { expiresIn: '7d' }
    );
    res.json({ success: true, token, user: { id: user.id, username: user.username } });
  } catch (e) {
    console.error('TigerTasks register error:', e);
    res.status(500).json({ error: 'Error al registrar cuenta Tiger Tasks' });
  }
});

app.post('/tigertasks/auth/login', async (req, res) => {
  try {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '').trim();
    if (!username || !password) return res.status(400).json({ error: 'Faltan credenciales' });

    const { rows } = await pool.query(
      'SELECT id, username, pwd_hash FROM tiger_tasks_users WHERE LOWER(username)=LOWER($1) LIMIT 1',
      [username]
    );
    if (!rows.length) return res.status(404).json({ error: 'Cuenta Tiger Tasks no encontrada' });
    const user = rows[0];
    const ok = await bcrypt.compare(password, user.pwd_hash || '');
    if (!ok) return res.status(401).json({ error: 'Contrase?a incorrecta' });

    const token = jwt.sign(
      { tid: user.id, username: user.username, source: 'tigertasks' },
      process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret',
      { expiresIn: '7d' }
    );
    res.json({ success: true, token, user: { id: user.id, username: user.username } });
  } catch (e) {
    console.error('TigerTasks login error:', e);
    res.status(500).json({ error: 'Error al iniciar sesi?n Tiger Tasks' });
  }
});

app.post('/tigertasks/link/oceanpay', async (req, res) => {
  const tigerUser = getTigerTasksUserFromAuthHeader(req.headers.authorization);
  if (!tigerUser) return res.status(401).json({ error: 'Token Tiger Tasks requerido' });
  const oceanUsername = String(req.body?.oceanUsername || '').trim();
  const oceanPassword = String(req.body?.oceanPassword || '').trim();
  if (!oceanUsername || !oceanPassword) return res.status(400).json({ error: 'Credenciales de Ocean Pay requeridas' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows: opRows } = await client.query(
      'SELECT id, username, pwd_hash FROM ocean_pay_users WHERE LOWER(username)=LOWER($1) LIMIT 1',
      [oceanUsername]
    );
    if (!opRows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Cuenta Ocean Pay no encontrada' });
    }
    const opUser = opRows[0];
    const ok = await bcrypt.compare(oceanPassword, String(opUser.pwd_hash || ''));
    if (!ok) {
      await client.query('ROLLBACK');
      return res.status(401).json({ error: 'Contrase?a de Ocean Pay incorrecta' });
    }

    await client.query(
      `INSERT INTO tiger_tasks_oceanpay_links (tiger_user_id, ocean_pay_user_id)
       VALUES ($1, $2)
       ON CONFLICT (tiger_user_id)
       DO UPDATE SET ocean_pay_user_id = EXCLUDED.ocean_pay_user_id, linked_at = NOW()`,
      [tigerUser.id, opUser.id]
    );
    await client.query('COMMIT');

    const oceanPayToken = jwt.sign(
      { id: opUser.id, uid: opUser.id, username: opUser.username },
      process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret',
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      oceanPayToken,
      oceanPayUser: { id: opUser.id, username: opUser.username }
    });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('TigerTasks link OceanPay error:', e);
    res.status(500).json({ error: 'No se pudo vincular Ocean Pay' });
  } finally {
    client.release();
  }
});

import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function getLocalProjectVersion(relPath, fallback = '0.0.0') {
  try {
    const packagePath = join(__dirname, relPath);
    const raw = fs.readFileSync(packagePath, 'utf8');
    const parsed = JSON.parse(raw);
    const version = String(parsed?.version || '').trim();
    return version || fallback;
  } catch (_) {
    return fallback;
  }
}

const OCEAN_PAY_LOCAL_VERSION = getLocalProjectVersion('Ocean Pay/package.json', '0.0.0');

/* ========== OWS STORE HELPERS (SEED + CHANGELOG SYNC) ========== */
const OWS_ADMIN_SECRET = process.env.OWS_ADMIN_SECRET || process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret';

const OWS_PROJECT_RELEASE_SOURCES = [
  { slug: 'ows-store', name: 'OWS Store', repo: 'OceanandWild/owsdatabase', defaultPlatforms: ['windows', 'android'] },
  { slug: 'wildweapon-mayhem', name: 'WildWeapon Mayhem', repo: 'OceanandWild/wildweapon-mayhem', defaultPlatforms: ['windows'] },
  { slug: 'savagespaceanimals', name: 'Savage Space Animals', repo: 'OceanandWild/savagespaceanimals', defaultPlatforms: ['windows'] },
  { slug: 'oceanpay', name: 'Ocean Pay', repo: 'OceanandWild/oceanpay', defaultPlatforms: ['windows'] },
  { slug: 'floretshop', name: 'Floret Shop', repo: 'OceanandWild/floretshop', defaultPlatforms: ['windows', 'android'] },
  { slug: 'wildtransfer', name: 'WildTransfer', repo: 'OceanandWild/wildtransfer', defaultPlatforms: ['windows', 'android'] },
  { slug: 'velocity-surge', name: 'Velocity Surge', repo: 'OceanandWild/velocity-surge', defaultPlatforms: ['windows'] },
  { slug: 'wildwave', name: 'WildWave', repo: 'OceanandWild/wildwave', defaultPlatforms: ['windows'] },
  { slug: 'ecoxion', name: 'Ecoxion', repo: 'OceanandWild/ecoxion', defaultPlatforms: ['windows'] }
];

function normalizeNewsBoolean(value, fallback = false) {
  if (value === undefined || value === null || value === '') return Boolean(fallback);
  const v = String(value).trim().toLowerCase();
  if (['1', 'true', 'yes', 'y', 'on'].includes(v)) return true;
  if (['0', 'false', 'no', 'n', 'off'].includes(v)) return false;
  return Boolean(fallback);
}

function normalizeNewsNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : Number(fallback || 0);
}

function requireOwsStoreAdmin(req, res) {
  const provided = String(
    req.headers['x-ows-admin-token']
    || req.headers['x-admin-secret']
    || req.query?.admin_token
    || req.body?.admin_token
    || ''
  ).trim();
  if (!provided || provided !== OWS_ADMIN_SECRET) {
    res.status(401).json({ error: 'No autorizado' });
    return false;
  }
  return true;
}

function toNewsArray(value) {
  if (Array.isArray(value)) {
    return value.map((v) => String(v || '').trim()).filter(Boolean);
  }
  if (typeof value === 'string') {
    const raw = value.trim();
    if (!raw) return [];
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) return parsed.map((v) => String(v || '').trim()).filter(Boolean);
    } catch (_) {
      // no-op: fallback a split por l?neas
    }
    return raw
      .split(/\r?\n/)
      .map((line) => line.replace(/^\s*[-*?]+\s*/, '').trim())
      .filter(Boolean);
  }
  return [];
}

const OWS_TIMELINE_ENTRY_TYPES = new Set(['changelog', 'event', 'news', 'banner']);

function normalizeTimelineEntryType(value, fallback = 'changelog') {
  const raw = String(value || fallback || 'changelog').trim().toLowerCase();
  return OWS_TIMELINE_ENTRY_TYPES.has(raw) ? raw : String(fallback || 'changelog');
}

function normalizeProjectSlug(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function normalizeTimelineProjectRefs(projectNames = [], explicitSlugs = []) {
  const names = toNewsArray(projectNames);
  const slugSet = new Set(
    toNewsArray(explicitSlugs)
      .map((x) => normalizeProjectSlug(x))
      .filter(Boolean)
  );
  names.forEach((name) => {
    const slug = normalizeProjectSlug(name);
    if (slug) slugSet.add(slug);
  });
  return {
    projectNames: names,
    projectSlugs: [...slugSet]
  };
}

function normalizeTimelineLines(value) {
  return toNewsArray(value).slice(0, 30);
}

function normalizeOwsNewsRow(row) {
  const safe = row || {};
  const title = String(safe.title || '').trim();
  const description = String(safe.description || '').trim();
  const projectNames = Array.isArray(safe.project_names) ? safe.project_names.map((x) => String(x || '').trim()).filter(Boolean) : [];
  const projectSlugs = Array.isArray(safe.project_slugs) ? safe.project_slugs.map((x) => normalizeProjectSlug(x)).filter(Boolean) : [];
  const platforms = Array.isArray(safe.platforms) ? safe.platforms.map((x) => String(x || '').trim().toLowerCase()).filter(Boolean) : [];
  const details = (safe.details && typeof safe.details === 'object') ? safe.details : {};
  const contentLines = Array.isArray(safe.content_lines) ? normalizeTimelineLines(safe.content_lines) : [];
  const changes = contentLines.length ? contentLines : normalizeTimelineLines(details?.changes || safe.changes);
  const entryType = normalizeTimelineEntryType(safe.kind || safe.entry_type || 'changelog');
  const model2d = (safe.model_2d_payload && typeof safe.model_2d_payload === 'object')
    ? { key: safe.model_2d_key || null, ...safe.model_2d_payload }
    : { key: safe.model_2d_key || null };
  const bannerMeta = (safe.visual_meta && typeof safe.visual_meta === 'object')
    ? safe.visual_meta
    : ((safe.banner_meta && typeof safe.banner_meta === 'object') ? safe.banner_meta : {});
  const eventStart = safe.starts_at ? new Date(safe.starts_at).toISOString() : (safe.event_start ? new Date(safe.event_start).toISOString() : null);
  const eventEnd = safe.ends_at ? new Date(safe.ends_at).toISOString() : (safe.event_end ? new Date(safe.event_end).toISOString() : null);
  const publishedAt = safe.published_at ? new Date(safe.published_at).toISOString() : (safe.update_date ? new Date(safe.update_date).toISOString() : null);
  const now = Date.now();
  const startTs = eventStart ? Date.parse(eventStart) : 0;
  const endTs = eventEnd ? Date.parse(eventEnd) : 0;
  let eventPhase = null;
  if (entryType === 'event') {
    if (startTs && now < startTs) eventPhase = 'upcoming';
    else if (endTs && now > endTs) eventPhase = 'ended';
    else eventPhase = 'active';
  }

  return {
    id: safe.id,
    project_slugs: projectSlugs,
    projectSlugs,
    project_names: projectNames,
    projectNames,
    title: title || 'Sin titulo',
    description: description || (changes[0] || ''),
    changes,
    content_lines: changes,
    contentLines: changes,
    details,
    kind: entryType,
    published_at: publishedAt,
    publishedAt,
    update_date: publishedAt,
    updateDate: publishedAt,
    created_at: safe.created_at ? new Date(safe.created_at).toISOString() : null,
    createdAt: safe.created_at ? new Date(safe.created_at).toISOString() : null,
    updated_at: safe.updated_at ? new Date(safe.updated_at).toISOString() : null,
    updatedAt: safe.updated_at ? new Date(safe.updated_at).toISOString() : null,
    entry_type: entryType,
    entryType,
    platforms,
    model_2d_key: safe.model_2d_key || null,
    model_2d_payload: model2d,
    model2d,
    banner_meta: bannerMeta,
    bannerMeta,
    is_active: safe.is_active !== false,
    isActive: safe.is_active !== false,
    priority: Number(safe.priority || 0),
    event_start: eventStart,
    event_end: eventEnd,
    eventStart,
    eventEnd,
    eventWindow: { startAt: eventStart, endAt: eventEnd },
    eventPhase,
    isEvent: entryType === 'event',
    isBanner: entryType === 'banner'
  };
}

function splitReleaseBody(body = '') {
  const text = String(body || '').replace(/\r/g, '\n');
  return text
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => line.replace(/^\s*[-*?]+\s*/, '').trim())
    .filter(Boolean)
    .slice(0, 14);
}

function inferPlatformsFromReleaseAssets(assets = [], fallback = ['windows']) {
  const set = new Set();
  (Array.isArray(assets) ? assets : []).forEach((asset) => {
    const n = String(asset?.name || '').toLowerCase();
    if (n.endsWith('.apk') || n.endsWith('.aab') || n.includes('android')) set.add('android');
    if (n.endsWith('.exe') || n.endsWith('.msi') || n.endsWith('.zip') || n.includes('win')) set.add('windows');
  });
  if (!set.size) fallback.forEach((p) => set.add(String(p || '').toLowerCase()));
  return [...set].filter(Boolean);
}

async function fetchGithubLatestRelease(repo) {
  const url = `https://api.github.com/repos/${repo}/releases/latest`;
  const headers = {
    'User-Agent': 'OWS-Store-Server',
    'Accept': 'application/vnd.github+json'
  };
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || '';
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(url, { headers });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    const err = new Error(`GitHub API ${res.status} for ${repo}`);
    err.status = res.status;
    err.body = text;
    throw err;
  }
  return res.json();
}

async function upsertOwsNewsEntryBySyncKey({
  syncKey,
  projectNames,
  projectSlugs = [],
  title,
  description,
  changes,
  updateDate,
  entryType = 'changelog',
  platforms = ['windows'],
  model2dKey = null,
  model2dPayload = {},
  bannerMeta = {},
  isActive = true,
  priority = 0,
  eventStart = null,
  eventEnd = null
}) {
  const entryKind = normalizeTimelineEntryType(entryType, 'changelog');
  const refs = normalizeTimelineProjectRefs(projectNames, projectSlugs);
  const cleanChanges = normalizeTimelineLines(changes);
  const details = {
    changes: cleanChanges,
    source: 'ows_store_timeline'
  };
  const existing = await pool.query(
    `SELECT id
     FROM ows_store_timeline
     WHERE (visual_meta->>'sync_key') = $1
     LIMIT 1`,
    [syncKey]
  );

  const baseParams = [
    refs.projectSlugs,
    refs.projectNames,
    String(title || 'Actualizacion'),
    String(description || '').trim() || null,
    cleanChanges,
    details,
    updateDate ? new Date(updateDate) : new Date(),
    entryKind,
    Array.isArray(platforms) ? platforms : ['windows'],
    model2dKey || null,
    model2dPayload && typeof model2dPayload === 'object' ? model2dPayload : {},
    { ...(bannerMeta && typeof bannerMeta === 'object' ? bannerMeta : {}), sync_key: syncKey },
    Boolean(isActive),
    Number(priority || 0),
    eventStart ? new Date(eventStart) : null,
    eventEnd ? new Date(eventEnd) : null
  ];

  if (existing.rowCount > 0) {
    const { rows } = await pool.query(
      `UPDATE ows_store_timeline
       SET project_slugs = $1,
           project_names = $2,
           title = $3,
           description = $4,
           content_lines = $5,
           details = $6,
           published_at = $7,
           kind = $8,
           platforms = $9,
           model_2d_key = $10,
           model_2d_payload = $11,
           visual_meta = $12,
           is_active = $13,
           priority = $14,
           starts_at = $15,
           ends_at = $16,
           updated_at = NOW()
       WHERE id = $17
       RETURNING *`,
      [...baseParams, existing.rows[0].id]
    );
    return rows[0] || null;
  }

  const { rows } = await pool.query(
    `INSERT INTO ows_store_timeline (
       project_slugs, project_names, title, description, content_lines, details, published_at, kind, platforms,
       model_2d_key, model_2d_payload, visual_meta, is_active, priority, starts_at, ends_at
     )
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
     RETURNING *`,
    baseParams
  );
  return rows[0] || null;
}

function normalizeOwsPushPlatform(value) {
  const raw = String(value || '').trim().toLowerCase();
  if (raw === 'win' || raw === 'windows') return 'windows';
  if (raw === 'android') return 'android';
  if (raw === 'all') return 'all';
  return 'web';
}

function normalizeOwsPushProvider(value) {
  const raw = String(value || '').trim().toLowerCase();
  if (raw === 'fcm' || raw === 'firebase') return 'fcm';
  if (raw === 'wns') return 'wns';
  if (raw === 'webpush') return 'webpush';
  return 'local';
}

function buildOwsStorePushUpdateMessage({ projectName, version, changelog }) {
  const safeProject = String(projectName || 'Proyecto OWS').trim() || 'Proyecto OWS';
  const safeVersion = String(version || '').trim() || 'nueva version';
  const firstLine = String(changelog || '')
    .split(/\r?\n/)
    .map((line) => line.replace(/^\s*[-*•]+\s*/, '').trim())
    .find(Boolean) || '';
  const title = `Update disponible: ${safeProject}`;
  const body = firstLine
    ? `${safeProject} ${safeVersion}: ${firstLine}`
    : `${safeProject} actualizo a ${safeVersion}.`;
  return { title, body };
}

async function sendFcmPushNotification({ token, title, body, data = {} }) {
  const serverKey = String(process.env.FCM_SERVER_KEY || process.env.FIREBASE_SERVER_KEY || '').trim();
  const targetToken = String(token || '').trim();
  if (!serverKey || !targetToken) return { sent: false, reason: 'missing-server-key-or-token' };
  try {
    const res = await fetch('https://fcm.googleapis.com/fcm/send', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `key=${serverKey}`
      },
      body: JSON.stringify({
        to: targetToken,
        priority: 'high',
        notification: {
          title: String(title || 'OWS Store'),
          body: String(body || 'Nueva actualizacion disponible')
        },
        data: (data && typeof data === 'object') ? data : {}
      })
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      return { sent: false, reason: `fcm-http-${res.status}`, detail: text };
    }
    const json = await res.json().catch(() => ({}));
    const successCount = Number(json?.success || 0);
    if (successCount > 0) return { sent: true };
    return { sent: false, reason: 'fcm-not-accepted', detail: json };
  } catch (err) {
    return { sent: false, reason: err?.message || 'fcm-error' };
  }
}

async function queueOwsStorePushUpdate({ projectSlug, projectName, version, changelog = '' }) {
  const slug = normalizeProjectSlug(projectSlug || '') || 'ows-store';
  const safeVersion = String(version || '').trim();
  if (!safeVersion) return { queued: 0 };
  const { title, body } = buildOwsStorePushUpdateMessage({ projectName, version: safeVersion, changelog });
  const dedupeKey = `update:${slug}:${safeVersion}`;
  const payload = {
    type: 'project_update',
    project_slug: slug,
    project_name: String(projectName || slug),
    version: safeVersion,
    changelog: String(changelog || '').trim()
  };
  try {
    const devicesRes = await pool.query(
      `SELECT device_id, platform, provider, push_token
       FROM ows_store_push_devices
       WHERE is_active = TRUE
         AND device_id IS NOT NULL
         AND device_id <> ''
         AND platform IN ('all', 'windows', 'android', 'web')`
    );
    const devices = Array.isArray(devicesRes?.rows) ? devicesRes.rows : [];
    let queued = 0;
    let pushedNow = 0;

    for (const device of devices) {
      const deviceId = String(device?.device_id || '').trim();
      if (!deviceId) continue;
      const platform = normalizeOwsPushPlatform(device?.platform || 'web');
      const provider = normalizeOwsPushProvider(device?.provider || 'local');
      const pushToken = String(device?.push_token || '').trim();

      const inserted = await pool.query(
        `INSERT INTO ows_store_push_notifications (
           device_id, platform, project_slug, version, title, body, payload, dedupe_key
         )
         VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8)
         ON CONFLICT (device_id, dedupe_key) DO NOTHING
         RETURNING id`,
        [deviceId, platform, slug, safeVersion, title, body, JSON.stringify(payload), dedupeKey]
      );
      const pushId = Number(inserted?.rows?.[0]?.id || 0);
      if (!pushId) continue;
      queued += 1;

      if (provider === 'fcm' && pushToken) {
        const fcm = await sendFcmPushNotification({
          token: pushToken,
          title,
          body,
          data: {
            type: 'project_update',
            project_slug: slug,
            project_name: String(projectName || slug),
            version: safeVersion
          }
        });
        if (fcm?.sent) {
          pushedNow += 1;
          await pool.query(
            `UPDATE ows_store_push_notifications
             SET delivered_at = NOW()
             WHERE id = $1`,
            [pushId]
          ).catch(() => {});
        }
      }
    }
    return { queued, pushedNow, dedupeKey };
  } catch (err) {
    console.warn('[ows-push] No se pudo encolar update push:', err?.message || err);
    return { queued: 0, error: err?.message || 'push-queue-error' };
  }
}

async function ensureOwsStoreProjectsSeedData() {
  const forcedComingSoonNoDate = new Set(['naturepedia']);
  const seeds = [
    {
      slug: 'ows-store',
      name: 'OWS Store',
      description: 'Launcher oficial del ecosistema Ocean and Wild Studios.',
      url: 'https://github.com/OceanandWild/owsdatabase/releases/latest',
      version: '0.0.0',
      status: 'launched',
      metadata: { platforms: ['windows', 'android'], repo: 'OceanandWild/owsdatabase' }
    },
    {
      slug: 'dinobox',
      name: 'DinoBox',
      description: 'Colecciona dinosaurios, completa expediciones y progresa en el pase de temporada.',
      url: '/DinoBox/index.html',
      version: '2026.3.8-dino',
      status: 'coming_soon',
      release_date: '2026-03-11T13:00:00Z',
      metadata: { platforms: ['windows'], release_channel: 'web_local', pending_release: true }
    },
    ...OWS_PROJECT_RELEASE_SOURCES
      .filter((p) => p.slug !== 'ows-store')
      .map((p) => {
        const slug = String(p.slug || '').trim().toLowerCase();
        const isForcedComingSoon = forcedComingSoonNoDate.has(slug);
        return {
          slug: p.slug,
          name: p.name,
          description: isForcedComingSoon
            ? `${p.name} se publicara proximamente en OWS Store.`
            : `${p.name} disponible en OWS Store.`,
          url: `https://github.com/${p.repo}/releases/latest`,
          version: p.slug === 'oceanpay' ? OCEAN_PAY_LOCAL_VERSION : '0.0.0',
          status: isForcedComingSoon ? 'coming_soon' : 'launched',
          release_date: null,
          metadata: {
            platforms: p.defaultPlatforms || ['windows'],
            repo: p.repo,
            pending_release: isForcedComingSoon
          }
        };
      })
  ];

  for (const item of seeds) {
    await pool.query(
      `INSERT INTO ows_projects (slug, name, description, url, version, status, release_date, metadata)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       ON CONFLICT (slug) DO UPDATE SET
         name = EXCLUDED.name,
         description = EXCLUDED.description,
         url = EXCLUDED.url,
         status = EXCLUDED.status,
         release_date = COALESCE(EXCLUDED.release_date, ows_projects.release_date),
         metadata = ows_projects.metadata || EXCLUDED.metadata`,
      [
        item.slug,
        item.name,
        item.description,
        item.url,
        item.version,
        item.status,
        item.release_date || null,
        item.metadata || {}
      ]
    );
  }

  return { seeded: seeds.length };
}

async function ensureOwsStoreProjectOffersSeedData() {
  const seeds = [
    {
      project_slug: 'velocity-surge',
      offer_code: 'vs_elemental_starter',
      title: 'Velocity Surge - Elemental Starter',
      description: 'Pack sincronizado para evento elemental con descuento exclusivo en OWS Store.',
      currency: 'voltbit',
      base_price: 6800,
      ows_store_price: 6100,
      reward_payload: {
        event_offer: {
          id: 'sync_vs_elemental_starter',
          eventId: 'elemental_convergence',
          name: 'PACK ELEMENTAL SINCRONIZADO',
          desc: 'Desbloquea un corredor elemental elegido + 20 tarjetas.',
          type: 'early',
          gives: { character: 'elemental_pyre', cards: 20, bits: 0 },
          pool: ['elemental_aqua', 'elemental_pyre', 'elemental_gale', 'elemental_terra', 'elemental_plasma', 'elemental_crystal', 'elemental_thunder'],
          badgeText: 'OWS',
          badgeColor: '#00f7ff',
          chestType: null
        }
      },
      metadata: {
        one_time_per_user: true,
        source: 'ows_store_sync',
        visible_in_project: true
      }
    },
    {
      project_slug: 'velocity-surge',
      offer_code: 'vs_planetary_crate',
      title: 'Velocity Surge - Planetary Crate',
      description: 'Cofre planetario premium. OWS Store aplica precio promocional especial.',
      currency: 'voltbit',
      base_price: 11800,
      ows_store_price: 10400,
      reward_payload: {
        event_offer: {
          id: 'sync_vs_planetary_crate',
          eventId: 'planetary_rush',
          name: 'COFRE PLANETARIO SINCRONIZADO',
          desc: 'Cofre avanzado del corredor planetario elegido + 52 tarjetas.',
          type: 'lastchance',
          lastChanceDays: 2,
          gives: { character: 'planet_terra', cards: 52, bits: 420 },
          pool: ['planet_mercury', 'planet_venus', 'planet_terra'],
          badgeText: '-OWS',
          badgeColor: '#ffd166',
          chestType: 'event_chest_planet_terra'
        }
      },
      metadata: {
        one_time_per_user: true,
        source: 'ows_store_sync',
        visible_in_project: true
      }
    },
    {
      project_slug: 'velocity-surge',
      offer_code: 'vs_elemental_last_current',
      title: 'Velocity Surge - Ultima Corriente',
      description: 'Oferta de cierre elemental con cofre premium y cards del objetivo del evento.',
      currency: 'voltbit',
      base_price: 9800,
      ows_store_price: 9200,
      reward_payload: {
        event_offer: {
          id: 'sync_vs_elemental_last_current',
          eventId: 'elemental_convergence',
          name: 'ULTIMA CORRIENTE SINCRONIZADA',
          desc: 'Cofre elemental premium + 45 tarjetas del corredor objetivo.',
          type: 'lastchance',
          lastChanceDays: 1,
          gives: { character: 'elemental_aqua', cards: 45, bits: 300 },
          pool: ['elemental_aqua', 'elemental_pyre', 'elemental_gale', 'elemental_terra', 'elemental_plasma', 'elemental_crystal', 'elemental_thunder'],
          badgeText: '-OWS',
          badgeColor: '#ffd166',
          chestType: 'event_chest_elemental_aqua'
        }
      },
      metadata: {
        one_time_per_user: true,
        source: 'ows_store_sync',
        visible_in_project: true
      }
    },
    {
      project_slug: 'velocity-surge',
      offer_code: 'vs_planetary_inner_pack',
      title: 'Velocity Surge - Sistema Interno',
      description: 'Pack planetario de entrada para desbloqueo y progresión rápida.',
      currency: 'voltbit',
      base_price: 7600,
      ows_store_price: 6990,
      reward_payload: {
        event_offer: {
          id: 'sync_vs_planetary_inner_pack',
          eventId: 'planetary_rush',
          name: 'PACK SISTEMA INTERNO SINCRONIZADO',
          desc: 'Elige entre MERCURY, VENUS o EARTH y recibe 24 tarjetas.',
          type: 'early',
          gives: { character: 'planet_mercury', cards: 24, bits: 120 },
          pool: ['planet_mercury', 'planet_venus', 'planet_terra'],
          badgeText: 'OWS',
          badgeColor: '#7dd3fc',
          chestType: null
        }
      },
      metadata: {
        one_time_per_user: true,
        source: 'ows_store_sync',
        visible_in_project: true
      }
    },
    {
      project_slug: 'velocity-surge',
      offer_code: 'vs_cloudwing_storm_birth',
      title: 'Velocity Surge - Nacimiento de Tormenta',
      description: 'Debut de CLOUDWING con tarjetas del evento y bonus de VoltBits.',
      currency: 'voltbit',
      base_price: 6200,
      ows_store_price: 5600,
      reward_payload: {
        event_offer: {
          id: 'sync_vs_cloudwing_storm_birth',
          eventId: 'aether_wing_storm',
          name: 'PACK TORMENTA ALADA SINCRONIZADO',
          desc: 'Desbloquea CLOUDWING y recibe 30 tarjetas del evento.',
          type: 'early',
          gives: { character: 'cloudwing', cards: 30, bits: 260 },
          badgeText: 'OWS',
          badgeColor: '#b7e7ff',
          chestType: null
        }
      },
      metadata: {
        one_time_per_user: true,
        source: 'ows_store_sync',
        visible_in_project: true
      }
    },
    {
      project_slug: 'velocity-surge',
      offer_code: 'vs_replica_crimson_cache',
      title: 'Velocity Surge - Replica Crimson Cache',
      description: 'Cofre oscuro del corredor Replica con rango variable de tarjetas y precio exclusivo en OWS Store.',
      currency: 'voltbit',
      base_price: 8900,
      ows_store_price: 7800,
      reward_payload: {
        event_offer: {
          id: 'sync_vs_replica_crimson_cache',
          eventId: 'elemental_convergence',
          name: 'REPLICA CRIMSON CACHE',
          desc: 'Cofre de Replica con entre 25 y 50 tarjetas por compra.',
          type: 'early',
          gives: {
            character: 'replica',
            cards: 25,
            cardsRange: { min: 25, max: 50 },
            bits: 0
          },
          badgeText: 'CHEST',
          badgeColor: '#ff5a96',
          chestType: 'event_chest_replica'
        }
      },
      metadata: {
        one_time_per_user: false,
        max_purchases_per_user: 3,
        source: 'ows_store_sync',
        visible_in_project: true,
        visual_key: 'chest_replica',
        illustration_primary: '#ff5a96',
        illustration_secondary: '#7a244e'
      }
    },
    {
      project_slug: 'velocity-surge',
      offer_code: 'vs_umbra_abyss_cache',
      title: 'Velocity Surge - Umbra Abyss Cache',
      description: 'Cofre elite de Umbra Reaper con recompensa variable de tarjetas por compra.',
      currency: 'voltbit',
      base_price: 9400,
      ows_store_price: 8200,
      reward_payload: {
        event_offer: {
          id: 'sync_vs_umbra_abyss_cache',
          eventId: 'elemental_convergence',
          name: 'UMBRA ABYSS CACHE',
          desc: 'Cofre de Umbra Reaper con entre 25 y 50 tarjetas por compra.',
          type: 'lastchance',
          gives: {
            character: 'umbra_reaper',
            cards: 25,
            cardsRange: { min: 25, max: 50 },
            bits: 0
          },
          badgeText: 'CHEST',
          badgeColor: '#9a6bff',
          chestType: 'event_chest_umbra_reaper'
        }
      },
      metadata: {
        one_time_per_user: false,
        max_purchases_per_user: 3,
        source: 'ows_store_sync',
        visible_in_project: true,
        visual_key: 'chest_umbra',
        illustration_primary: '#9a6bff',
        illustration_secondary: '#2f2352'
      }
    },
    {
      project_slug: 'velocity-surge',
      offer_code: 'vs_core_vault_weekly',
      title: 'Velocity Surge - Core Vault Weekly',
      description: 'Oferta recurrente de recursos para acelerar mejoras en carrera.',
      currency: 'voltbit',
      base_price: 3400,
      ows_store_price: 3200,
      reward_payload: {
        event_offer: {
          id: 'sync_vs_core_vault_weekly',
          eventId: 'elemental_convergence',
          name: 'CORE VAULT',
          desc: 'Pack de apoyo con cards y VoltBits para progresión rápida.',
          type: 'early',
          gives: { character: 'storm', cards: 12, bits: 220 },
          pool: ['storm', 'elemental_thunder', 'elemental_aqua'],
          badgeText: 'WEEKLY',
          badgeColor: '#52d9df',
          chestType: null
        }
      },
      metadata: {
        one_time_per_user: false,
        source: 'ows_store_sync',
        visible_in_project: true
      }
    }
  ];

  let seeded = 0;
  for (const item of seeds) {
    await pool.query(
      `INSERT INTO ows_project_offers (
         project_slug, offer_code, title, description, currency,
         base_price, ows_store_price, reward_payload, metadata, is_active
       )
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,TRUE)
       ON CONFLICT (project_slug, offer_code) DO UPDATE SET
         title = EXCLUDED.title,
         description = EXCLUDED.description,
         currency = EXCLUDED.currency,
         base_price = EXCLUDED.base_price,
         ows_store_price = EXCLUDED.ows_store_price,
         reward_payload = ows_project_offers.reward_payload || EXCLUDED.reward_payload,
         metadata = ows_project_offers.metadata || EXCLUDED.metadata,
         updated_at = NOW()`,
      [
        item.project_slug,
        item.offer_code,
        item.title,
        item.description,
        item.currency,
        item.base_price,
        item.ows_store_price,
        item.reward_payload || {},
        item.metadata || {}
      ]
    );
    seeded += 1;
  }

  return { seeded };
}

async function ensureOwsStoreNewsSeedData() {
  const now = new Date();
  const oneDayMs = 24 * 60 * 60 * 1000;
  const toIsoOrNull = (value) => {
    if (!value) return null;
    const d = new Date(value);
    return Number.isFinite(d.getTime()) ? d.toISOString() : null;
  };

  const releaseDateBySlug = new Map();
  try {
    const trackedSlugs = ['ecoxion', 'wild-destiny', 'wildshorts'];
    const { rows } = await pool.query(
      `SELECT LOWER(slug) AS slug, release_date
       FROM ows_projects
       WHERE LOWER(slug) = ANY($1::text[])`,
      [trackedSlugs]
    );
    rows.forEach((row) => {
      const slug = String(row?.slug || '').trim().toLowerCase();
      if (!slug) return;
      const iso = toIsoOrNull(row?.release_date);
      if (iso) releaseDateBySlug.set(slug, iso);
    });
  } catch (err) {
    console.log('[OWS] No se pudieron leer release_date de eventos seed:', err?.message || err);
  }

  const wildShortsReleaseFromDb = releaseDateBySlug.get('wildshorts');
  if (!wildShortsReleaseFromDb) {
    try {
      const wsRelease = await fetchGithubLatestRelease('OceanandWild/wildshorts');
      const wsReleaseDate = toIsoOrNull(wsRelease?.published_at || wsRelease?.created_at || null);
      if (wsReleaseDate) releaseDateBySlug.set('wildshorts', wsReleaseDate);
    } catch (_err) {
      // fallback silencioso: si no hay release, usamos ventana relativa.
    }
  }

  const ecoxionStart = releaseDateBySlug.get('ecoxion') || new Date(now.getTime() - (35 * oneDayMs)).toISOString();
  const ecoxionEnd = new Date(now.getTime() - (3 * oneDayMs)).toISOString();
  const wildDestinyStart = releaseDateBySlug.get('wild-destiny') || new Date(now.getTime() - (28 * oneDayMs)).toISOString();
  const wildDestinyEnd = new Date(now.getTime() - (2 * oneDayMs)).toISOString();
  const wildShortsStart = releaseDateBySlug.get('wildshorts') || new Date(now.getTime() + (6 * oneDayMs)).toISOString();
  const wildShortsEnd = new Date((Date.parse(wildShortsStart) || now.getTime()) + (14 * oneDayMs)).toISOString();

  const entries = [
    {
      syncKey: 'seed:ows-store:welcome',
      projectNames: ['ows-store', 'OWS Store'],
      title: 'OWS Store centraliza noticias, changelogs y eventos',
      description: 'La informacion global del ecosistema ahora vive dentro de OWS Store.',
      changes: [
        'Noticias globales integradas',
        'Eventos destacados con ventana de tiempo',
        'Changelogs por proyecto con plataforma'
      ],
      updateDate: now,
      entryType: 'changelog',
      platforms: ['windows', 'android'],
      model2dKey: 'store_hub',
      model2dPayload: { palette: 'cyan-orange' },
      bannerMeta: { visual: 'store_hub', importance: 'high' },
      isActive: true,
      priority: 10
    },
    {
      syncKey: 'seed:dinobox:launch',
      projectNames: ['dinobox', 'DinoBox'],
      title: 'DinoBox - lanzamiento programado en OWS Store',
      description: 'DinoBox queda programado para lanzamiento en 3 dias dentro de OWS Store.',
      changes: [
        'Ficha de DinoBox habilitada en OWS Store con countdown activo.',
        'Prelanzamiento marcado como coming_soon para evitar instalacion anticipada.',
        'Lanzamiento oficial previsto para 2026-03-11 10:00 (Uruguay).'
      ],
      updateDate: now,
      entryType: 'changelog',
      platforms: ['windows'],
      model2dKey: 'launch_orbit',
      model2dPayload: { accent: '#f59e0b' },
      bannerMeta: { visual: 'launch_orbit', category: 'launch' },
      isActive: true,
      priority: 11
    },
    {
      syncKey: 'seed:event:wild-destiny-launch',
      projectNames: ['wild-destiny', 'Wild Destiny'],
      title: 'Wild Destiny - Evento de lanzamiento',
      description: 'Evento de lanzamiento oficial de Wild Destiny en OWS Store para Windows.',
      changes: [
        'Ventana de lanzamiento cerrada y marcada como finalizada.',
        'Tarjeta de evento con visual renovado para mejor lectura en el hub.'
      ],
      updateDate: wildDestinyStart,
      entryType: 'event',
      platforms: ['windows'],
      model2dKey: 'wild_destiny_event',
      model2dPayload: { accent: '#00f3ff', secondary: '#7b61ff' },
      bannerMeta: { visual: 'wild_destiny_event', category: 'launch' },
      isActive: true,
      priority: 14,
      eventStart: wildDestinyStart,
      eventEnd: wildDestinyEnd
    },
    {
      syncKey: 'seed:event:ecoxion-launch',
      projectNames: ['ecoxion', 'Ecoxion'],
      title: 'Ecoxion: lanzamiento a Windows en OWS Store',
      description: 'Evento de lanzamiento de Ecoxion en OWS Store.',
      changes: [
        'Evento historico marcado como finalizado.',
        'Se agrega ventana de cierre para estado consistente en el panel de eventos.'
      ],
      updateDate: ecoxionStart,
      entryType: 'event',
      platforms: ['windows'],
      model2dKey: 'ecoxion_event',
      model2dPayload: { accent: '#00c7ff', secondary: '#7fffd4' },
      bannerMeta: { visual: 'ecoxion_event', category: 'launch' },
      isActive: true,
      priority: 15,
      eventStart: ecoxionStart,
      eventEnd: ecoxionEnd
    },
    {
      syncKey: 'seed:event:wildshorts-launch-window',
      projectNames: ['wildshorts', 'WildShorts'],
      title: 'WildShorts - ventana de lanzamiento',
      description: 'Lanzamiento confirmado de WildShorts con ventana de evento definida.',
      changes: [
        'Fecha de inicio alineada con la fecha de lanzamiento del proyecto.',
        'Fecha de cierre asignada para seguimiento claro del evento en OWS Store.'
      ],
      updateDate: wildShortsStart,
      entryType: 'event',
      platforms: ['windows'],
      model2dKey: 'wildshorts_event',
      model2dPayload: { accent: '#34d2ff', secondary: '#ffb067' },
      bannerMeta: { visual: 'wildshorts_event', category: 'launch' },
      isActive: true,
      priority: 13,
      eventStart: wildShortsStart,
      eventEnd: wildShortsEnd
    },
    {
      syncKey: 'seed:oceanpay:ecoxion-integration-pack',
      projectNames: ['oceanpay', 'Ocean Pay', 'Ecoxion'],
      title: 'Ocean Pay + Ecoxion: integracion ampliada',
      description: 'Ocean Pay refuerza el flujo de Ecoxion con mejor sincronizacion de saldo, suscripciones y compatibilidad.',
      changes: [
        'Unificacion de persistencia de saldo sobre tarjetas (ocean_pay_cards.balances) para Ecoxionums.',
        'Mejoras en sincronizacion de Ecoxionums entre app y servidor con trazabilidad de transacciones.',
        'Suscripciones de Ecoxion alineadas con Ocean Pay y renovacion/estado consistente.',
        'Compatibilidad reforzada para lectura de saldos legacy sin romper el flujo actual.',
        'Ajustes de estabilidad para que OWS Store consuma changelogs/eventos de forma centralizada por API.'
      ],
      updateDate: now,
      entryType: 'changelog',
      platforms: ['windows', 'android'],
      model2dKey: 'currency_sync',
      model2dPayload: { accent: '#22d3ee', secondary: '#8b5cf6' },
      bannerMeta: { visual: 'currency_sync', category: 'changelog', focus: 'ecoxion' },
      isActive: true,
      priority: 11
    }
  ];

  let count = 0;
  for (const item of entries) {
    await upsertOwsNewsEntryBySyncKey(item);
    count++;
  }
  return { seeded: count };
}

async function ensureProjectChangelogSync({ force = false, projectSlug = '' } = {}) {
  const slugFilter = String(projectSlug || '').trim().toLowerCase();

  // Lee proyectos desde la DB en vez del array hardcodeado OWS_PROJECT_RELEASE_SOURCES.
  // Asi cualquier proyecto registrado via POST /ows-store/projects queda automaticamente
  // sincronizado sin necesidad de modificar el codigo.
  let dbRows = [];
  try {
    const { rows } = await pool.query(
      `SELECT slug, name, metadata FROM ows_projects WHERE status != 'unavailable' ORDER BY slug`
    );
    dbRows = rows;
  } catch (err) {
    console.warn('[changelog-sync] No se pudo leer ows_projects, usando OWS_PROJECT_RELEASE_SOURCES como fallback:', err?.message);
    dbRows = OWS_PROJECT_RELEASE_SOURCES.map((s) => ({
      slug: s.slug,
      name: s.name,
      metadata: { repo: s.repo, platforms: s.defaultPlatforms || ['windows'] }
    }));
  }

  // Filtrar por slug si se pidio uno especifico
  const sources = dbRows
    .filter((row) => {
      if (!slugFilter) return true;
      return String(row.slug || '').toLowerCase() === slugFilter ||
             String(row.name || '').toLowerCase() === slugFilter;
    })
    .map((row) => {
      const meta = (row.metadata && typeof row.metadata === 'object') ? row.metadata : {};
      const repoRaw = String(meta.repo || '').trim();
      // Normalizar: si viene como "OceanandWild/slug" usar tal cual, si es solo "slug" agregar org
      const repo = repoRaw.includes('/') ? repoRaw : (repoRaw ? `OceanandWild/${repoRaw}` : '');
      return {
        slug: String(row.slug || '').trim(),
        name: String(row.name || '').trim(),
        repo,
        defaultPlatforms: Array.isArray(meta.platforms) ? meta.platforms : ['windows']
      };
    })
    .filter((s) => s.slug && s.repo); // Solo proyectos con repo configurado

  const summary = { scanned: sources.length, updated: 0, skipped: 0, errors: [] };

  for (const source of sources) {
    try {
      const release = await fetchGithubLatestRelease(source.repo);
      const tag = String(release?.tag_name || release?.name || '').trim();
      if (!tag) {
        summary.skipped++;
        continue;
      }

      const syncKey = `github:${source.repo}:${tag}`;
      const already = await pool.query(
        `SELECT id, published_at
         FROM ows_store_timeline
         WHERE (visual_meta->>'sync_key') = $1
         LIMIT 1`,
        [syncKey]
      );

      if (already.rowCount > 0 && !force) {
        summary.skipped++;
        continue;
      }

      const bodyLines = splitReleaseBody(release?.body || '');
      const publishedAt = release?.published_at || release?.created_at || new Date().toISOString();
      const releasePlatforms = inferPlatformsFromReleaseAssets(release?.assets || [], source.defaultPlatforms || ['windows']);

      await upsertOwsNewsEntryBySyncKey({
        syncKey,
        projectNames: [source.slug, source.name],
        title: `${source.name} ${tag}`,
        description: bodyLines[0] || `Nueva release publicada para ${source.name}.`,
        changes: bodyLines.length ? bodyLines : [`Release ${tag} publicada en GitHub.`],
        updateDate: publishedAt,
        entryType: 'changelog',
        platforms: releasePlatforms,
        model2dKey: 'release_sync',
        model2dPayload: { repo: source.repo, tag },
        bannerMeta: {
          visual: 'release_sync',
          repo: source.repo,
          tag,
          html_url: release?.html_url || '',
          prerelease: Boolean(release?.prerelease),
          draft: Boolean(release?.draft)
        },
        isActive: true,
        priority: 0
      });

      summary.updated++;
    } catch (err) {
      summary.errors.push({
        slug: source.slug,
        repo: source.repo,
        message: err?.message || 'sync error',
        status: err?.status || 0
      });
    }
  }

  return summary;
}

/* ========== MIGRACIÃ“N AUTOMÃTICA DE BASE DE DATOS ========== */
async function migrateLegacyOwsNewsUpdatesToTimeline() {
  try {
    const { rows } = await pool.query(`
      SELECT *
      FROM ows_news_updates
      ORDER BY update_date DESC, created_at DESC, id DESC
      LIMIT 2000
    `);
    if (!rows.length) return { migrated: 0 };

    let migrated = 0;
    for (const row of rows) {
      const legacySyncKey = String(row?.banner_meta?.sync_key || '').trim() || `legacy:ows_news_updates:${row.id}`;
      const normalized = normalizeOwsNewsRow(row);
      await upsertOwsNewsEntryBySyncKey({
        syncKey: legacySyncKey,
        projectNames: normalized.projectNames,
        projectSlugs: normalized.projectSlugs,
        title: normalized.title,
        description: normalized.description,
        changes: normalized.changes,
        updateDate: normalized.updateDate,
        entryType: normalized.entryType,
        platforms: normalized.platforms,
        model2dKey: normalized.model_2d_key,
        model2dPayload: normalized.model_2d_payload || {},
        bannerMeta: {
          ...(normalized.banner_meta || {}),
          legacy_news_id: row.id
        },
        isActive: normalized.isActive,
        priority: normalized.priority,
        eventStart: normalized.eventStart,
        eventEnd: normalized.eventEnd
      });
      migrated += 1;
    }
    return { migrated };
  } catch (err) {
    console.log('[OWS] Error migrando ows_news_updates -> ows_store_timeline:', err?.message || err);
    return { migrated: 0, error: err?.message || 'migration error' };
  }
}

async function runDatabaseMigrations() {
  console.log('ðŸ”„ Ejecutando migraciones de base de datos...');

  try {
    // 0. Corregir nombres de columnas en users_nat (necesario para Supabase / NatMarket)
    console.log('ðŸ”§ Corrigiendo esquema de users_nat...');
    await pool.query(`
      DO $$ 
      BEGIN
        -- Renombrar password_hash a password si existe
        IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users_nat' AND column_name = 'password_hash') 
        AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users_nat' AND column_name = 'password') THEN
          ALTER TABLE users_nat RENAME COLUMN password_hash TO password;
        END IF;

        -- Renombrar unique_id a user_unique_id si existe
        IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users_nat' AND column_name = 'unique_id') 
        AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users_nat' AND column_name = 'user_unique_id') THEN
          ALTER TABLE users_nat RENAME COLUMN unique_id TO user_unique_id;
        END IF;

        -- Hacer email opcional (null) si existe, ya que el registro no lo pide
        IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users_nat' AND column_name = 'email') THEN
          ALTER TABLE users_nat ALTER COLUMN email DROP NOT NULL;
        END IF;
      END $$;
    `).catch(err => console.log('âš ï¸ Aviso: MigraciÃ³n de nombres de columna users_nat:', err.message));

    // 1. Agregar columna comment a user_ratings_nat si no existe
    await pool.query(`
      ALTER TABLE user_ratings_nat 
      ADD COLUMN IF NOT EXISTS comment TEXT
    `).catch(() => console.log('âš ï¸ Columna comment ya existe en user_ratings_nat'));

    // 2. Eliminar y recrear foreign keys con ON DELETE CASCADE
    console.log('ðŸ”§ Arreglando foreign keys...');

    // ai_product_generations
    await pool.query(`
      ALTER TABLE ai_product_generations 
      DROP CONSTRAINT IF EXISTS ai_product_generations_user_id_fkey
    `).catch(() => { });

    await pool.query(`
      ALTER TABLE ai_product_generations 
      ADD CONSTRAINT ai_product_generations_user_id_fkey 
      FOREIGN KEY (user_id) REFERENCES users_nat(id) 
      ON DELETE CASCADE
    `).catch(() => console.log('âš ï¸ FK ai_product_generations ya existe'));

    // messages_nat
    await pool.query(`
      ALTER TABLE messages_nat 
      DROP CONSTRAINT IF EXISTS messages_nat_sender_id_fkey
    `).catch(() => { });

    await pool.query(`
      ALTER TABLE messages_nat 
      ADD CONSTRAINT messages_nat_sender_id_fkey 
      FOREIGN KEY (sender_id) REFERENCES users_nat(id) 
      ON DELETE CASCADE
    `).catch(() => console.log('âš ï¸ FK messages_nat ya existe'));

    // user_favorites_nat
    await pool.query(`
      ALTER TABLE user_favorites_nat 
      DROP CONSTRAINT IF EXISTS user_favorites_nat_user_id_fkey
    `).catch(() => { });

    await pool.query(`
      ALTER TABLE user_favorites_nat 
      ADD CONSTRAINT user_favorites_nat_user_id_fkey 
      FOREIGN KEY (user_id) REFERENCES users_nat(id) 
      ON DELETE CASCADE
    `).catch(() => console.log('âš ï¸ FK user_favorites_nat ya existe'));

    // user_wishlist_nat
    await pool.query(`
      ALTER TABLE user_wishlist_nat 
      DROP CONSTRAINT IF EXISTS user_wishlist_nat_user_id_fkey
    `).catch(() => { });

    await pool.query(`
      ALTER TABLE user_wishlist_nat 
      ADD CONSTRAINT user_wishlist_nat_user_id_fkey 
      FOREIGN KEY (user_id) REFERENCES users_nat(id) 
      ON DELETE CASCADE
    `).catch(() => console.log('âš ï¸ FK user_wishlist_nat ya existe'));

    // user_follows (si existe)
    await pool.query(`
      ALTER TABLE user_follows 
      DROP CONSTRAINT IF EXISTS user_follows_follower_id_fkey
    `).catch(() => { });

    await pool.query(`
      ALTER TABLE user_follows 
      ADD CONSTRAINT user_follows_follower_id_fkey 
      FOREIGN KEY (follower_id) REFERENCES users_nat(id) 
      ON DELETE CASCADE
    `).catch(() => { });

    await pool.query(`
      ALTER TABLE user_follows 
      DROP CONSTRAINT IF EXISTS user_follows_following_id_fkey
    `).catch(() => { });

    await pool.query(`
      ALTER TABLE user_follows 
      ADD CONSTRAINT user_follows_following_id_fkey 
      FOREIGN KEY (following_id) REFERENCES users_nat(id) 
      ON DELETE CASCADE
    `).catch(() => { });

    // 3. Limpiar registros huÃ©rfanos (datos que referencian usuarios inexistentes)
    console.log('ðŸ§¹ Limpiando datos huÃ©rfanos...');

    // Limpiar ai_product_generations
    await pool.query(`
      DELETE FROM ai_product_generations 
      WHERE user_id NOT IN (SELECT id FROM users_nat)
    `).catch(() => { });

    // Limpiar messages_nat
    await pool.query(`
      DELETE FROM messages_nat 
      WHERE sender_id NOT IN (SELECT id FROM users_nat)
    `).catch(() => { });

    // Limpiar user_favorites_nat
    await pool.query(`
      DELETE FROM user_favorites_nat 
      WHERE user_id NOT IN (SELECT id FROM users_nat)
    `).catch(() => { });

    // Limpiar user_wishlist_nat
    await pool.query(`
      DELETE FROM user_wishlist_nat 
      WHERE user_id NOT IN (SELECT id FROM users_nat)
    `).catch(() => { });

    // Limpiar user_follows
    await pool.query(`
      DELETE FROM user_follows 
      WHERE follower_id NOT IN (SELECT id FROM users_nat)
        OR following_id NOT IN (SELECT id FROM users_nat)
    `).catch(() => { });

    // 4. Crear tabla reviews_nat si no existe
    await pool.query(`
      CREATE TABLE IF NOT EXISTS reviews_nat (
        id SERIAL PRIMARY KEY,
        reviewer_id INTEGER NOT NULL REFERENCES users_nat(id) ON DELETE CASCADE,
        reviewed_user_id INTEGER NOT NULL REFERENCES users_nat(id) ON DELETE CASCADE,
        product_id INTEGER REFERENCES products_nat(id) ON DELETE SET NULL,
        rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
        comment TEXT,
        review_type VARCHAR(20) NOT NULL CHECK (review_type IN ('seller', 'buyer')),
        created_at TIMESTAMP DEFAULT NOW()
      )
    `).catch(() => console.log('âš ï¸ Tabla reviews_nat ya existe'));

    // Limpiar user_reviews_nat (si existe)
    await pool.query(`
      DELETE FROM user_reviews_nat 
      WHERE reviewer_id NOT IN (SELECT id FROM users_nat)
        OR reviewed_user_id NOT IN (SELECT id FROM users_nat)
    `).catch(() => { });

    // Limpiar reviews_nat
    await pool.query(`
      DELETE FROM reviews_nat 
      WHERE reviewer_id NOT IN (SELECT id FROM users_nat)
        OR reviewed_user_id NOT IN (SELECT id FROM users_nat)
    `).catch(() => { });

    // 5. Agregar columna unique_id a ocean_pay_users si no existe
    await pool.query(`
      ALTER TABLE ocean_pay_users 
      ADD COLUMN IF NOT EXISTS unique_id VARCHAR(100)
    `).catch(() => console.log('âš ï¸ Columna unique_id ya existe en ocean_pay_users'));

    // 6. Agregar columnas de monedas si no existen
    await pool.query(`
      ALTER TABLE ocean_pay_users 
      ADD COLUMN IF NOT EXISTS ecoxionums INTEGER DEFAULT 0,
      ADD COLUMN IF NOT EXISTS aquabux INTEGER DEFAULT 0,
      ADD COLUMN IF NOT EXISTS appbux INTEGER DEFAULT 0
    `).catch(() => console.log('âš ï¸ Columnas de monedas ya existen en ocean_pay_users'));

    // 7. Fix command_limit_extensions foreign key and data type
    await pool.query(`
      DO $$ 
      BEGIN
        -- Drop legacy foreign key if exists
        IF EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE constraint_name = 'command_limit_extensions_user_id_fkey') THEN
          ALTER TABLE command_limit_extensions DROP CONSTRAINT command_limit_extensions_user_id_fkey;
        END IF;

        -- Convert user_id to INTEGER if it is TEXT
        IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'command_limit_extensions' AND column_name = 'user_id' AND data_type = 'text') THEN
          ALTER TABLE command_limit_extensions ALTER COLUMN user_id TYPE INTEGER USING (user_id::integer);
        END IF;

        -- Add correct foreign key to ocean_pay_users
        IF NOT EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE constraint_name = 'command_limit_extensions_user_id_ocean_fkey') THEN
          ALTER TABLE command_limit_extensions 
          ADD CONSTRAINT command_limit_extensions_user_id_ocean_fkey 
          FOREIGN KEY (user_id) REFERENCES ocean_pay_users(id) ON DELETE CASCADE;
        END IF;
      END $$;
    `).catch(err => console.log('âš ï¸ Aviso: MigraciÃ³n command_limit_extensions:', err.message));

    // 8. Crear tabla ocean_pay_cards si no existe
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ocean_pay_cards (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES ocean_pay_users(id) ON DELETE CASCADE,
        card_number VARCHAR(16) NOT NULL UNIQUE,
        cvv VARCHAR(3) NOT NULL,
        expiry_date VARCHAR(5) NOT NULL,
        is_active BOOLEAN DEFAULT true,
        is_primary BOOLEAN DEFAULT false,
        card_name VARCHAR(50) DEFAULT 'Mi Tarjeta',
        created_at TIMESTAMP DEFAULT NOW()
      )
    `).catch(() => console.log('âš ï¸ Tabla ocean_pay_cards ya existe'));

    // 9. Agregar columna balances (JSONB) a ocean_pay_cards para multisaldo flexible
    await pool.query(`
      ALTER TABLE ocean_pay_cards 
      ADD COLUMN IF NOT EXISTS balances JSONB DEFAULT '{}'
    `).catch(() => console.log('âš ï¸ Columna balances ya existe en ocean_pay_cards'));

    // 2.4 Migraciones legacy de saldos (solo si se habilita explicitamente por entorno)
    if (ENABLE_LEGACY_BALANCE_RESCUE) {
      console.log('Ejecutando migracion legacy de saldos Ecoxionums...');
      try {
        await pool.query(`
          UPDATE ocean_pay_cards opc
          SET balances = jsonb_set(COALESCE(opc.balances, '{}'::jsonb), '{ecoxionums}', to_jsonb((m.value)::numeric))
          FROM ocean_pay_metadata m
          WHERE opc.user_id = m.user_id
            AND m.key = 'ecoxionums'
            AND opc.is_primary = true
            AND (opc.balances->>'ecoxionums' IS NULL OR (opc.balances->>'ecoxionums')::numeric = 0)
            AND m.value ~ '^[0-9.]+$'
        `);

        await pool.query(`
          UPDATE ocean_pay_cards opc
          SET balances = jsonb_set(COALESCE(opc.balances, '{}'::jsonb), '{ecoxionums}', to_jsonb(u.ecoxionums))
          FROM ocean_pay_users u
          WHERE opc.user_id = u.id
            AND opc.is_primary = true
            AND (opc.balances->>'ecoxionums' IS NULL OR (opc.balances->>'ecoxionums')::numeric = 0)
            AND u.ecoxionums > 0
        `);
      } catch (migErr) {
        console.log('Aviso: error en migracion legacy de Ecoxionums:', migErr.message);
      }
    } else {
      console.log('Se omiten migraciones legacy de Ecoxionums en arranque (anti-reset).');
    }

    // 2.5. Asegurar 500 VoltBits de cortesia para Velocity Surge
    try {
      await pool.query(`
        UPDATE ocean_pay_cards
        SET balances = jsonb_set(COALESCE(balances, '{}'::jsonb), '{voltbit}', '500'::jsonb)
        WHERE is_primary = true
          AND (balances->>'voltbit' IS NULL OR (balances->>'voltbit')::numeric = 0)
      `);
      console.log('Balance de VoltBits (500) inicializado para usuarios existentes');
    } catch (voltErr) {
      console.log('Aviso: error en inicializacion VoltBits:', voltErr.message);
    }

    // 2.6. Asegurar MayhemCoins para WildWeapon Mayhem
    try {
      await pool.query(`
        INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount)
        SELECT c.id, 'mayhemcoins', 0
        FROM ocean_pay_cards c
        WHERE c.is_primary = true
          AND NOT EXISTS (
            SELECT 1 FROM ocean_pay_card_balances
            WHERE card_id = c.id AND currency_type = 'mayhemcoins'
          )
        ON CONFLICT (card_id, currency_type) DO NOTHING
      `);
      console.log('MayhemCoins inicializados para usuarios existentes');
    } catch (mcErr) {
      console.log('Aviso: error en inicializacion MayhemCoins:', mcErr.message);
    }

    // 2.7. Fusion metadata -> card_balances (legacy, desactivada por defecto)
    if (ENABLE_LEGACY_BALANCE_RESCUE) {
      console.log('Sincronizando saldos de metadata -> card_balances...');
      try {
        const metaKeys = ['wildcredits', 'wildgems', 'ecobooks', 'amber', 'nxb', 'voltbit', 'appbux', 'ecotokens', 'ecobits'];
        for (const key of metaKeys) {
          await pool.query(`
            INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount)
            SELECT c.id, '${key}', GREATEST(
              COALESCE((m.value)::numeric, 0),
              COALESCE((SELECT amount FROM ocean_pay_card_balances WHERE card_id = c.id AND currency_type = '${key}'), 0)
            )
            FROM ocean_pay_cards c
            JOIN ocean_pay_metadata m ON m.user_id = c.user_id AND m.key = '${key}'
            WHERE c.is_primary = true
              AND m.value ~ '^[0-9.]+$'
            ON CONFLICT (card_id, currency_type)
            DO UPDATE SET amount = GREATEST(ocean_pay_card_balances.amount, EXCLUDED.amount)
          `).catch(e => console.log(`Migracion ${key}:`, e.message));
        }

        await pool.query(`
          UPDATE ocean_pay_cards opc
          SET balances = COALESCE(opc.balances, '{}'::jsonb) || (
            SELECT jsonb_object_agg(cb.currency_type, cb.amount)
            FROM ocean_pay_card_balances cb
            WHERE cb.card_id = opc.id
          )
          WHERE opc.is_primary = true
            AND EXISTS (SELECT 1 FROM ocean_pay_card_balances WHERE card_id = opc.id)
        `).catch(e => console.log('Sync JSONB:', e.message));
      } catch (fusionErr) {
        console.log('Aviso: error en fusion metadata -> card_balances:', fusionErr.message);
      }
    } else {
      console.log('Se omite fusion metadata -> card_balances en arranque (anti-reset).');
    }

    // 2.8. UNIFICACION DE SUSCRIPCIONES: Migrar DinoPass, NaturePass y WildShorts a ocean_pay_subscriptions
    console.log('ðŸ”„ Unificando suscripciones en ocean_pay_subscriptions...');
    try {
      // 1. Nature-Pass desde metadata
      await pool.query(`
        INSERT INTO ocean_pay_subscriptions (user_id, project_id, plan_name, sub_name, price, currency, status, start_date)
        SELECT m.user_id, 'Naturepedia', 'Nature-Pass', 'Nature-Pass', 0, 'wildgems', 'active', m.created_at
        FROM ocean_pay_metadata m
        WHERE m.key = 'nature_pass' AND m.value = 'true'
        AND NOT EXISTS (
          SELECT 1 FROM ocean_pay_subscriptions s 
          WHERE s.user_id = m.user_id AND s.project_id = 'Naturepedia' AND s.plan_name = 'Nature-Pass'
        )
      `).catch(e => console.log('âš ï¸ MigraciÃ³n Nature-Pass:', e.message));

      // 2. DinoPass desde metadata
      await pool.query(`
        INSERT INTO ocean_pay_subscriptions (user_id, project_id, plan_name, sub_name, price, currency, status, start_date)
        SELECT m.user_id, 'DinoBox', 
               CASE WHEN m.value = 'elite' THEN 'DinoPass Elite' ELSE 'DinoPass Premium' END,
               CASE WHEN m.value = 'elite' THEN 'DinoPass Elite' ELSE 'DinoPass Premium' END,
               0, 'wildgems', 'active', m.created_at
        FROM ocean_pay_metadata m
        WHERE m.key = 'dinopass_type'
        AND NOT EXISTS (
          SELECT 1 FROM ocean_pay_subscriptions s 
          WHERE s.user_id = m.user_id AND s.project_id = 'DinoBox' 
          AND s.plan_name IN ('DinoPass Elite', 'DinoPass Premium')
        )
      `).catch(e => console.log('âš ï¸ MigraciÃ³n DinoPass:', e.message));

      // 3. WildShorts Premium (desde wildshorts_subs)
      await pool.query(`
        INSERT INTO ocean_pay_subscriptions (user_id, project_id, plan_name, sub_name, price, currency, status, start_date, end_date)
        SELECT ws.user_id, 'WildShorts', ws.plan_id, ws.plan_id, 0, 'wildgems', 
               CASE WHEN ws.active = true THEN 'active' ELSE 'cancelled' END,
               ws.starts_at, ws.ends_at
        FROM wildshorts_subs ws
        WHERE NOT EXISTS (
          SELECT 1 FROM ocean_pay_subscriptions s 
          WHERE s.user_id = ws.user_id AND s.project_id = 'WildShorts' AND s.plan_name = ws.plan_id
        )
      `).catch(e => console.log('âš ï¸ MigraciÃ³n WildShorts:', e.message));

      console.log('âœ… UnificaciÃ³n de suscripciones completada');

      // Parche: Reparar registros con nulos (evitar "null" en la UI)
      await pool.query(`
        UPDATE ocean_pay_subscriptions 
        SET plan_name = COALESCE(plan_name, sub_name, 'SuscripciÃ³n'),
            sub_name = COALESCE(sub_name, plan_name, 'SuscripciÃ³n'),
            project_id = COALESCE(project_id, 'Ocean Pay'),
            currency = COALESCE(currency, 'wildgems')
        WHERE plan_name IS NULL OR sub_name IS NULL OR project_id IS NULL OR currency IS NULL
      `).catch(e => console.log('âš ï¸ Error reparando nulos en subs:', e.message));

    } catch (subErr) {
      console.log('âš ï¸ Aviso: Error en unificaciÃ³n de suscripciones:', subErr.message);
    }

    // 10. Crear tabla ocean_pay_card_balances para saldos por tarjeta (Legado/Compatibilidad)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ocean_pay_card_balances (
        id SERIAL PRIMARY KEY,
        card_id INTEGER NOT NULL REFERENCES ocean_pay_cards(id) ON DELETE CASCADE,
        currency_type VARCHAR(50) NOT NULL,
        amount DECIMAL(20, 2) DEFAULT 0,
        UNIQUE(card_id, currency_type)
      )
    `).catch(() => console.log('âš ï¸ Tabla ocean_pay_card_balances ya existe'));

    // 10.1 Unificacion de saldos en sistema por tarjeta
    try {
      // JSONB balances -> ocean_pay_card_balances
      await pool.query(`
        WITH parsed AS (
          SELECT
            c.id AS card_id,
            LOWER(e.key) AS currency_type,
            CASE
              WHEN e.value ~ '^-?[0-9]+(\\.[0-9]+)?$' THEN GREATEST((e.value)::numeric, 0)
              ELSE NULL
            END AS amount
          FROM ocean_pay_cards c
          CROSS JOIN LATERAL jsonb_each_text(COALESCE(c.balances, '{}'::jsonb)) e
          WHERE c.is_primary = true
        ),
        expanded AS (
          SELECT
            card_id,
            currency_type,
            MAX(amount) AS amount
          FROM parsed
          WHERE amount IS NOT NULL
          GROUP BY card_id, currency_type
        )
        INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount)
        SELECT card_id, currency_type, amount
        FROM expanded
        ON CONFLICT (card_id, currency_type)
        DO UPDATE SET amount = EXCLUDED.amount  -- cards.balances is source of truth, no GREATEST
      `);

      // metadata -> ocean_pay_card_balances (legacy only, disabled by default)
      if (ENABLE_LEGACY_BALANCE_RESCUE) {
        await pool.query(`
          WITH parsed AS (
            SELECT
              c.id AS card_id,
              LOWER(m.key) AS currency_type,
              GREATEST((m.value)::numeric, 0) AS amount
            FROM ocean_pay_cards c
            JOIN ocean_pay_metadata m ON m.user_id = c.user_id
            WHERE c.is_primary = true
              AND m.value ~ '^-?[0-9]+(\\.[0-9]+)?$'
          ),
          dedup AS (
            SELECT
              card_id,
              currency_type,
              MAX(amount) AS amount
            FROM parsed
            GROUP BY card_id, currency_type
          )
          INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount)
          SELECT card_id, currency_type, amount
          FROM dedup
          ON CONFLICT (card_id, currency_type)
          DO UPDATE SET amount = GREATEST(ocean_pay_card_balances.amount, EXCLUDED.amount)
        `);
      }

      // columnas legacy de usuario -> ocean_pay_card_balances: SKIPPED at startup.
      // Reason: ocean_pay_users.aquabux/.appbux/.ecoxionums are legacy columns that may hold
      // stale high values from before the unified balance system. Writing them back with
      // GREATEST() would restore balances that were legitimately spent.
      // These columns are updated by setUnifiedCardCurrencyBalance for compatibility only.

      // Fuente unificada -> JSONB balances de tarjeta
      // Note: card_balances was just populated FROM cards.balances above,
      // so this is effectively a no-op. Still useful to keep card_balances
      // in sync as a secondary store.
      await pool.query(`
        UPDATE ocean_pay_cards c
        SET balances = COALESCE(c.balances, '{}'::jsonb) || COALESCE(src.payload, '{}'::jsonb)
        FROM (
          SELECT card_id, jsonb_object_agg(currency_type, amount) AS payload
          FROM ocean_pay_card_balances
          GROUP BY card_id
        ) src
        WHERE src.card_id = c.id
      `);

      // Fuente unificada -> metadata (compatibilidad de lectura para servicios legacy)
      await pool.query(`
        UPDATE ocean_pay_metadata m
        SET value = src.amount::text
        FROM (
          SELECT c.user_id, cb.currency_type, cb.amount
          FROM ocean_pay_cards c
          JOIN ocean_pay_card_balances cb ON cb.card_id = c.id
          WHERE c.is_primary = true
        ) src
        WHERE m.user_id = src.user_id
          AND LOWER(m.key) = src.currency_type
      `);
      await pool.query(`
        INSERT INTO ocean_pay_metadata (user_id, key, value)
        SELECT src.user_id, src.currency_type, src.amount::text
        FROM (
          SELECT c.user_id, cb.currency_type, cb.amount
          FROM ocean_pay_cards c
          JOIN ocean_pay_card_balances cb ON cb.card_id = c.id
          WHERE c.is_primary = true
        ) src
        WHERE NOT EXISTS (
          SELECT 1 FROM ocean_pay_metadata m
          WHERE m.user_id = src.user_id
            AND LOWER(m.key) = src.currency_type
        )
      `).catch(() => {});

      // Mantener columnas legacy sincronizadas (solo compatibilidad)
      await pool.query(`
        UPDATE ocean_pay_users u
        SET
          aquabux = COALESCE(src.aquabux, u.aquabux),
          appbux = COALESCE(src.appbux, u.appbux),
          ecoxionums = COALESCE(src.ecoxionums, u.ecoxionums)
        FROM (
          SELECT
            c.user_id,
            MAX(CASE WHEN cb.currency_type = 'aquabux' THEN cb.amount END)::int AS aquabux,
            MAX(CASE WHEN cb.currency_type = 'appbux' THEN cb.amount END)::int AS appbux,
            MAX(CASE WHEN cb.currency_type = 'ecoxionums' THEN cb.amount END)::int AS ecoxionums
          FROM ocean_pay_cards c
          LEFT JOIN ocean_pay_card_balances cb ON cb.card_id = c.id
          WHERE c.is_primary = true
          GROUP BY c.user_id
        ) src
        WHERE src.user_id = u.id
      `);
      console.log('âœ… Unificacion de saldos completada (fuente por tarjeta activa).');
    } catch (balanceUnifyErr) {
      console.log('âš ï¸ Aviso: Error en unificacion de saldos:', balanceUnifyErr.message);
    }

    // 10.2 Sincronizacion bidireccional por compatibilidad (fuente principal: ocean_pay_cards.balances)
    try {
      await pool.query(`
        CREATE OR REPLACE FUNCTION sync_card_balances_from_cards_fn()
        RETURNS trigger AS $$
        BEGIN
          IF pg_trigger_depth() > 1 THEN
            RETURN NEW;
          END IF;

          DELETE FROM ocean_pay_card_balances WHERE card_id = NEW.id;

          INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount)
          SELECT
            NEW.id,
            src.currency_type,
            MAX(src.amount) AS amount
          FROM (
            SELECT
              LOWER(kv.key) AS currency_type,
              GREATEST((kv.value)::numeric, 0) AS amount
            FROM jsonb_each_text(COALESCE(NEW.balances, '{}'::jsonb)) kv
            WHERE kv.value ~ '^-?[0-9]+(\\.[0-9]+)?$'
          ) src
          GROUP BY src.currency_type
          ON CONFLICT (card_id, currency_type) DO UPDATE SET amount = EXCLUDED.amount;

          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
      `);

      await pool.query(`
        DROP TRIGGER IF EXISTS trg_sync_card_balances_from_cards ON ocean_pay_cards;
        CREATE TRIGGER trg_sync_card_balances_from_cards
        AFTER INSERT OR UPDATE OF balances
        ON ocean_pay_cards
        FOR EACH ROW
        EXECUTE FUNCTION sync_card_balances_from_cards_fn();
      `);

      await pool.query(`
        CREATE OR REPLACE FUNCTION sync_cards_from_card_balances_fn()
        RETURNS trigger AS $$
        BEGIN
          IF pg_trigger_depth() > 1 THEN
            RETURN NEW;
          END IF;

          UPDATE ocean_pay_cards
          SET balances = jsonb_set(
            COALESCE(balances, '{}'::jsonb),
            ARRAY[LOWER(NEW.currency_type)]::text[],
            to_jsonb(COALESCE(NEW.amount, 0)::numeric),
            true
          )
          WHERE id = NEW.card_id;

          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
      `);

      await pool.query(`
        DROP TRIGGER IF EXISTS trg_sync_cards_from_card_balances ON ocean_pay_card_balances;
        CREATE TRIGGER trg_sync_cards_from_card_balances
        AFTER INSERT OR UPDATE OF amount
        ON ocean_pay_card_balances
        FOR EACH ROW
        EXECUTE FUNCTION sync_cards_from_card_balances_fn();
      `);

      await pool.query(`
        CREATE OR REPLACE FUNCTION sync_cards_from_metadata_fn()
        RETURNS trigger AS $$
        DECLARE
          v_card_id INTEGER;
        BEGIN
          IF pg_trigger_depth() > 1 THEN
            RETURN NEW;
          END IF;

          IF NEW.value !~ '^-?[0-9]+(\\.[0-9]+)?$' THEN
            RETURN NEW;
          END IF;

          SELECT id INTO v_card_id
          FROM ocean_pay_cards
          WHERE user_id = NEW.user_id
          ORDER BY is_primary DESC, id ASC
          LIMIT 1;

          IF v_card_id IS NULL THEN
            RETURN NEW;
          END IF;

          -- metadata trigger: do NOT update cards.balances from metadata.
          -- metadata is a legacy compat layer. cards.balances is the source of truth.
          -- Updating cards from metadata would restore spent balances.
          RETURN NEW;
          UPDATE ocean_pay_cards  -- unreachable, kept for schema reference
          SET balances = jsonb_set(
            COALESCE(balances, '{}'::jsonb),
            ARRAY[LOWER(NEW.key)]::text[],
            to_jsonb(COALESCE((NEW.value)::numeric, 0)),
            true
          )
          WHERE id = v_card_id;

          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
      `);

      await pool.query(`
        DROP TRIGGER IF EXISTS trg_sync_cards_from_metadata ON ocean_pay_metadata;
        CREATE TRIGGER trg_sync_cards_from_metadata
        AFTER INSERT OR UPDATE OF value
        ON ocean_pay_metadata
        FOR EACH ROW
        EXECUTE FUNCTION sync_cards_from_metadata_fn();
      `).catch(() => {});
      console.log('âœ… Sincronizacion de compatibilidad activada (fuente principal: ocean_pay_cards).');
    } catch (syncErr) {
      console.log('âš ï¸ Aviso: Error habilitando sincronizacion de compatibilidad:', syncErr.message);
    }

    // 10. AÃ±adir columnas faltantes a ocean_pay_cards
    await pool.query(`
      ALTER TABLE ocean_pay_cards 
      ADD COLUMN IF NOT EXISTS is_primary BOOLEAN DEFAULT false,
      ADD COLUMN IF NOT EXISTS card_name VARCHAR(50) DEFAULT 'Mi Tarjeta'
        `).catch(() => { });

    // 11. Asegurar columna moneda en ocean_pay_txs
    await pool.query(`
      ALTER TABLE ocean_pay_txs 
      ADD COLUMN IF NOT EXISTS moneda VARCHAR(50) DEFAULT 'ecoxionums'
    `).catch(() => { });

    // 12. Crear tabla ocean_pay_pos si no existe (POS Virtual)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ocean_pay_pos(
          id SERIAL PRIMARY KEY,
          code VARCHAR(10) UNIQUE NOT NULL,
          sender_id INTEGER NOT NULL REFERENCES ocean_pay_users(id) ON DELETE CASCADE,
          sender_card_id INTEGER REFERENCES ocean_pay_cards(id) ON DELETE CASCADE,
          receiver_id INTEGER REFERENCES ocean_pay_users(id) ON DELETE CASCADE,
          receiver_card_id INTEGER REFERENCES ocean_pay_cards(id) ON DELETE CASCADE,
          amount DECIMAL(20, 2) NOT NULL,
          currency VARCHAR(50) NOT NULL,
          target_currency VARCHAR(50),
          is_exchange BOOLEAN DEFAULT FALSE,
          status VARCHAR(20) DEFAULT 'pending',
          created_at TIMESTAMP DEFAULT NOW(),
          completed_at TIMESTAMP
      );
    `).catch(err => console.log('âš ï¸ Error creando ocean_pay_pos:', err.message));

    // 13. Crear tabla ocean_pay_subscriptions (VIP System)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ocean_pay_subscriptions(
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES ocean_pay_users(id) ON DELETE CASCADE,
        plan_name VARCHAR(50) NOT NULL,
        price DECIMAL(20, 2) NOT NULL,
        currency VARCHAR(20) DEFAULT 'wildgems',
        status VARCHAR(20) DEFAULT 'active',
        start_date TIMESTAMP DEFAULT NOW(),
        end_date TIMESTAMP NOT NULL,
        auto_renew BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `).catch(err => console.log('âš ï¸ Error creando ocean_pay_subscriptions:', err.message));

    // 14. Crear tabla ocean_pay_notifications
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ocean_pay_notifications(
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES ocean_pay_users(id) ON DELETE CASCADE,
        title VARCHAR(100) NOT NULL,
        message TEXT NOT NULL,
        type VARCHAR(20) DEFAULT 'info',
        is_read BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `).catch(err => console.log('âš ï¸ Error creando ocean_pay_notifications:', err.message));

    // 15. Crear tabla ocean_pass
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ocean_pass(
        user_id INTEGER PRIMARY KEY REFERENCES ocean_pay_users(id) ON DELETE CASCADE,
        is_active BOOLEAN DEFAULT FALSE,
        expiry TIMESTAMP,
        has_debt BOOLEAN DEFAULT FALSE,
        debt_amount DECIMAL(20, 2) DEFAULT 0,
        missions JSONB DEFAULT '[]',
        last_reward_claim TIMESTAMP,
        minutes_tracked INTEGER DEFAULT 0,
        plan_id VARCHAR(40) DEFAULT 'ocean-pass-standard',
        billing_currency VARCHAR(40) DEFAULT 'aquabux',
        billing_amount NUMERIC(20,2) DEFAULT 0,
        next_renew_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `).catch(err => console.log('âš ï¸ Error creando ocean_pass:', err.message));
    await pool.query(`
      ALTER TABLE ocean_pass
      ADD COLUMN IF NOT EXISTS plan_id VARCHAR(40) DEFAULT 'ocean-pass-standard',
      ADD COLUMN IF NOT EXISTS billing_currency VARCHAR(40) DEFAULT 'aquabux',
      ADD COLUMN IF NOT EXISTS billing_amount NUMERIC(20,2) DEFAULT 0,
      ADD COLUMN IF NOT EXISTS next_renew_at TIMESTAMP
    `).catch(err => console.log('âš ï¸ Error alter ocean_pass:', err.message));
    // 16. Crear tabla ows_news_updates para automatizaciÃ³n de News
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ows_news_updates (
        id SERIAL PRIMARY KEY,
        project_names TEXT[] DEFAULT '{}',
        title VARCHAR(150) NOT NULL,
        description TEXT,
        changes TEXT,
        update_date TIMESTAMP DEFAULT NOW(),
        created_at TIMESTAMP DEFAULT NOW()
      );
    `).catch(err => console.log('âš ï¸ Error creando ows_news_updates:', err.message));

    await pool.query(`
      ALTER TABLE ows_news_updates
      ADD COLUMN IF NOT EXISTS entry_type VARCHAR(20) DEFAULT 'changelog',
      ADD COLUMN IF NOT EXISTS platforms TEXT[] DEFAULT '{}',
      ADD COLUMN IF NOT EXISTS model_2d_key TEXT,
      ADD COLUMN IF NOT EXISTS model_2d_payload JSONB DEFAULT '{}'::jsonb,
      ADD COLUMN IF NOT EXISTS banner_meta JSONB DEFAULT '{}'::jsonb,
      ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE,
      ADD COLUMN IF NOT EXISTS priority INTEGER DEFAULT 0,
      ADD COLUMN IF NOT EXISTS event_start TIMESTAMP,
      ADD COLUMN IF NOT EXISTS event_end TIMESTAMP
    `).catch(err => console.log('âš ï¸ Error migrando ows_news_updates:', err.message));
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_ows_news_updates_entry_type
      ON ows_news_updates(entry_type)
    `).catch(() => {});
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_ows_news_updates_update_date
      ON ows_news_updates(update_date DESC)
    `).catch(() => {});

    await pool.query(`
      CREATE TABLE IF NOT EXISTS ows_store_timeline (
        id SERIAL PRIMARY KEY,
        project_slugs TEXT[] DEFAULT '{}',
        project_names TEXT[] DEFAULT '{}',
        title VARCHAR(180) NOT NULL,
        description TEXT,
        content_lines TEXT[] DEFAULT '{}',
        details JSONB DEFAULT '{}'::jsonb,
        published_at TIMESTAMP DEFAULT NOW(),
        kind VARCHAR(20) DEFAULT 'changelog',
        platforms TEXT[] DEFAULT '{}',
        model_2d_key TEXT,
        model_2d_payload JSONB DEFAULT '{}'::jsonb,
        visual_meta JSONB DEFAULT '{}'::jsonb,
        is_active BOOLEAN DEFAULT TRUE,
        priority INTEGER DEFAULT 0,
        starts_at TIMESTAMP,
        ends_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `).catch(err => console.log('⚠️ Error creando ows_store_timeline:', err.message));
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_ows_store_timeline_kind
      ON ows_store_timeline(kind)
    `).catch(() => {});
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_ows_store_timeline_published_at
      ON ows_store_timeline(published_at DESC)
    `).catch(() => {});
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_ows_store_timeline_sync_key
      ON ows_store_timeline ((visual_meta->>'sync_key'))
    `).catch(() => {});

    await pool.query(`
      CREATE TABLE IF NOT EXISTS ows_store_push_devices (
        id SERIAL PRIMARY KEY,
        device_id VARCHAR(120) NOT NULL,
        user_id BIGINT,
        platform VARCHAR(20) NOT NULL DEFAULT 'web',
        provider VARCHAR(20) NOT NULL DEFAULT 'local',
        push_token TEXT,
        endpoint TEXT,
        p256dh TEXT,
        auth TEXT,
        app_version VARCHAR(40),
        metadata JSONB DEFAULT '{}'::jsonb,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        last_seen_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(device_id, platform)
      );
    `).catch(err => console.log('[OWS] Error creando ows_store_push_devices:', err.message));
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_ows_store_push_devices_active
      ON ows_store_push_devices(is_active, platform, last_seen_at DESC)
    `).catch(() => {});

    await pool.query(`
      CREATE TABLE IF NOT EXISTS ows_store_push_notifications (
        id SERIAL PRIMARY KEY,
        device_id VARCHAR(120) NOT NULL,
        platform VARCHAR(20) NOT NULL DEFAULT 'web',
        project_slug VARCHAR(80),
        version VARCHAR(80),
        title VARCHAR(180) NOT NULL,
        body TEXT,
        payload JSONB DEFAULT '{}'::jsonb,
        dedupe_key VARCHAR(200),
        created_at TIMESTAMP DEFAULT NOW(),
        delivered_at TIMESTAMP,
        acknowledged_at TIMESTAMP,
        UNIQUE(device_id, dedupe_key)
      );
    `).catch(err => console.log('[OWS] Error creando ows_store_push_notifications:', err.message));
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_ows_store_push_notifications_inbox
      ON ows_store_push_notifications(device_id, delivered_at, acknowledged_at, created_at DESC)
    `).catch(() => {});

    await pool.query(`
      DELETE FROM ows_store_timeline
      WHERE (visual_meta->>'sync_key') = 'seed:event:ows-store-update-trailer-20260324'
         OR (
              kind = 'event'
              AND LOWER(COALESCE(title, '')) LIKE '%ows store%'
              AND LOWER(COALESCE(title, '')) LIKE '%trailer%'
            )
    `).catch(err => console.log('[OWS] Aviso limpiando trailer legacy en ows_store_timeline:', err.message));
    await pool.query(`
      DELETE FROM ows_news_updates
      WHERE (banner_meta->>'sync_key') = 'seed:event:ows-store-update-trailer-20260324'
         OR (
              entry_type = 'event'
              AND LOWER(COALESCE(title, '')) LIKE '%ows store%'
              AND LOWER(COALESCE(title, '')) LIKE '%trailer%'
            )
    `).catch(err => console.log('[OWS] Aviso limpiando trailer legacy en ows_news_updates:', err.message));

    if (typeof migrateLegacyOwsNewsUpdatesToTimeline === 'function') {
      await migrateLegacyOwsNewsUpdatesToTimeline().catch(err => console.log('[OWS] Error migrando legacy news a timeline:', err.message));
    } else {
      console.warn('[OWS] migrateLegacyOwsNewsUpdatesToTimeline no definida, se omite migracion legacy.');
    }

    if (typeof ensureOwsStoreNewsSeedData === 'function') {
      await ensureOwsStoreNewsSeedData().catch(err => console.log('[OWS] Error seeding ows_store_timeline:', err.message));
    } else {
      console.warn('[OWS] ensureOwsStoreNewsSeedData no definida, se omite seed de ows_store_timeline.');
    }

    // 17. Crear tabla ows_projects para el Sistema OWS Store
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ows_projects(
      id SERIAL PRIMARY KEY,
      slug VARCHAR(50) UNIQUE NOT NULL,
      name VARCHAR(100) NOT NULL,
      description TEXT,
      icon_url TEXT,
      banner_url TEXT,
      url TEXT NOT NULL,
      version VARCHAR(20) DEFAULT '1.0.0',
      status VARCHAR(20) DEFAULT 'launched', -- 'launched', 'unavailable', 'coming_soon'
        release_date TIMESTAMP, --Para countdown en 'coming_soon'
        last_update TIMESTAMP DEFAULT NOW(),
      created_at TIMESTAMP DEFAULT NOW(),
      metadata JSONB DEFAULT '{}' -- Para capturas, requisitos, tags, etc.
      );
    `).catch(err => console.log('âš ï¸ Error creando ows_projects:', err.message));

    // MigraciÃ³n: installer_url para descarga de .exe en OWS Store
    await pool.query(`
      ALTER TABLE ows_projects
      ADD COLUMN IF NOT EXISTS installer_url TEXT
    `).catch(() => console.log('âš ï¸ Columna installer_url ya existe en ows_projects'));

    await pool.query(`
      CREATE TABLE IF NOT EXISTS ows_project_offers(
        id SERIAL PRIMARY KEY,
        project_slug VARCHAR(50) NOT NULL REFERENCES ows_projects(slug) ON DELETE CASCADE,
        offer_code VARCHAR(80) NOT NULL,
        title VARCHAR(160) NOT NULL,
        description TEXT,
        currency VARCHAR(40) NOT NULL DEFAULT 'voltbit',
        base_price NUMERIC(20,2) NOT NULL DEFAULT 0,
        ows_store_price NUMERIC(20,2),
        reward_payload JSONB DEFAULT '{}'::jsonb,
        metadata JSONB DEFAULT '{}'::jsonb,
        is_active BOOLEAN DEFAULT TRUE,
        starts_at TIMESTAMP,
        ends_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(project_slug, offer_code)
      );
    `).catch(err => console.log('âš ï¸ Error creando ows_project_offers:', err.message));
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_ows_project_offers_project_active
      ON ows_project_offers(project_slug, is_active, starts_at, ends_at)
    `).catch(() => {});

    await pool.query(`
      CREATE TABLE IF NOT EXISTS ows_project_offer_purchases(
        id SERIAL PRIMARY KEY,
        project_slug VARCHAR(50) NOT NULL REFERENCES ows_projects(slug) ON DELETE CASCADE,
        offer_code VARCHAR(80) NOT NULL,
        user_id BIGINT NOT NULL,
        surface VARCHAR(30) NOT NULL DEFAULT 'project',
        currency VARCHAR(40) NOT NULL,
        paid_amount NUMERIC(20,2) NOT NULL DEFAULT 0,
        reward_payload JSONB DEFAULT '{}'::jsonb,
        metadata JSONB DEFAULT '{}'::jsonb,
        status VARCHAR(20) NOT NULL DEFAULT 'completed',
        claimed_by_project BOOLEAN NOT NULL DEFAULT FALSE,
        claimed_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `).catch(err => console.log('âš ï¸ Error creando ows_project_offer_purchases:', err.message));
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_ows_project_offer_purchases_user_pending
      ON ows_project_offer_purchases(user_id, project_slug, claimed_by_project, status)
    `).catch(() => {});

    if (typeof ensureOwsStoreProjectsSeedData === 'function') {
      await ensureOwsStoreProjectsSeedData().catch(err => console.log('[OWS] Error seeding ows_projects:', err.message));
    } else {
      console.warn('[OWS] ensureOwsStoreProjectsSeedData no definida, se omite seed de ows_projects.');
    }

    if (typeof ensureProjectChangelogSync === 'function') {
      await ensureProjectChangelogSync({ force: true }).catch(err => console.log('[OWS] Error syncing project changelogs:', err.message));
    } else {
      console.warn('[OWS] ensureProjectChangelogSync no definida, se omite sync de changelogs.');
    }

    if (typeof ensureOwsStoreProjectOffersSeedData === 'function') {
      await ensureOwsStoreProjectOffersSeedData().catch(err => console.log('[OWS] Error seeding ows_project_offers:', err.message));
    } else {
      console.warn('[OWS] ensureOwsStoreProjectOffersSeedData no definida, se omite seed de ofertas.');
    }

    // Tabla de releases Android para updater asistido (OWS Store Launcher)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ows_android_releases (
        id SERIAL PRIMARY KEY,
        project_slug VARCHAR(50) NOT NULL REFERENCES ows_projects(slug) ON DELETE CASCADE,
        package_id VARCHAR(120) NOT NULL,
        version_name VARCHAR(60) NOT NULL,
        version_code INTEGER NOT NULL,
        apk_url TEXT NOT NULL,
        sha256 VARCHAR(128),
        size_bytes BIGINT DEFAULT 0,
        min_store_version VARCHAR(40),
        release_notes TEXT,
        status VARCHAR(20) DEFAULT 'published',
        is_mandatory BOOLEAN DEFAULT FALSE,
        published_at TIMESTAMP DEFAULT NOW(),
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(project_slug, version_code)
      );
    `).catch(err => console.log('âš ï¸ Error creando ows_android_releases:', err.message));

    // MigraciÃ³n: Asegurar columnas para Intercambio (Swap)
    await pool.query(`
      ALTER TABLE ocean_pay_pos
      ADD COLUMN IF NOT EXISTS target_currency VARCHAR(50),
      ADD COLUMN IF NOT EXISTS is_exchange BOOLEAN DEFAULT FALSE
        `).catch(() => { });

    // --- CRITICAL FIX: Add Password Column to Ocean Pay Users ---
    // User requested that ocean_pay_users be the authority.
    await pool.query(`
      ALTER TABLE ocean_pay_users
      ADD COLUMN IF NOT EXISTS password VARCHAR(255)
      `).catch(() => console.log('âš ï¸ Columna password ya existe en ocean_pay_users'));

    // 12. Generar tarjetas para usuarios existentes que no tengan una
    const usersWithoutCard = await pool.query(`
      SELECT id FROM ocean_pay_users 
      WHERE id NOT IN(SELECT user_id FROM ocean_pay_cards)
      `);

    for (const user of usersWithoutCard.rows) {
      const { cardNumber, cvv, expiryDate } = generateCardDetails();
      const cardResult = await pool.query(
        'INSERT INTO ocean_pay_cards (user_id, card_number, cvv, expiry_date, is_primary, card_name) VALUES ($1, $2, $3, $4, true, $5) RETURNING id',
        [user.id, cardNumber, cvv, expiryDate, 'Tarjeta Principal']
      ).catch(e => { console.error('Error generando tarjeta para usuario:', user.id, e.message); return null; });

      if (cardResult && cardResult.rows[0]) {
        // Inicializar saldos para la nueva tarjeta
        const currencies = ['aquabux', 'ecoxionums', 'ecorebits', 'wildcredits', 'wildgems', 'appbux', 'ecobooks', 'ecotokens', 'ecopower', 'amber', 'nxb', 'voltbit', 'mayhemcoins', 'cosmicdust', 'wildwavetokens'];
        for (const curr of currencies) {
          const initialBalance = (curr === 'voltbit') ? 500 : (curr === 'ecopower' ? 100 : 0);
          await pool.query(
            'INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING',
            [cardResult.rows[0].id, curr, initialBalance]
          );
        }
      }
    }

    // Asegurar WildWave Tokens en todas las tarjetas existentes
    await pool.query(`
      INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount)
      SELECT c.id, 'wildwavetokens', 0
      FROM ocean_pay_cards c
      ON CONFLICT (card_id, currency_type) DO NOTHING
    `).catch((e) => {
      console.warn('No se pudo asegurar wildwavetokens en tarjetas existentes:', e.message);
    });

    // 11. Establecer tarjeta principal para usuarios que no tengan una (CRÃTICO: Hacer esto ANTES de migrar saldos)
    await pool.query(`
      UPDATE ocean_pay_cards c SET is_primary = true
      WHERE c.id = (
      SELECT MIN(id) FROM ocean_pay_cards WHERE user_id = c.user_id
      ) AND NOT EXISTS(
        SELECT 1 FROM ocean_pay_cards WHERE user_id = c.user_id AND is_primary = true
      )
      `);

        // 12. Migracion legacy de saldos historicos (desactivada por defecto).
    if (ENABLE_LEGACY_BALANCE_RESCUE) {
      console.log('Sincronizando saldos historicos con el sistema de tarjetas (legacy)...');
      await pool.query(`
      INSERT INTO ocean_pay_card_balances(card_id, currency_type, amount)
      SELECT c.id, 'aquabux', u.aquabux
      FROM ocean_pay_cards c JOIN ocean_pay_users u ON c.user_id = u.id WHERE c.is_primary = true
      ON CONFLICT(card_id, currency_type) DO UPDATE SET amount = EXCLUDED.amount WHERE ocean_pay_card_balances.amount = 0;

      INSERT INTO ocean_pay_card_balances(card_id, currency_type, amount)
      SELECT c.id, 'appbux', u.appbux
      FROM ocean_pay_cards c JOIN ocean_pay_users u ON c.user_id = u.id WHERE c.is_primary = true
      ON CONFLICT(card_id, currency_type) DO UPDATE SET amount = EXCLUDED.amount WHERE ocean_pay_card_balances.amount = 0;

      INSERT INTO ocean_pay_card_balances(card_id, currency_type, amount)
      SELECT c.id, 'ecorebits', COALESCE(MAX(uc.amount), 0)
      FROM ocean_pay_cards c
      JOIN ocean_pay_users u ON c.user_id = u.id
      LEFT JOIN user_currency uc ON u.id = uc.user_id AND uc.currency_type = 'ecocorebits'
      WHERE c.is_primary = true
      GROUP BY c.id
      ON CONFLICT(card_id, currency_type) DO UPDATE SET amount = EXCLUDED.amount WHERE ocean_pay_card_balances.amount = 0;

      INSERT INTO ocean_pay_card_balances(card_id, currency_type, amount)
      SELECT c.id, 'ecopower', 100
      FROM ocean_pay_cards c WHERE c.is_primary = true
      ON CONFLICT(card_id, currency_type) DO NOTHING;
    `);
    } else {
      console.log('Se omite sincronizacion legacy de saldos historicos en arranque.');
    }

    /* 
    // 13. LIMPIEZA DE SALDOS - Resetear todos a 0 (excepto ecopower = 100)
    // Se limpian tanto los nuevos saldos por tarjeta como los antiguos saldos globales
    console.log('ðŸ§¹ Iniciando limpieza profunda de saldos...');

    // Resetear saldos por tarjeta
    await pool.query(`
      UPDATE ocean_pay_card_balances 
      SET amount = CASE 
        WHEN currency_type = 'ecopower' THEN 100 
        ELSE 0
    END
    `);

    // Resetear saldos globales antiguos en ocean_pay_users
    await pool.query(`UPDATE ocean_pay_users SET aquabux = 0, appbux = 0`);

    // Resetear saldos en user_currency (usado para ecorebits)
    await pool.query(`UPDATE user_currency SET amount = 0`);

    // Resetear metadatos (wildcredits, ecoxionums, ecobooks)
    await pool.query(`
      UPDATE ocean_pay_metadata 
      SET value = '0' 
      WHERE key IN('wildcredits', 'ecoxionums', 'ecobooks')
    `);

    console.log('âœ… Limpieza de saldos completada. Todos los sistemas en cero.');
    */
    console.log('âœ… Sistema de persistencia de saldos activo.');

    console.log('âœ… Migraciones completadas exitosamente!');

  } catch (err) {
    console.error('âŒ Error en migraciones:', err.message);
  }
}

// Ejecutar migraciones al iniciar el servidor
runDatabaseMigrations();
let migrationExecuted = false;

/* ===== HEALTH CHECK / STATUS ENDPOINT ===== */
// Este endpoint se usa para verificar que el servidor estÃ© funcionando
// y proporciona el estado de los servicios principales.
app.get('/status', async (_req, res) => {
  const services = {
    server: { status: 'up', name: 'OWS Database Server' },
    ecoconsole: { status: 'up', name: 'EcoConsole' },
    ecoxion: { status: 'up', name: 'Ecoxion' },
    natmarket: { status: 'up', name: 'NatMarket' },
    naturepedia: { status: 'up', name: 'Naturepedia' }
  };

  // Verificar conexiÃ³n a base de datos
  try {
    await pool.query('SELECT 1');
    services.database = { status: 'up', name: 'PostgreSQL Database' };
  } catch (e) {
    services.database = { status: 'down', name: 'PostgreSQL Database', error: e.message };
  }

  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    services
  });
});

// Endpoints individuales para cada servicio (health checks simples)
app.get('/ecoconsole/health', (_req, res) => res.json({ status: 'up', service: 'EcoConsole' }));

/* =========================================
   ECOCONSOLE REWORK ENDPOINTS (SKELETON)
   ========================================= */

// AutenticaciÃ³n directa con Ocean Pay
app.post('/ecoconsole/auth', async (req, res) => {
  const { token } = req.body;
  // TODO: Validar token con Ocean Pay system
  res.json({ success: true, message: "Placeholder: AutenticaciÃ³n exitosa" });
});

// Obtener cuota de comandos
app.get('/ecoconsole/command-quota', async (req, res) => {
  res.json({
    success: true,
    dailyLimit: 50,
    remaining: 50,
    resetAt: new Date(new Date().setHours(24, 0, 0, 0)).toISOString()
  });
});

// Ejecutar comando de pago
app.post('/ecoconsole/paid-command', async (req, res) => {
  const { commandName, cost } = req.body;
  // TODO: Descontar EcoCoreBits del usuario
  res.json({
    success: true,
    newBalance: 1000, // Placeholder
    message: `Comando ${commandName} ejecutado correctamente`
  });
});

// EstadÃ­sticas del usuario
app.get('/ecoconsole/user-stats', async (req, res) => {
  res.json({
    success: true,
    stats: {
      totalCommands: 0,
      favoriteCommand: 'none',
      joinDate: new Date().toISOString()
    }
  });
});

app.get('/ecoxion/health', (_req, res) => res.json({ status: 'up', service: 'Ecoxion' }));
app.get('/natmarket/health', (_req, res) => res.json({ status: 'up', service: 'NatMarket' }));
app.get('/naturepedia/health', (_req, res) => res.json({ status: 'up', service: 'Naturepedia' }));
app.get('/floret/health', (_req, res) => res.json({ status: 'up', service: 'Floret Shop' }));

// ========== FLORET SHOP ENDPOINTS ==========
const FLORET_MAIN_SELLER_EMAIL = 'karatedojor@gmail.com';

function normalizeFloretEmail(email) {
  return String(email || '').trim().toLowerCase();
}

async function getFloretMalevoRecipient() {
  const safeEmail = normalizeFloretEmail(FLORET_MAIN_SELLER_EMAIL);
  const { rows } = await pool.query(
    `SELECT id, username, email, power_level
     FROM floret_users
     WHERE LOWER(COALESCE(email, '')) = $1
        OR LOWER(COALESCE(username, '')) = 'malevo'
     ORDER BY power_level DESC, id ASC
     LIMIT 1`,
    [safeEmail]
  );
  const user = rows[0] || null;
  return {
    userId: user?.id || null,
    email: user?.email || FLORET_MAIN_SELLER_EMAIL
  };
}

async function resolveFloretReviewerName(userId, fallbackName = '') {
  const safeName = String(fallbackName || '').trim();
  if (!userId) return safeName || 'Cliente Floret';

  try {
    const { rows } = await pool.query(
      'SELECT username FROM floret_users WHERE id = $1 LIMIT 1',
      [userId]
    );
    if (rows[0]?.username) return rows[0].username;
  } catch (_err) {
    // Keep fallback name when DB lookup fails
  }
  return safeName || 'Cliente Floret';
}

async function createFloretNotification({
  type,
  title,
  message,
  productId = null,
  reviewId = null,
  reviewScope = 'product',
  orderId = null,
  meta = null
}) {
  const recipient = await getFloretMalevoRecipient();
  await pool.query(
    `INSERT INTO floret_notifications
      (target_user_id, target_email, type, title, message, product_id, review_id, review_scope, order_id, meta)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
    [
      recipient.userId,
      recipient.email,
      String(type || 'product_review'),
      String(title || 'Nueva resena'),
      String(message || ''),
      productId || null,
      reviewId || null,
      String(reviewScope || 'product'),
      orderId || null,
      meta ? JSON.stringify(meta) : null
    ]
  );
}

async function createFloretReviewNotification({
  type,
  title,
  message,
  productId = null,
  reviewId,
  reviewScope
}) {
  return createFloretNotification({
    type,
    title,
    message,
    productId,
    reviewId,
    reviewScope
  });
}

async function assertFloretMalevoAccess({ userId, email }) {
  const normalizedEmail = normalizeFloretEmail(email);
  const requiredEmail = normalizeFloretEmail(FLORET_MAIN_SELLER_EMAIL);

  if (normalizedEmail && normalizedEmail === requiredEmail) {
    return { allowed: true };
  }

  if (!userId) return { allowed: false, reason: 'Acceso restringido a administracion Floret' };

  const { rows } = await pool.query(
    `SELECT id, email, username, power_level, is_admin
     FROM floret_users
     WHERE id = $1
     LIMIT 1`,
    [userId]
  );
  const actor = rows[0];
  if (!actor) return { allowed: false, reason: 'Usuario no encontrado' };

  const actorEmail = normalizeFloretEmail(actor.email);
  const actorUser = String(actor.username || '').trim().toLowerCase();
  const isFloretCoreAdmin = actorEmail === requiredEmail || actorUser === 'malevo' || actorUser === 'oceanandwild';
  if (!isFloretCoreAdmin) {
    return { allowed: false, reason: 'Acceso restringido a administracion Floret' };
  }
  return { allowed: true, actor };
}

const FLORET_ORDER_STATUS_FLOW = ['new', 'paid', 'preparing', 'shipped', 'delivered', 'cancelled'];

function normalizeFloretOrderStatus(value) {
  const safe = String(value || '').trim().toLowerCase();
  if (!safe) return 'new';
  return FLORET_ORDER_STATUS_FLOW.includes(safe) ? safe : 'new';
}

function sanitizeFloretOrderItems(items = []) {
  if (!Array.isArray(items)) return [];
  return items
    .map((item) => ({
      productId: Number(item.productId || item.id || 0) || null,
      productName: String(item.productName || item.name || '').trim(),
      unitPrice: Number(item.unitPrice || item.price || 0) || 0,
      quantity: Math.max(1, Number(item.quantity || 1) || 1),
      size: String(item.size || '').trim() || null
    }))
    .filter((item) => item.productId && item.productName && item.unitPrice > 0);
}

// Registro
app.post('/floret/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Usuario y contraseÃ±a son requeridos' });
  }
  try {
    const hashed = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      `INSERT INTO floret_users(username, email, password) VALUES($1, $2, $3) RETURNING id, username, email, created_at`,
      [username, email || null, hashed]
    );
    res.json({ success: true, user: rows[0] });
  } catch (e) {
    if (e.code === '23505') {
      return res.status(400).json({ error: 'El usuario ya existe' });
    }
    console.error('Error en registro Floret:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Login
// Helper for Floret Quota
async function getFloretQuota(userId) {
  const { rows } = await pool.query('SELECT * FROM floret_admin_quotas WHERE user_id = $1', [userId]);
  let quota = rows[0];

  if (!quota) {
    const res = await pool.query('INSERT INTO floret_admin_quotas(user_id) VALUES($1) RETURNING *', [userId]);
    quota = res.rows[0];
  }

  // Check reset logic (24h cooldown)
  if (quota.last_upload_time) {
    const last = new Date(quota.last_upload_time);
    const now = new Date();
    const diffHrs = (now - last) / (1000 * 60 * 60);

    if (diffHrs >= 24) {
      await pool.query('UPDATE floret_admin_quotas SET uploads_today = 0, last_upload_time = NULL WHERE user_id = $1', [userId]);
      quota.uploads_today = 0;
      quota.last_upload_time = null;
    }
  }

  return quota;
}

// Login
app.post('/floret/login', async (req, res) => {
  const { username, password, identifier, email } = req.body;
  const loginId = String(identifier || username || email || '').trim();
  if (!loginId || !password) {
    return res.status(400).json({ error: 'Usuario/email y contrase\u00f1a son requeridos' });
  }
  try {
    const { rows } = await pool.query(
      "SELECT * FROM floret_users WHERE LOWER(username) = LOWER($1) OR LOWER(COALESCE(email, '')) = LOWER($1) LIMIT 1",
      [loginId]
    );
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Usuario o email no encontrado' });
    }
    const valid = await bcrypt.compare(password, rows[0].password);
    if (!valid) {
      return res.status(401).json({ error: 'Contrase\u00f1a incorrecta' });
    }
    const { id, email: accountEmail, created_at, is_admin, power_level } = rows[0];
    res.json({ success: true, user: { id, username: rows[0].username, email: accountEmail, created_at, is_admin, power_level } });
  } catch (e) {
    console.error('Error en login Floret:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/floret/reset-password', async (req, res) => {
  const { identifier, email, newPassword } = req.body || {};
  const loginId = String(identifier || '').trim();
  const safeEmail = String(email || '').trim();
  const safePass = String(newPassword || '');

  if (!loginId || !safeEmail || !safePass) {
    return res.status(400).json({ error: 'Completa usuario/email, email y nueva contrase\u00f1a' });
  }
  if (safePass.length < 8) {
    return res.status(400).json({ error: 'La nueva contrase\u00f1a debe tener al menos 8 caracteres' });
  }

  try {
    const { rows } = await pool.query(
      "SELECT id FROM floret_users WHERE (LOWER(username) = LOWER($1) OR LOWER(COALESCE(email, '')) = LOWER($1)) AND LOWER(COALESCE(email, '')) = LOWER($2) LIMIT 1",
      [loginId, safeEmail]
    );
    if (!rows.length) {
      return res.status(404).json({ error: 'No se encontro una cuenta que coincida con esos datos' });
    }

    const hashed = await bcrypt.hash(safePass, 10);
    await pool.query('UPDATE floret_users SET password = $1 WHERE id = $2', [hashed, rows[0].id]);
    res.json({ success: true, message: 'Contrasena actualizada' });
  } catch (e) {
    console.error('Error en reset de contrasena Floret:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});
// Endpoint para crear preferencia de MercadoPago
app.post('/floret/create_preference', async (req, res) => {
  try {
    const { items, back_url } = req.body;

    // âš ï¸ FIX CRÃTICO: MercadoPago rechaza localhost/http en auto_return.
    // Forzamos SIEMPRE la URL de producciÃ³n (HTTPS) para evitar el error 400.
    const returnUrl = 'https://floretshop.netlify.app';

    console.log(`[MP Preference] Creando preferencia.Return URL forzada: ${returnUrl} `);

    // Transformar items al formato de MP
    const body = {
      items: items.map(item => ({
        title: item.name,
        quantity: Number(item.quantity) || 1,
        unit_price: Number(item.price),
        currency_id: 'UYU',
      })),
      back_urls: {
        success: returnUrl,
        failure: returnUrl,
        pending: returnUrl
      },
      auto_return: 'approved',
    };

    const preference = new Preference(mpClient);
    const result = await preference.create({ body });

    res.json({ id: result.id });
  } catch (error) {
    console.error('Error creando preferencia MP:', error);
    // Devolvemos el mensaje de error real para depurar
    res.status(500).json({
      error: 'Error al crear la preferencia de pago',
      details: error.message,
      mp_error: error.cause || error
    });
  }
});

app.post('/floret/orders', async (req, res) => {
  const client = await pool.connect();
  try {
    const {
      buyerName,
      buyerEmail,
      buyerPhone = '',
      shippingAddress = '',
      shippingCity = '',
      paymentMethod = 'mercado_pago',
      paymentRef = '',
      items = []
    } = req.body || {};

    const safeName = String(buyerName || '').trim();
    const safeEmail = String(buyerEmail || '').trim().toLowerCase();
    const cleanItems = sanitizeFloretOrderItems(items);

    if (!safeName || !safeEmail) {
      return res.status(400).json({ error: 'Faltan datos del comprador' });
    }
    if (!cleanItems.length) {
      return res.status(400).json({ error: 'No hay items validos para procesar' });
    }

    await client.query('BEGIN');

    const ids = cleanItems.map((item) => item.productId);
    const productsRes = await client.query(
      `SELECT id, name, stock, price
       FROM floret_products
       WHERE id = ANY($1::int[])
       FOR UPDATE`,
      [ids]
    );
    const productMap = new Map(productsRes.rows.map((row) => [Number(row.id), row]));

    const queuedNotifications = [];
    for (const item of cleanItems) {
      const dbProduct = productMap.get(item.productId);
      if (!dbProduct) {
        throw new Error(`Producto no encontrado (ID ${item.productId})`);
      }
      if (Number(dbProduct.stock || 0) < item.quantity) {
        throw new Error(`Stock insuficiente para ${dbProduct.name}`);
      }
    }

    const total = cleanItems.reduce((sum, item) => sum + (item.unitPrice * item.quantity), 0);
    const orderRes = await client.query(
      `INSERT INTO floret_orders
        (buyer_name, buyer_email, buyer_phone, shipping_address, shipping_city, payment_method, payment_ref, total, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'paid')
       RETURNING *`,
      [
        safeName,
        safeEmail,
        String(buyerPhone || '').trim(),
        String(shippingAddress || '').trim(),
        String(shippingCity || '').trim(),
        String(paymentMethod || 'mercado_pago').trim().toLowerCase(),
        String(paymentRef || '').trim() || null,
        Number(total.toFixed(2))
      ]
    );
    const order = orderRes.rows[0];

    for (const item of cleanItems) {
      await client.query(
        `INSERT INTO floret_order_items
          (order_id, product_id, product_name, unit_price, quantity, size, line_total)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          order.id,
          item.productId,
          item.productName,
          item.unitPrice,
          item.quantity,
          item.size,
          Number((item.unitPrice * item.quantity).toFixed(2))
        ]
      );

      const dbProduct = productMap.get(item.productId);
      const nextStock = Math.max(0, Number(dbProduct.stock || 0) - item.quantity);
      await client.query('UPDATE floret_products SET stock = $1 WHERE id = $2', [nextStock, item.productId]);
      dbProduct.stock = nextStock;

      if (nextStock <= 3) {
        queuedNotifications.push({
          type: 'stock_low',
          title: `Stock bajo en ${dbProduct.name}`,
          message: `Quedan ${nextStock} unidades de ${dbProduct.name}.`,
          productId: item.productId,
          reviewScope: 'stock',
          orderId: order.id,
          meta: { stock: nextStock, productId: item.productId }
        });
      }
    }

    queuedNotifications.push({
      type: 'order_new',
      title: `Nuevo pedido #${order.id}`,
      message: `${safeName} confirmo una compra por $${Number(order.total || 0).toLocaleString('es-UY')}.`,
      reviewScope: 'order',
      orderId: order.id,
      meta: { orderId: order.id, total: Number(order.total || 0) }
    });

    await client.query('COMMIT');
    for (const notification of queuedNotifications) {
      await createFloretNotification(notification);
    }
    res.json({ success: true, orderId: order.id, order });
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch (_rollbackErr) { }
    console.error('Error creando orden Floret:', e);
    res.status(500).json({ error: e.message || 'Error interno' });
  } finally {
    client.release();
  }
});

app.get('/floret/seller/dashboard', async (req, res) => {
  try {
    const userId = Number(req.query.userId || 0) || null;
    const email = String(req.query.email || '');
    const access = await assertFloretMalevoAccess({ userId, email });
    if (!access.allowed) return res.status(403).json({ error: access.reason || 'No autorizado' });

    const [statsRes, lowStockRes, recentOrdersRes] = await Promise.all([
      pool.query(
        `SELECT
          COUNT(*)::int AS total_orders,
          COUNT(*) FILTER (WHERE status = 'new')::int AS pending_orders,
          COUNT(*) FILTER (WHERE status = 'preparing')::int AS preparing_orders,
          COUNT(*) FILTER (WHERE status = 'shipped')::int AS shipped_orders,
          COUNT(*) FILTER (WHERE status = 'delivered')::int AS delivered_orders,
          COALESCE(SUM(total), 0)::numeric AS gross_total
         FROM floret_orders`
      ),
      pool.query(
        `SELECT id, name, stock, price
         FROM floret_products
         WHERE stock <= 5
         ORDER BY stock ASC, created_at DESC
         LIMIT 12`
      ),
      pool.query(
        `SELECT id, buyer_name, buyer_email, total, status, created_at
         FROM floret_orders
         ORDER BY created_at DESC
         LIMIT 12`
      )
    ]);

    const stats = statsRes.rows[0] || {};
    res.json({
      stats: {
        totalOrders: Number(stats.total_orders || 0),
        pendingOrders: Number(stats.pending_orders || 0),
        preparingOrders: Number(stats.preparing_orders || 0),
        shippedOrders: Number(stats.shipped_orders || 0),
        deliveredOrders: Number(stats.delivered_orders || 0),
        grossTotal: Number(stats.gross_total || 0)
      },
      lowStock: lowStockRes.rows || [],
      recentOrders: recentOrdersRes.rows || []
    });
  } catch (e) {
    console.error('Error obteniendo dashboard seller Floret:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

app.get('/floret/seller/orders', async (req, res) => {
  try {
    const userId = Number(req.query.userId || 0) || null;
    const email = String(req.query.email || '');
    const status = normalizeFloretOrderStatus(req.query.status || '');
    const limit = Math.min(200, Math.max(10, Number(req.query.limit || 80) || 80));
    const access = await assertFloretMalevoAccess({ userId, email });
    if (!access.allowed) return res.status(403).json({ error: access.reason || 'No autorizado' });

    const whereSql = req.query.status ? 'WHERE o.status = $1' : '';
    const params = req.query.status ? [status, limit] : [limit];
    const limitRef = req.query.status ? '$2' : '$1';

    const ordersRes = await pool.query(
      `SELECT
        o.id,
        o.buyer_name,
        o.buyer_email,
        o.buyer_phone,
        o.shipping_address,
        o.shipping_city,
        o.payment_method,
        o.payment_ref,
        o.total,
        o.status,
        o.created_at,
        o.updated_at
       FROM floret_orders o
       ${whereSql}
       ORDER BY o.created_at DESC
       LIMIT ${limitRef}`,
      params
    );

    const orderIds = ordersRes.rows.map((row) => row.id);
    let itemMap = new Map();
    if (orderIds.length) {
      const itemsRes = await pool.query(
        `SELECT id, order_id, product_id, product_name, unit_price, quantity, size, line_total
         FROM floret_order_items
         WHERE order_id = ANY($1::int[])
         ORDER BY id ASC`,
        [orderIds]
      );
      itemMap = itemsRes.rows.reduce((map, item) => {
        const key = Number(item.order_id);
        if (!map.has(key)) map.set(key, []);
        map.get(key).push(item);
        return map;
      }, new Map());
    }

    const orders = ordersRes.rows.map((order) => ({
      ...order,
      items: itemMap.get(Number(order.id)) || []
    }));
    res.json({ orders });
  } catch (e) {
    console.error('Error obteniendo ordenes seller Floret:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

app.patch('/floret/seller/orders/:id/status', async (req, res) => {
  try {
    const orderId = Number(req.params.id);
    const userId = Number(req.body?.userId || 0) || null;
    const email = String(req.body?.email || '');
    const nextStatus = normalizeFloretOrderStatus(req.body?.status || '');
    const access = await assertFloretMalevoAccess({ userId, email });
    if (!access.allowed) return res.status(403).json({ error: access.reason || 'No autorizado' });
    if (!orderId) return res.status(400).json({ error: 'ID de orden invalido' });

    const orderRes = await pool.query(
      `UPDATE floret_orders
       SET status = $1, updated_at = NOW()
       WHERE id = $2
       RETURNING *`,
      [nextStatus, orderId]
    );
    if (!orderRes.rows.length) return res.status(404).json({ error: 'Orden no encontrada' });

    const order = orderRes.rows[0];
    await createFloretNotification({
      type: 'order_status',
      title: `Pedido #${order.id} actualizado`,
      message: `El pedido #${order.id} ahora esta en estado "${nextStatus}".`,
      reviewScope: 'order',
      orderId: order.id,
      meta: { orderId: order.id, status: nextStatus }
    });

    res.json({ success: true, order });
  } catch (e) {
    console.error('Error actualizando estado de orden Floret:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Obtener cuota
app.get('/floret/quota/:userId', async (req, res) => {
  try {
    const quota = await getFloretQuota(req.params.userId);
    res.json(quota);
  } catch (e) {
    res.status(500).json({ error: 'Error obteniendo cuota' });
  }
});

// Otorgar cuota (Solo Super-Admin PowerLevel 2)
app.post('/floret/grant-quota', async (req, res) => {
  const { adminId, targetUserId, amount } = req.body;
  try {
    const admin = await pool.query('SELECT power_level FROM floret_users WHERE id = $1', [adminId]);
    if (!admin.rows[0] || admin.rows[0].power_level < 2) {
      return res.status(403).json({ error: 'No tienes permiso para otorgar cuota' });
    }
    await pool.query('UPDATE floret_admin_quotas SET uploads_today = uploads_today - $1 WHERE user_id = $2', [amount || 1, targetUserId]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Error otorgando cuota' });
  }
});

// Obtener productos
app.get('/floret/products', async (_req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        p.id,
        p.name,
        p.description,
        p.price,
        p.stock,
        p.condition,
        p.images,
        p.requires_size,
        p.sizes,
        p.measurements,
        p.created_at,
        p.seller_email,
        COALESCE(rs.review_count, 0)::int AS review_count,
        COALESCE(rs.avg_rating, 0)::numeric AS avg_rating
      FROM floret_products p
      LEFT JOIN LATERAL (
        SELECT
          COUNT(*) AS review_count,
          ROUND(AVG(rating)::numeric, 1) AS avg_rating
        FROM floret_product_reviews
        WHERE product_id = p.id
      ) rs ON TRUE
      ORDER BY p.created_at DESC
      `);
    const products = rows.map(r => ({
      id: r.id,
      name: r.name,
      description: r.description,
      price: parseFloat(r.price),
      stock: parseInt(r.stock) || 0,
      condition: r.condition,
      images: r.images || [],
      requiresSize: r.requires_size,
      sizes: r.sizes || [],
      measurements: r.measurements,
      sellerEmail: r.seller_email || FLORET_MAIN_SELLER_EMAIL,
      reviewSummary: {
        count: parseInt(r.review_count, 10) || 0,
        avgRating: parseFloat(r.avg_rating) || 0
      }
    }));
    res.json(products);
  } catch (e) {
    console.error('Error obteniendo productos Floret:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Obtener reviews/comentarios de un producto
app.get('/floret/reviews/product/:productId', async (req, res) => {
  try {
    const productId = Number(req.params.productId);
    if (!productId) return res.status(400).json({ error: 'productId invalido' });

    const [reviewsRes, summaryRes] = await Promise.all([
      pool.query(
        `SELECT
          r.id,
          r.product_id,
          r.reviewer_user_id,
          COALESCE(u.username, r.reviewer_name, 'Cliente Floret') AS reviewer_name,
          r.rating,
          r.comment,
          r.created_at
        FROM floret_product_reviews r
        LEFT JOIN floret_users u ON u.id = r.reviewer_user_id
        WHERE r.product_id = $1
        ORDER BY r.created_at DESC`,
        [productId]
      ),
      pool.query(
        `SELECT
          COUNT(*)::int AS review_count,
          COALESCE(ROUND(AVG(rating)::numeric, 1), 0) AS avg_rating
        FROM floret_product_reviews
        WHERE product_id = $1`,
        [productId]
      )
    ]);

    res.json({
      productId,
      summary: {
        count: Number(summaryRes.rows[0]?.review_count || 0),
        avgRating: Number(summaryRes.rows[0]?.avg_rating || 0)
      },
      reviews: reviewsRes.rows
    });
  } catch (e) {
    console.error('Error obteniendo reviews de producto Floret:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Crear review/comentario de producto
app.post('/floret/reviews/product', async (req, res) => {
  try {
    const {
      productId,
      rating,
      comment,
      reviewerUserId = null,
      reviewerName = ''
    } = req.body || {};

    const safeProductId = Number(productId);
    const safeRating = Number(rating);
    const safeComment = String(comment || '').trim();

    if (!safeProductId) return res.status(400).json({ error: 'productId requerido' });
    if (!Number.isInteger(safeRating) || safeRating < 1 || safeRating > 5) {
      return res.status(400).json({ error: 'rating debe estar entre 1 y 5' });
    }
    if (!safeComment) return res.status(400).json({ error: 'comment es requerido' });

    const productRes = await pool.query(
      'SELECT id, name, seller_email FROM floret_products WHERE id = $1 LIMIT 1',
      [safeProductId]
    );
    if (!productRes.rows.length) {
      return res.status(404).json({ error: 'Producto no encontrado' });
    }
    const product = productRes.rows[0];
    const reviewerDisplayName = await resolveFloretReviewerName(reviewerUserId, reviewerName);

    const { rows } = await pool.query(
      `INSERT INTO floret_product_reviews
        (product_id, reviewer_user_id, reviewer_name, rating, comment)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [safeProductId, reviewerUserId || null, reviewerDisplayName, safeRating, safeComment]
    );
    const review = rows[0];

    await createFloretReviewNotification({
      type: 'product_review',
      title: `Nueva review en "${product.name}"`,
      message: `${reviewerDisplayName} dejo ${safeRating} estrellas en ${product.name}.`,
      productId: safeProductId,
      reviewId: review.id,
      reviewScope: 'product'
    });

    res.json({ success: true, review });
  } catch (e) {
    console.error('Error creando review de producto Floret:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Crear review/comentario al vendedor Malevo
app.post('/floret/reviews/seller', async (req, res) => {
  try {
    const {
      rating,
      comment,
      reviewerUserId = null,
      reviewerName = '',
      sellerEmail = FLORET_MAIN_SELLER_EMAIL
    } = req.body || {};

    const safeRating = Number(rating);
    const safeComment = String(comment || '').trim();
    const safeSellerEmail = normalizeFloretEmail(sellerEmail) || FLORET_MAIN_SELLER_EMAIL;

    if (!Number.isInteger(safeRating) || safeRating < 1 || safeRating > 5) {
      return res.status(400).json({ error: 'rating debe estar entre 1 y 5' });
    }
    if (!safeComment) return res.status(400).json({ error: 'comment es requerido' });

    const reviewerDisplayName = await resolveFloretReviewerName(reviewerUserId, reviewerName);
    const { rows } = await pool.query(
      `INSERT INTO floret_seller_reviews
        (seller_email, reviewer_user_id, reviewer_name, rating, comment)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [safeSellerEmail, reviewerUserId || null, reviewerDisplayName, safeRating, safeComment]
    );
    const review = rows[0];

    await createFloretReviewNotification({
      type: 'seller_review',
      title: 'Nueva review para Malevo',
      message: `${reviewerDisplayName} califico a Malevo con ${safeRating} estrellas.`,
      reviewId: review.id,
      reviewScope: 'seller'
    });

    res.json({ success: true, review });
  } catch (e) {
    console.error('Error creando review de seller Floret:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Obtener reviews de Malevo
app.get('/floret/reviews/seller', async (req, res) => {
  try {
    const sellerEmail = normalizeFloretEmail(req.query.sellerEmail) || FLORET_MAIN_SELLER_EMAIL;
    const { rows } = await pool.query(
      `SELECT
        r.id,
        r.seller_email,
        r.reviewer_user_id,
        COALESCE(u.username, r.reviewer_name, 'Cliente Floret') AS reviewer_name,
        r.rating,
        r.comment,
        r.created_at
      FROM floret_seller_reviews r
      LEFT JOIN floret_users u ON u.id = r.reviewer_user_id
      WHERE LOWER(r.seller_email) = LOWER($1)
      ORDER BY r.created_at DESC`,
      [sellerEmail]
    );
    const summaryRes = await pool.query(
      `SELECT
        COUNT(*)::int AS review_count,
        COALESCE(ROUND(AVG(rating)::numeric, 1), 0) AS avg_rating
      FROM floret_seller_reviews
      WHERE LOWER(seller_email) = LOWER($1)`,
      [sellerEmail]
    );

    res.json({
      sellerEmail,
      summary: {
        count: Number(summaryRes.rows[0]?.review_count || 0),
        avgRating: Number(summaryRes.rows[0]?.avg_rating || 0)
      },
      reviews: rows
    });
  } catch (e) {
    console.error('Error obteniendo reviews del seller Floret:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Obtener una review puntual de producto (para modal de notificacion)
app.get('/floret/reviews/product-detail/:reviewId', async (req, res) => {
  try {
    const reviewId = Number(req.params.reviewId);
    if (!reviewId) return res.status(400).json({ error: 'reviewId invalido' });

    const access = await assertFloretMalevoAccess({
      userId: Number(req.query.userId || 0) || null,
      email: req.query.email || ''
    });
    if (!access.allowed) return res.status(403).json({ error: access.reason || 'No autorizado' });

    const { rows } = await pool.query(
      `SELECT
        r.id,
        r.product_id,
        p.name AS product_name,
        COALESCE(u.username, r.reviewer_name, 'Cliente Floret') AS reviewer_name,
        r.rating,
        r.comment,
        r.created_at
      FROM floret_product_reviews r
      LEFT JOIN floret_products p ON p.id = r.product_id
      LEFT JOIN floret_users u ON u.id = r.reviewer_user_id
      WHERE r.id = $1
      LIMIT 1`,
      [reviewId]
    );

    if (!rows.length) return res.status(404).json({ error: 'Review no encontrada' });
    res.json(rows[0]);
  } catch (e) {
    console.error('Error obteniendo detalle review producto Floret:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Notificaciones de Malevo para reviews
app.get('/floret/notifications', async (req, res) => {
  try {
    const userId = Number(req.query.userId || 0) || null;
    const email = String(req.query.email || '');
    const access = await assertFloretMalevoAccess({ userId, email });
    if (!access.allowed) return res.status(403).json({ error: access.reason || 'No autorizado' });

    const safeEmail = normalizeFloretEmail(email) || FLORET_MAIN_SELLER_EMAIL;
    const { rows } = await pool.query(
      `SELECT
        n.id,
        n.type,
        n.title,
        n.message,
        n.product_id,
        n.review_id,
        n.review_scope,
        n.order_id,
        n.meta,
        n.is_read,
        n.created_at,
        p.name AS product_name
      FROM floret_notifications n
      LEFT JOIN floret_products p ON p.id = n.product_id
      WHERE (n.target_user_id = $1)
         OR (LOWER(COALESCE(n.target_email, '')) = LOWER($2))
      ORDER BY n.created_at DESC
      LIMIT 150`,
      [userId || -1, safeEmail]
    );

    const unreadCount = rows.reduce((count, n) => count + (n.is_read ? 0 : 1), 0);
    res.json({ notifications: rows, unreadCount });
  } catch (e) {
    console.error('Error obteniendo notificaciones Floret:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/floret/notifications/read/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    const userId = Number(req.body?.userId || 0) || null;
    const email = String(req.body?.email || '');
    if (!id) return res.status(400).json({ error: 'id invalido' });

    const access = await assertFloretMalevoAccess({ userId, email });
    if (!access.allowed) return res.status(403).json({ error: access.reason || 'No autorizado' });

    const safeEmail = normalizeFloretEmail(email) || FLORET_MAIN_SELLER_EMAIL;
    await pool.query(
      `UPDATE floret_notifications
       SET is_read = TRUE
       WHERE id = $1
         AND ((target_user_id = $2) OR (LOWER(COALESCE(target_email, '')) = LOWER($3)))`,
      [id, userId || -1, safeEmail]
    );
    res.json({ success: true });
  } catch (e) {
    console.error('Error marcando notificacion Floret como leida:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/floret/notifications/read-all', async (req, res) => {
  try {
    const userId = Number(req.body?.userId || 0) || null;
    const email = String(req.body?.email || '');
    const access = await assertFloretMalevoAccess({ userId, email });
    if (!access.allowed) return res.status(403).json({ error: access.reason || 'No autorizado' });

    const safeEmail = normalizeFloretEmail(email) || FLORET_MAIN_SELLER_EMAIL;
    await pool.query(
      `UPDATE floret_notifications
       SET is_read = TRUE
       WHERE (target_user_id = $1)
          OR (LOWER(COALESCE(target_email, '')) = LOWER($2))`,
      [userId || -1, safeEmail]
    );
    res.json({ success: true });
  } catch (e) {
    console.error('Error marcando todas las notificaciones Floret:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Consolidado de reviews (seller + productos) para Malevo
app.get('/floret/reviews/all', async (req, res) => {
  try {
    const userId = Number(req.query.userId || 0) || null;
    const email = String(req.query.email || '');
    const access = await assertFloretMalevoAccess({ userId, email });
    if (!access.allowed) return res.status(403).json({ error: access.reason || 'No autorizado' });

    const sellerEmail = FLORET_MAIN_SELLER_EMAIL;
    const [sellerRows, productRows] = await Promise.all([
      pool.query(
        `SELECT
          r.id,
          'seller' AS scope,
          NULL::int AS product_id,
          NULL::text AS product_name,
          COALESCE(u.username, r.reviewer_name, 'Cliente Floret') AS reviewer_name,
          r.rating,
          r.comment,
          r.created_at
        FROM floret_seller_reviews r
        LEFT JOIN floret_users u ON u.id = r.reviewer_user_id
        WHERE LOWER(r.seller_email) = LOWER($1)
        ORDER BY r.created_at DESC`,
        [sellerEmail]
      ),
      pool.query(
        `SELECT
          r.id,
          'product' AS scope,
          r.product_id,
          p.name AS product_name,
          COALESCE(u.username, r.reviewer_name, 'Cliente Floret') AS reviewer_name,
          r.rating,
          r.comment,
          r.created_at
        FROM floret_product_reviews r
        LEFT JOIN floret_products p ON p.id = r.product_id
        LEFT JOIN floret_users u ON u.id = r.reviewer_user_id
        WHERE LOWER(COALESCE(p.seller_email, $1)) = LOWER($1)
        ORDER BY r.created_at DESC`
        ,
        [sellerEmail]
      )
    ]);

    const allReviews = [...sellerRows.rows, ...productRows.rows]
      .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    res.json({
      sellerReviews: sellerRows.rows,
      productReviews: productRows.rows,
      allReviews
    });
  } catch (e) {
    console.error('Error obteniendo consolidado de reviews Floret:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Crear producto (admin con cuotas y Cloudinary)
app.post('/floret/products', upload.array('images'), async (req, res) => {
  let { name, description, price, stock, condition, requiresSize, sizes, measurements, userId, images: existingImages } = req.body;

  if (!userId) return res.status(401).json({ error: 'Usuario no identificado' });

  try {
    const userRes = await pool.query('SELECT * FROM floret_users WHERE id = $1', [userId]);
    const user = userRes.rows[0];
    if (!user || !user.is_admin) return res.status(403).json({ error: 'No tienes permisos de administrador' });

    // Verificar cuota para Sub-Admin (Malevo)
    if (user.power_level === 1) {
      const quota = await getFloretQuota(user.id);
      if (quota.uploads_today >= quota.max_daily) {
        return res.status(429).json({ error: 'Has alcanzado tu cuota diaria (4 productos). La cuota se reinicia 24hs despuÃƒÂ©s de tu primera publicaciÃƒÂ³n del ciclo.' });
      }
    }

    // Procesar imÃƒÂ¡genes (Cloudinary a travÃƒÂ©s de multer-storage-cloudinary)
    let imgUrls = [];
    if (req.files && req.files.length > 0) {
      imgUrls = req.files.map(f => f.path);
    } else if (existingImages) {
      imgUrls = Array.isArray(existingImages) ? existingImages : existingImages.split(',').map(s => s.trim());
    }

    if (!name || !price) {
      return res.status(400).json({ error: 'Nombre y precio son requeridos' });
    }

    const sellerEmail = normalizeFloretEmail(user.email) || FLORET_MAIN_SELLER_EMAIL;
    const { rows } = await pool.query(`
      INSERT INTO floret_products(name, description, price, stock, condition, images, requires_size, sizes, measurements, seller_email)
    VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *
      `, [
      name,
      description || '',
      price,
      parseInt(stock) || 1,
      condition || 'Nuevo',
      imgUrls,
      requiresSize === 'true' || requiresSize === true,
      Array.isArray(sizes) ? sizes : (sizes ? sizes.split(',').map(s => s.trim()) : []),
      measurements || '',
      sellerEmail
    ]);

    // Actualizar cuota si es sub-admin
    if (user.power_level === 1) {
      await pool.query(`
        UPDATE floret_admin_quotas 
        SET uploads_today = uploads_today + 1,
      last_upload_time = COALESCE(last_upload_time, NOW()) 
        WHERE user_id = $1
      `, [user.id]);
    }

    res.json({ success: true, product: rows[0] });
  } catch (e) {
    console.error('Error creando producto Floret:', e);
    res.status(500).json({ error: 'Error interno de servidor' });
  }
});

app.patch('/floret/products/:id', async (req, res) => {
  const productId = Number(req.params.id || 0);
  const userId = Number(req.body?.userId || 0);
  const email = String(req.body?.email || '');

  if (!productId) return res.status(400).json({ error: 'Producto invalido' });
  if (!userId && !email) return res.status(401).json({ error: 'No autorizado' });

  try {
    const access = await assertFloretMalevoAccess({ userId, email });
    if (!access.allowed) return res.status(403).json({ error: access.reason || 'Sin permisos' });

    const updates = [];
    const values = [];

    if (req.body?.name !== undefined) {
      const safe = String(req.body.name || '').trim();
      if (!safe) return res.status(400).json({ error: 'Nombre invalido' });
      values.push(safe);
      updates.push(`name = $${values.length}`);
    }
    if (req.body?.description !== undefined) {
      values.push(String(req.body.description || '').trim());
      updates.push(`description = $${values.length}`);
    }
    if (req.body?.price !== undefined) {
      const price = Number(req.body.price);
      if (!Number.isFinite(price) || price <= 0) return res.status(400).json({ error: 'Precio invalido' });
      values.push(price);
      updates.push(`price = $${values.length}`);
    }
    if (req.body?.stock !== undefined) {
      const stock = Math.max(0, parseInt(req.body.stock, 10) || 0);
      values.push(stock);
      updates.push(`stock = $${values.length}`);
    }
    if (req.body?.condition !== undefined) {
      const safeCondition = String(req.body.condition || '').trim() || 'Nuevo';
      values.push(safeCondition);
      updates.push(`condition = $${values.length}`);
    }
    if (req.body?.requiresSize !== undefined) {
      const requiresSize = req.body.requiresSize === true || req.body.requiresSize === 'true';
      values.push(requiresSize);
      updates.push(`requires_size = $${values.length}`);
    }
    if (req.body?.sizes !== undefined) {
      const sizesValue = req.body.sizes;
      const normalizedSizes = Array.isArray(sizesValue)
        ? sizesValue.map((size) => String(size || '').trim()).filter(Boolean)
        : String(sizesValue || '')
          .split(',')
          .map((size) => size.trim())
          .filter(Boolean);
      values.push(normalizedSizes);
      updates.push(`sizes = $${values.length}`);
    }
    if (req.body?.measurements !== undefined) {
      values.push(String(req.body.measurements || '').trim());
      updates.push(`measurements = $${values.length}`);
    }
    if (req.body?.images !== undefined) {
      const imagesValue = req.body.images;
      const normalizedImages = Array.isArray(imagesValue)
        ? imagesValue.map((url) => String(url || '').trim()).filter(Boolean)
        : String(imagesValue || '')
          .split(',')
          .map((url) => url.trim())
          .filter(Boolean);
      values.push(normalizedImages);
      updates.push(`images = $${values.length}`);
    }

    if (!updates.length) {
      return res.status(400).json({ error: 'Sin cambios para actualizar' });
    }

    values.push(productId);
    const { rows } = await pool.query(
      `UPDATE floret_products
       SET ${updates.join(', ')}
       WHERE id = $${values.length}
       RETURNING *`,
      values
    );

    if (!rows.length) return res.status(404).json({ error: 'Producto no encontrado' });
    res.json({ success: true, product: rows[0] });
  } catch (e) {
    console.error('Error actualizando producto Floret:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/floret/products/:id/mark-sold-out', async (req, res) => {
  const productId = Number(req.params.id || 0);
  const userId = Number(req.body?.userId || 0);
  const email = String(req.body?.email || '');

  if (!productId) return res.status(400).json({ error: 'Producto invalido' });
  if (!userId && !email) return res.status(401).json({ error: 'No autorizado' });

  try {
    const access = await assertFloretMalevoAccess({ userId, email });
    if (!access.allowed) return res.status(403).json({ error: access.reason || 'Sin permisos' });

    const { rows } = await pool.query(
      `UPDATE floret_products
       SET stock = 0
       WHERE id = $1
       RETURNING *`,
      [productId]
    );
    if (!rows.length) return res.status(404).json({ error: 'Producto no encontrado' });
    res.json({ success: true, product: rows[0] });
  } catch (e) {
    console.error('Error agotando producto Floret:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Eliminar producto
app.delete('/floret/products/:id', async (req, res) => {
  const id = Number(req.params.id || 0);
  const userId = Number(req.query.userId || 0);
  const email = String(req.query.email || '');

  if (!id) return res.status(400).json({ error: 'Producto invalido' });
  if (!userId && !email) return res.status(401).json({ error: 'No autorizado' });

  try {
    const access = await assertFloretMalevoAccess({ userId, email });
    if (!access.allowed) return res.status(403).json({ error: access.reason || 'Sin permisos' });

    await pool.query('DELETE FROM floret_products WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (e) {
    console.error('Error eliminando producto Floret:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});


// ===== OCEAN PAY - MODO OFFLINE (SIN INTERNET) =====
// Ocean Pay funciona completamente sin internet usando localStorage
app.get('/ocean-pay/index.html', (_req, res) => {
  try {
    const html = fs.readFileSync(join(__dirname, 'Ocean Pay', 'index.html'), 'utf-8');
    res.type('html').send(html);
  } catch (e) {
    res.status(404).send('Archivo no encontrado');
  }
});

// Servir archivos estÃƒÂ¡ticos de Ocean Pay
app.use('/ocean-pay', express.static(join(__dirname, 'Ocean Pay')));

// A Wild Question Game - frontend route
app.get('/a-wild-question-game', (_req, res) => {
  try {
    const html = fs.readFileSync(join(__dirname, 'A Wild Question Game', 'index.html'), 'utf-8');
    res.type('html').send(html);
  } catch (e) {
    res.status(404).send('Archivo no encontrado');
  }
});
app.use('/a-wild-question-game', express.static(join(__dirname, 'A Wild Question Game')));

// ===== WILD TRANSFER - COMPARTIR ARCHIVOS (MULTIPLE) =====
const wildTransferStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = join(__dirname, 'uploads', 'wild-transfer');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    // Si no tenemos un cÃƒÂ³digo en el request (primer archivo), lo generamos
    if (!req.sessionCode) {
      req.sessionCode = Math.random().toString(36).substring(2, 8).toUpperCase();
    }
    cb(null, req.sessionCode + '-' + Date.now() + '-' + file.originalname);
  }
});

const wildTransferUpload = multer({ storage: wildTransferStorage });

// FunciÃƒÂ³n para limpiar archivos viejos (> 24 horas)
const cleanOldWildTransferFiles = () => {
  const dir = join(__dirname, 'uploads', 'wild-transfer');
  if (!fs.existsSync(dir)) return;
  const now = Date.now();
  const files = fs.readdirSync(dir);
  files.forEach(f => {
    const filePath = join(dir, f);
    const stats = fs.statSync(filePath);
    const age = now - stats.mtimeMs;
    // 24 horas = 86400000 ms
    if (age > 86400000) {
      fs.unlinkSync(filePath);
      console.log(`Ã°Å¸â€”â€˜Ã¯Â¸Â Wild Transfer: Archivo expirado eliminado: ${f} `);
    }
  });
};

// Limpiar cada 6 horas
setInterval(cleanOldWildTransferFiles, 6 * 60 * 60 * 1000);

app.use('/wild-transfer', express.static(join(__dirname, 'WildTransfer')));

app.post('/api/wild-transfer/upload', wildTransferUpload.array('files', 10), async (req, res) => {
  if (!req.files || req.files.length === 0) return res.status(400).json({ error: 'No se subieron archivos' });
  const totalBytes = req.files.reduce((sum, f) => sum + Number(f.size || 0), 0);
  const userId = getOceanPayUserIdFromAuthHeader(req.headers.authorization);
  let reward = null;
  if (userId) {
    const rewardAmount = computeWildTransferReward(totalBytes, req.files.length, 'upload');
    reward = await awardWildTransferCurrency(
      userId,
      rewardAmount,
      `Recompensa por subir ${req.files.length} archivo(s)`,
      { transferCode: req.sessionCode, action: 'upload' }
    );
  }
  console.log(`Ã°Å¸â€œÂ¤ ${req.files.length} archivos subidos a Wild Transfer con cÃƒÂ³digo ${req.sessionCode} `);
  res.json({
    success: true,
    code: req.sessionCode,
    files: req.files.map(f => ({ name: f.originalname, size: f.size })),
    reward: reward ? {
      currency: WT_RELAY_CURRENCY,
      amount: reward.amount,
      newBalance: reward.newBalance
    } : null
  });
});

app.get('/api/wild-transfer/info/:code', (req, res) => {
  try {
    const { code } = req.params;
    const dir = join(__dirname, 'uploads', 'wild-transfer');
    if (!fs.existsSync(dir)) return res.json({ success: false, error: 'No hay archivos' });

    const allFiles = fs.readdirSync(dir);
    const sessionFiles = allFiles.filter(f => f.startsWith(code.toUpperCase() + '-'));

    if (sessionFiles.length === 0) return res.status(404).json({ success: false, error: 'CÃƒÂ³digo no encontrado' });

    const fileList = sessionFiles.map(f => {
      const parts = f.split('-');
      return {
        id: f,
        name: parts.slice(2).join('-'), // Quitamos CODE y TIMESTAMP
        size: fs.statSync(join(dir, f)).size
      };
    });

    res.json({ success: true, code, files: fileList });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Compatibilidad con URL antigua de descarga
app.get('/api/wild-transfer/download/:code', (req, res) => {
  const { code } = req.params;
  const dir = join(__dirname, 'uploads', 'wild-transfer');
  if (!fs.existsSync(dir)) return res.status(404).send('Directorio no encontrado');

  const files = fs.readdirSync(dir);
  const sessionFiles = files.filter(f => f.startsWith(code.toUpperCase() + '-'));

  if (sessionFiles.length === 0) return res.status(404).send('CÃƒÂ³digo no encontrado');

  // Si solo hay uno, lo descargamos directamente como antes
  if (sessionFiles.length === 1) {
    const f = sessionFiles[0];
    const filePath = join(dir, f);
    const originalName = f.split('-').slice(2).join('-');
    return res.download(filePath, originalName);
  }

  // Si hay varios, no podemos descargar todos en un solo GET de navegador fÃƒÂ¡cilmente sin ZIP
  // AsÃƒÂ­ que redirigimos a la interfaz para que los vea
  res.send(`Este cÃƒÂ³digo contiene ${sessionFiles.length} archivos.Por favor usa la interfaz de Wild Transfer para revisarlos.`);
});

app.get('/api/wild-transfer/download-file/:filename', async (req, res) => {
  const { filename } = req.params;
  const filePath = join(__dirname, 'uploads', 'wild-transfer', filename);
  if (fs.existsSync(filePath)) {
    const originalName = filename.split('-').slice(2).join('-');
    const userId = getOceanPayUserIdFromAuthHeader(req.headers.authorization);
    if (userId) {
      const stats = fs.statSync(filePath);
      const rewardAmount = computeWildTransferReward(Number(stats.size || 0), 1, 'receive');
      const reward = await awardWildTransferCurrency(
        userId,
        rewardAmount,
        `Recompensa por recibir archivo (${originalName})`,
        { transferCode: filename.split('-')[0] || null, action: 'receive' }
      );
      if (reward) {
        res.setHeader('X-WT-Reward-Currency', WT_RELAY_CURRENCY);
        res.setHeader('X-WT-Reward-Amount', String(reward.amount));
        res.setHeader('X-WT-New-Balance', String(reward.newBalance));
      }
    }
    res.download(filePath, originalName);
  } else {
    res.status(404).send('Archivo no encontrado');
  }
});

const WT_PROJECT_ID = 'WildTransfer';
const WT_WEEKLY_INTERVAL_DAYS = 7;
const WT_RELAY_CURRENCY = 'relayshards';
const WT_RELAY_CURRENCY_LABEL = 'RelayShards';
const WT_WEEKLY_PLANS = [
  {
    id: 'relay-core',
    label: 'Relay Core',
    perks: [
      'Up to 10 files per transfer',
      'Up to 2 GB total per batch',
      'Priority sync window'
    ],
    limits: { maxFiles: 10, maxBatchMb: 2048 },
    priceByCurrency: { [WT_RELAY_CURRENCY]: 160 }
  },
  {
    id: 'relay-plus',
    label: 'Relay Plus',
    perks: [
      'Up to 20 files per transfer',
      'Up to 8 GB total per batch',
      'Fast lane delivery'
    ],
    limits: { maxFiles: 20, maxBatchMb: 8192 },
    priceByCurrency: { [WT_RELAY_CURRENCY]: 340 }
  },
  {
    id: 'relay-ultra',
    label: 'Relay Ultra',
    perks: [
      'Up to 40 files per transfer',
      'Up to 20 GB total per batch',
      'Highest relay priority'
    ],
    limits: { maxFiles: 40, maxBatchMb: 20480 },
    priceByCurrency: { [WT_RELAY_CURRENCY]: 560 }
  }
];
const WT_PLAN_MAP = new Map(WT_WEEKLY_PLANS.map((p) => [p.id, p]));
const WT_META_CURRENCIES = new Set(['amber', 'ecotokens']);
let wtSubscriptionColumnsCache = { expiresAt: 0, columns: new Set() };

function getOceanPayUserIdFromAuthHeader(authHeader) {
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  try {
    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    const candidate = decoded.id || decoded.uid;
    const userId = Number(candidate);
    return Number.isFinite(userId) ? userId : null;
  } catch (_e) {
    return null;
  }
}

function normalizeWtCurrency(currency) {
  return String(currency || '').trim().toLowerCase();
}

function normalizeWtPlanName(name) {
  const raw = String(name || '').toLowerCase();
  if (raw.includes('ultra')) return 'relay-ultra';
  if (raw.includes('plus')) return 'relay-plus';
  if (raw.includes('core')) return 'relay-core';
  return 'relay-core';
}

function computeWildTransferReward(totalBytes, fileCount, action) {
  const mb = Math.max(0, Number(totalBytes || 0) / (1024 * 1024));
  const files = Math.max(1, Number(fileCount || 1));
  if (action === 'receive') {
    return Math.max(1, Math.round((mb * 0.65) + (files * 0.4)));
  }
  return Math.max(2, Math.round((mb * 1.6) + (files * 1.1)));
}

async function awardWildTransferCurrency(userId, amount, reason, extraMeta = {}) {
  const safeAmount = Math.floor(Number(amount || 0));
  if (!Number.isFinite(userId) || userId <= 0 || !Number.isFinite(safeAmount) || safeAmount <= 0) {
    return null;
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { rows: cards } = await client.query(
      `SELECT id
       FROM ocean_pay_cards
       WHERE user_id = $1 AND COALESCE(is_active, true) = true
       ORDER BY is_primary DESC, id ASC
       LIMIT 1
       FOR UPDATE`,
      [userId]
    );

    if (!cards.length) {
      await client.query('ROLLBACK');
      return null;
    }

    const cardId = Number(cards[0].id);
    await client.query(
      `INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount)
       VALUES ($1, $2, 0)
       ON CONFLICT (card_id, currency_type) DO NOTHING`,
      [cardId, WT_RELAY_CURRENCY]
    );

    const { rows: balanceRows } = await client.query(
      `SELECT amount
       FROM ocean_pay_card_balances
       WHERE card_id = $1 AND currency_type = $2
       FOR UPDATE`,
      [cardId, WT_RELAY_CURRENCY]
    );
    const previousBalance = Number(balanceRows[0]?.amount || 0);
    const newBalance = previousBalance + safeAmount;

    await client.query(
      `UPDATE ocean_pay_card_balances
       SET amount = $1
       WHERE card_id = $2 AND currency_type = $3`,
      [newBalance, cardId, WT_RELAY_CURRENCY]
    );

    await client.query(
      `UPDATE ocean_pay_cards
       SET balances = jsonb_set(
         COALESCE(balances, '{}'::jsonb),
         '{relayshards}',
         to_jsonb($1::numeric),
         true
       )
       WHERE id = $2`,
      [newBalance, cardId]
    );

    await client.query(
      `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
       VALUES ($1, $2, $3, $4, $5)`,
      [userId, reason || 'Recompensa WildTransfer', safeAmount, 'WildTransfer', WT_RELAY_CURRENCY]
    );

    await client.query(
      `INSERT INTO ocean_pay_notifications (user_id, type, title, message)
       VALUES ($1, 'success', $2, $3)`,
      [
        userId,
        'Recompensa WildTransfer',
        `Ganaste +${safeAmount} ${WT_RELAY_CURRENCY_LABEL} por ${extraMeta.action === 'receive' ? 'recibir' : 'subir'} archivos.`
      ]
    ).catch(() => null);

    await client.query('COMMIT');
    return { amount: safeAmount, previousBalance, newBalance, cardId };
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('WildTransfer reward error:', error);
    return null;
  } finally {
    client.release();
  }
}

function serializeWtPlan(plan) {
  return {
    id: plan.id,
    label: plan.label,
    perks: plan.perks,
    limits: plan.limits,
    priceByCurrency: plan.priceByCurrency,
    checkoutCurrency: WT_RELAY_CURRENCY,
    cadence: 'weekly'
  };
}

async function getWtSubscriptionColumnSet() {
  const now = Date.now();
  if (wtSubscriptionColumnsCache.columns.size > 0 && now < wtSubscriptionColumnsCache.expiresAt) {
    return wtSubscriptionColumnsCache.columns;
  }
  const { rows } = await pool.query(
    `SELECT column_name
     FROM information_schema.columns
     WHERE table_schema = 'public'
       AND table_name = 'ocean_pay_subscriptions'`
  );
  const set = new Set(rows.map((r) => String(r.column_name || '').toLowerCase()));
  wtSubscriptionColumnsCache = {
    columns: set,
    expiresAt: now + 5 * 60 * 1000
  };
  return set;
}

async function cancelLegacyWildTransferSubscriptions({ userId = null, client = null } = {}) {
  const ownClient = !client;
  const db = client || await pool.connect();
  try {
    if (ownClient) await db.query('BEGIN');

    const columns = await getWtSubscriptionColumnSet();
    const hasEndDate = columns.has('end_date');
    const hasNextPayment = columns.has('next_payment');
    const hasStatus = columns.has('status');

    const setClauses = [];
    if (hasStatus) setClauses.push(`status = 'cancelled'`);
    if (hasEndDate) setClauses.push('end_date = NOW()');
    if (hasNextPayment) setClauses.push('next_payment = NOW()');
    if (!setClauses.length) {
      if (ownClient) await db.query('COMMIT');
      return { migrated: 0 };
    }

    const params = [WT_PROJECT_ID, WT_RELAY_CURRENCY];
    const whereClauses = [
      'LOWER(COALESCE(project_id, \'\')) = LOWER($1)',
      'LOWER(COALESCE(currency, \'\')) <> LOWER($2)'
    ];
    if (hasStatus) {
      whereClauses.push("(status IS NULL OR LOWER(status) = 'active')");
    }
    if (Number.isFinite(Number(userId)) && Number(userId) > 0) {
      params.push(Number(userId));
      whereClauses.push(`user_id = $${params.length}`);
    }

    const { rowCount } = await db.query(
      `UPDATE ocean_pay_subscriptions
       SET ${setClauses.join(', ')}
       WHERE ${whereClauses.join(' AND ')}`,
      params
    );

    if (rowCount > 0 && Number.isFinite(Number(userId)) && Number(userId) > 0) {
      await db.query(
        `INSERT INTO ocean_pay_notifications (user_id, type, title, message)
         VALUES ($1, 'info', $2, $3)`,
        [
          Number(userId),
          'Migracion RelayShards',
          `Tu suscripcion legacy de WildTransfer fue cancelada automaticamente. Vuelve a suscribirte con ${WT_RELAY_CURRENCY_LABEL}.`
        ]
      ).catch(() => null);
    }

    if (ownClient) await db.query('COMMIT');
    return { migrated: Number(rowCount || 0) };
  } catch (error) {
    if (ownClient) await db.query('ROLLBACK');
    throw error;
  } finally {
    if (ownClient) db.release();
  }
}

app.get('/wildtransfer/subscription/plans', (_req, res) => {
  res.json({
    success: true,
    projectId: WT_PROJECT_ID,
    currency: WT_RELAY_CURRENCY,
    cadence: 'weekly',
    plans: WT_WEEKLY_PLANS.map(serializeWtPlan)
  });
});

app.get('/wildtransfer/subscription/status', async (req, res) => {
  try {
    const userId = getOceanPayUserIdFromAuthHeader(req.headers.authorization);
    if (!userId) return res.status(401).json({ error: 'Token de Ocean Pay requerido' });
    await cancelLegacyWildTransferSubscriptions({ userId });

    const columns = await getWtSubscriptionColumnSet();
    const hasEndDate = columns.has('end_date');
    const hasNextPayment = columns.has('next_payment');
    const hasStatus = columns.has('status');
    const hasSubName = columns.has('sub_name');
    const expiryExpr = hasEndDate && hasNextPayment
      ? 'COALESCE(end_date, next_payment, created_at)'
      : (hasEndDate ? 'COALESCE(end_date, created_at)' : (hasNextPayment ? 'COALESCE(next_payment, created_at)' : 'created_at'));
    const statusClause = hasStatus ? "AND (status IS NULL OR LOWER(status) = 'active')" : '';

    const { rows: cardRows } = await pool.query(
      `SELECT id, card_name, is_primary
       FROM ocean_pay_cards
       WHERE user_id = $1 AND COALESCE(is_active, true) = true
       ORDER BY is_primary DESC, id ASC`,
      [userId]
    );

    const { rows: subRows } = await pool.query(
      `SELECT *, ${expiryExpr} AS effective_end_date
       FROM ocean_pay_subscriptions
       WHERE user_id = $1
         AND LOWER(COALESCE(project_id, '')) = LOWER($2)
         AND LOWER(COALESCE(currency, '')) = LOWER($3)
         ${statusClause}
       ORDER BY ${expiryExpr} DESC, created_at DESC
       LIMIT 1`,
      [userId, WT_PROJECT_ID, WT_RELAY_CURRENCY]
    );

    const rawSub = subRows[0] || null;
    const effectiveEnd = rawSub?.effective_end_date ? new Date(rawSub.effective_end_date) : null;
    const isActive = Boolean(rawSub) && effectiveEnd instanceof Date && !Number.isNaN(effectiveEnd.getTime()) && effectiveEnd.getTime() > Date.now();
    const planName = rawSub ? (rawSub.plan_name || (hasSubName ? rawSub.sub_name : '') || 'Relay Core') : '';
    const planId = normalizeWtPlanName(planName);
    const plan = WT_PLAN_MAP.get(planId) || WT_WEEKLY_PLANS[0];

    res.json({
      success: true,
      linked: true,
      projectId: WT_PROJECT_ID,
      cards: cardRows,
      plans: WT_WEEKLY_PLANS.map(serializeWtPlan),
      subscription: isActive ? {
        id: rawSub.id,
        active: true,
        planId,
        planName: plan.label,
        currency: String(rawSub.currency || WT_RELAY_CURRENCY).toLowerCase(),
        price: Number(rawSub.price || plan.priceByCurrency[WT_RELAY_CURRENCY] || 0),
        endsAt: effectiveEnd.toISOString(),
        perks: plan.perks,
        limits: plan.limits
      } : null
    });
  } catch (e) {
    console.error('WildTransfer subscription status error:', e);
    res.status(500).json({ error: 'No se pudo obtener el estado de suscripcion' });
  }
});

app.post('/wildtransfer/subscription/checkout', async (req, res) => {
  const userId = getOceanPayUserIdFromAuthHeader(req.headers.authorization);
  if (!userId) return res.status(401).json({ error: 'Token de Ocean Pay requerido' });

  const planId = String(req.body?.planId || '').trim();
  const currency = WT_RELAY_CURRENCY;
  const preferredCardId = Number(req.body?.cardId || 0);

  const plan = WT_PLAN_MAP.get(planId);
  if (!plan) return res.status(400).json({ error: 'Plan no valido' });
  const price = Number(plan.priceByCurrency[currency]);
  if (!Number.isFinite(price) || price <= 0) {
    return res.status(400).json({ error: 'No se encontro un precio valido para el plan seleccionado' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await cancelLegacyWildTransferSubscriptions({ userId, client });

    const { rows: cards } = await client.query(
      `SELECT id, card_name, is_primary
       FROM ocean_pay_cards
       WHERE user_id = $1 AND COALESCE(is_active, true) = true
       ORDER BY is_primary DESC, id ASC`,
      [userId]
    );
    if (cards.length === 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'No tienes una tarjeta activa en Ocean Pay' });
    }

    const selectedCard = cards.find((c) => Number(c.id) === preferredCardId)
      || cards.find((c) => Boolean(c.is_primary))
      || cards[0];
    if (!selectedCard) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'No se pudo seleccionar una tarjeta valida' });
    }

    let currentBalance = 0;
    let newBalance = 0;

    if (WT_META_CURRENCIES.has(currency)) {
      await client.query(
        `INSERT INTO ocean_pay_metadata (user_id, key, value)
         VALUES ($1, $2, '0')
         ON CONFLICT (user_id, key) DO NOTHING`,
        [userId, currency]
      );
      const { rows: metaRows } = await client.query(
        `SELECT value
         FROM ocean_pay_metadata
         WHERE user_id = $1 AND key = $2
         FOR UPDATE`,
        [userId, currency]
      );
      currentBalance = Number(metaRows[0]?.value || 0);
      if (currentBalance < price) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: `Saldo insuficiente de ${currency.toUpperCase()}` });
      }
      newBalance = currentBalance - price;
      await client.query(
        `UPDATE ocean_pay_metadata
         SET value = $1
         WHERE user_id = $2 AND key = $3`,
        [String(newBalance), userId, currency]
      );
    } else {
      await client.query(
        `INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount)
         VALUES ($1, $2, 0)
         ON CONFLICT (card_id, currency_type) DO NOTHING`,
        [selectedCard.id, currency]
      );
      const { rows: balRows } = await client.query(
        `SELECT amount
         FROM ocean_pay_card_balances
         WHERE card_id = $1 AND currency_type = $2
         FOR UPDATE`,
        [selectedCard.id, currency]
      );
      currentBalance = Number(balRows[0]?.amount || 0);
      if (currentBalance < price) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: `Saldo insuficiente de ${currency.toUpperCase()}` });
      }
      newBalance = currentBalance - price;
      await client.query(
        `UPDATE ocean_pay_card_balances
         SET amount = $1
         WHERE card_id = $2 AND currency_type = $3`,
        [newBalance, selectedCard.id, currency]
      );
    }

    const columns = await getWtSubscriptionColumnSet();
    const hasEndDate = columns.has('end_date');
    const hasNextPayment = columns.has('next_payment');
    const hasStatus = columns.has('status');
    const hasSubName = columns.has('sub_name');
    const hasIntervalDays = columns.has('interval_days');
    const hasStartDate = columns.has('start_date');
    const expiryExpr = hasEndDate && hasNextPayment
      ? 'COALESCE(end_date, next_payment, created_at)'
      : (hasEndDate ? 'COALESCE(end_date, created_at)' : (hasNextPayment ? 'COALESCE(next_payment, created_at)' : 'created_at'));
    const statusClause = hasStatus ? "AND (status IS NULL OR LOWER(status) = 'active')" : '';

    const { rows: existingRows } = await client.query(
      `SELECT id, ${expiryExpr} AS effective_end_date
       FROM ocean_pay_subscriptions
       WHERE user_id = $1
         AND LOWER(COALESCE(project_id, '')) = LOWER($2)
         AND LOWER(COALESCE(currency, '')) = LOWER($3)
         ${statusClause}
       ORDER BY ${expiryExpr} DESC, created_at DESC
       LIMIT 1
       FOR UPDATE`,
      [userId, WT_PROJECT_ID, WT_RELAY_CURRENCY]
    );

    const now = new Date();
    const existing = existingRows[0] || null;
    const existingEnd = existing?.effective_end_date ? new Date(existing.effective_end_date) : null;
    const baseDate = existingEnd instanceof Date && !Number.isNaN(existingEnd.getTime()) && existingEnd.getTime() > now.getTime()
      ? existingEnd
      : now;
    const finalEnd = new Date(baseDate.getTime() + WT_WEEKLY_INTERVAL_DAYS * 24 * 60 * 60 * 1000);

    let subscriptionId = 0;
    if (existing?.id) {
      const updateFields = ['project_id = $1', 'plan_name = $2', 'price = $3', 'currency = $4', 'card_id = $5'];
      const updateValues = [WT_PROJECT_ID, plan.label, price, currency, selectedCard.id];
      if (hasSubName) {
        updateFields.push(`sub_name = $${updateValues.length + 1}`);
        updateValues.push(plan.label);
      }
      if (hasStatus) {
        updateFields.push(`status = $${updateValues.length + 1}`);
        updateValues.push('active');
      }
      if (hasIntervalDays) {
        updateFields.push(`interval_days = $${updateValues.length + 1}`);
        updateValues.push(WT_WEEKLY_INTERVAL_DAYS);
      }
      if (hasNextPayment) {
        updateFields.push(`next_payment = $${updateValues.length + 1}`);
        updateValues.push(finalEnd);
      }
      if (hasEndDate) {
        updateFields.push(`end_date = $${updateValues.length + 1}`);
        updateValues.push(finalEnd);
      }
      updateValues.push(existing.id);

      const updateSql = `
        UPDATE ocean_pay_subscriptions
        SET ${updateFields.join(', ')}
        WHERE id = $${updateValues.length}
        RETURNING id`;
      const { rows: updated } = await client.query(updateSql, updateValues);
      subscriptionId = Number(updated[0]?.id || existing.id);
    } else {
      const insertCols = ['user_id', 'project_id', 'plan_name', 'price', 'currency', 'card_id'];
      const insertVals = [userId, WT_PROJECT_ID, plan.label, price, currency, selectedCard.id];
      if (hasSubName) {
        insertCols.push('sub_name');
        insertVals.push(plan.label);
      }
      if (hasStatus) {
        insertCols.push('status');
        insertVals.push('active');
      }
      if (hasStartDate) {
        insertCols.push('start_date');
        insertVals.push(now);
      }
      if (hasIntervalDays) {
        insertCols.push('interval_days');
        insertVals.push(WT_WEEKLY_INTERVAL_DAYS);
      }
      if (hasNextPayment) {
        insertCols.push('next_payment');
        insertVals.push(finalEnd);
      }
      if (hasEndDate) {
        insertCols.push('end_date');
        insertVals.push(finalEnd);
      }
      const placeholders = insertVals.map((_, idx) => `$${idx + 1}`).join(', ');
      const insertSql = `
        INSERT INTO ocean_pay_subscriptions (${insertCols.join(', ')})
        VALUES (${placeholders})
        RETURNING id`;
      const { rows: inserted } = await client.query(insertSql, insertVals);
      subscriptionId = Number(inserted[0]?.id || 0);
    }

    await client.query(
      `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
       VALUES ($1, $2, $3, $4, $5)`,
      [userId, `Suscripcion semanal: ${plan.label}`, -price, WT_PROJECT_ID, currency]
    );

    await client.query(
      `INSERT INTO ocean_pay_notifications (user_id, type, title, message)
       VALUES ($1, $2, $3, $4)`,
      [
        userId,
        'success',
        'WildTransfer activado',
        `Tu plan ${plan.label} quedo activo hasta ${finalEnd.toLocaleString('es-ES')}.`
      ]
    ).catch(() => null);

    const { rows: finalRows } = await client.query(
      `SELECT *, ${expiryExpr} AS effective_end_date
       FROM ocean_pay_subscriptions
       WHERE id = $1
       LIMIT 1`,
      [subscriptionId]
    );
    const finalSub = finalRows[0] || null;

    await client.query('COMMIT');
    res.json({
      success: true,
      projectId: WT_PROJECT_ID,
      subscription: finalSub ? {
        id: finalSub.id,
        active: true,
        planId: normalizeWtPlanName(finalSub.plan_name || finalSub.sub_name || plan.label),
        planName: finalSub.plan_name || finalSub.sub_name || plan.label,
        currency: String(finalSub.currency || currency).toLowerCase(),
        price: Number(finalSub.price || price),
        endsAt: (finalSub.effective_end_date ? new Date(finalSub.effective_end_date) : finalEnd).toISOString(),
        perks: plan.perks,
        limits: plan.limits
      } : null,
      charged: {
        currency,
        amount: price,
        previousBalance: currentBalance,
        newBalance
      }
    });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('WildTransfer subscription checkout error:', e);
    res.status(500).json({ error: 'No se pudo procesar el checkout de WildTransfer' });
  } finally {
    client.release();
  }
});

const TT_PROJECT_ID = 'Tiger Tasks';
const TT_CURRENCY = 'tigrys';
const TT_WEEKLY_INTERVAL_DAYS = 7;
const TT_DAILY_REWARD = 120;
const TT_TASK_REWARD = 12;
const TT_TASK_DAILY_CAP = 180;
const TT_WEEKLY_PLANS = [
  {
    id: 'cub-starter',
    label: 'Cub Starter',
    perks: ['Resaltador de checklist: hasta 3 importantes', 'Acceso a base Tiger Pass', 'Prioridad estandar', 'Perfil premium inicial'],
    priceByCurrency: { [TT_CURRENCY]: 180 }
  },
  {
    id: 'stripe-plus',
    label: 'Stripe Plus',
    perks: ['Resaltador de checklist: hasta 4 importantes', 'Rendimiento estable', 'Acceso preferente', 'Panel avanzado'],
    priceByCurrency: { [TT_CURRENCY]: 320 }
  },
  {
    id: 'jungle-pro',
    label: 'Jungle Pro',
    perks: ['Resaltador de checklist: hasta 7 importantes', 'Suite Pro Tiger', 'Mayor prioridad', 'Automatizaciones premium'],
    priceByCurrency: { [TT_CURRENCY]: 520 }
  },
  {
    id: 'alpha-claw',
    label: 'Alpha Claw',
    perks: ['Resaltador de checklist: hasta 7 importantes', 'Plan maximo Tiger', 'Prioridad total', 'Beneficios elite'],
    priceByCurrency: { [TT_CURRENCY]: 900 }
  }
];
const TT_PLAN_MAP = new Map(TT_WEEKLY_PLANS.map((p) => [p.id, p]));
let ttSubscriptionColumnsCache = { expiresAt: 0, columns: new Set() };

function normalizeTtPlanName(name) {
  const raw = String(name || '').toLowerCase();
  if (raw.includes('alpha')) return 'alpha-claw';
  if (raw.includes('jungle')) return 'jungle-pro';
  if (raw.includes('stripe')) return 'stripe-plus';
  if (raw.includes('cub')) return 'cub-starter';
  return 'cub-starter';
}

function serializeTtPlan(plan) {
  return {
    id: plan.id,
    label: plan.label,
    perks: plan.perks,
    priceByCurrency: plan.priceByCurrency,
    checkoutCurrency: TT_CURRENCY,
    cadence: 'weekly'
  };
}

async function getTtSubscriptionColumnSet() {
  const now = Date.now();
  if (ttSubscriptionColumnsCache.columns.size > 0 && now < ttSubscriptionColumnsCache.expiresAt) {
    return ttSubscriptionColumnsCache.columns;
  }
  const { rows } = await pool.query(
    `SELECT column_name
     FROM information_schema.columns
     WHERE table_schema = 'public'
       AND table_name = 'ocean_pay_subscriptions'`
  );
  const set = new Set(rows.map((r) => String(r.column_name || '').toLowerCase()));
  ttSubscriptionColumnsCache = {
    columns: set,
    expiresAt: now + 5 * 60 * 1000
  };
  return set;
}

async function ensureTigerCardBalance(client, userId, lockRow = false) {
  const lock = lockRow ? 'FOR UPDATE' : '';
  const { rows: cards } = await client.query(
    `SELECT id
     FROM ocean_pay_cards
     WHERE user_id = $1 AND COALESCE(is_active, true) = true
     ORDER BY is_primary DESC, id ASC
     LIMIT 1
     ${lock}`,
    [userId]
  );
  if (!cards.length) return null;
  const cardId = Number(cards[0].id);
  await client.query(
    `INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount)
     VALUES ($1, $2, 0)
     ON CONFLICT (card_id, currency_type) DO NOTHING`,
    [cardId, TT_CURRENCY]
  );
  return cardId;
}

async function getTigerBalanceForUser(userId) {
  const client = await pool.connect();
  try {
    const cardId = await ensureTigerCardBalance(client, userId, false);
    if (!cardId) return 0;
    const { rows } = await client.query(
      `SELECT amount
       FROM ocean_pay_card_balances
       WHERE card_id = $1 AND currency_type = $2
       LIMIT 1`,
      [cardId, TT_CURRENCY]
    );
    return Number(rows[0]?.amount || 0);
  } finally {
    client.release();
  }
}

async function awardTigerCurrency({ userId, amount, claimType, claimKey, reason }) {
  const safeAmount = Math.max(0, Math.floor(Number(amount || 0)));
  const safeUserId = Number(userId || 0);
  if (!Number.isFinite(safeUserId) || safeUserId <= 0 || safeAmount <= 0) {
    return { awarded: false, error: 'Parï¿½metros invï¿½lidos' };
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const cardId = await ensureTigerCardBalance(client, safeUserId, true);
    if (!cardId) {
      await client.query('ROLLBACK');
      return { awarded: false, error: 'No tienes tarjeta activa en Ocean Pay' };
    }

    if (claimType === 'task_complete') {
      const { rows: capRows } = await client.query(
        `SELECT COALESCE(SUM(amount), 0) AS total
         FROM tiger_tasks_reward_claims
         WHERE user_id = $1
           AND claim_type = 'task_complete'
           AND created_at::date = CURRENT_DATE`,
        [safeUserId]
      );
      const currentToday = Number(capRows[0]?.total || 0);
      if (currentToday >= TT_TASK_DAILY_CAP) {
        await client.query('ROLLBACK');
        return { awarded: false, amount: 0, message: 'Lï¿½mite diario de Tigrys por tareas alcanzado.' };
      }
    }

    const { rows: claimRows } = await client.query(
      `INSERT INTO tiger_tasks_reward_claims (user_id, claim_type, claim_key, amount)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id, claim_type, claim_key) DO NOTHING
       RETURNING id`,
      [safeUserId, claimType, claimKey, safeAmount]
    );
    if (!claimRows.length) {
      await client.query('ROLLBACK');
      return { awarded: false, amount: 0, message: 'Esta recompensa ya fue reclamada.' };
    }

    const { rows: balanceRows } = await client.query(
      `SELECT amount
       FROM ocean_pay_card_balances
       WHERE card_id = $1 AND currency_type = $2
       FOR UPDATE`,
      [cardId, TT_CURRENCY]
    );
    const previousBalance = Number(balanceRows[0]?.amount || 0);
    const newBalance = previousBalance + safeAmount;

    await client.query(
      `UPDATE ocean_pay_card_balances
       SET amount = $1
       WHERE card_id = $2 AND currency_type = $3`,
      [newBalance, cardId, TT_CURRENCY]
    );
    await client.query(
      `UPDATE ocean_pay_cards
       SET balances = jsonb_set(
         COALESCE(balances, '{}'::jsonb),
         '{tigrys}',
         to_jsonb($1::numeric),
         true
       )
       WHERE id = $2`,
      [newBalance, cardId]
    );
    await client.query(
      `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
       VALUES ($1, $2, $3, $4, $5)`,
      [safeUserId, reason || 'Recompensa Tiger Tasks', safeAmount, TT_PROJECT_ID, TT_CURRENCY]
    );
    await client.query(
      `INSERT INTO ocean_pay_notifications (user_id, type, title, message)
       VALUES ($1, 'success', $2, $3)`,
      [safeUserId, 'Tigrys recibidos', `Ganaste +${safeAmount} TIGRYS en Tiger Tasks.`]
    ).catch(() => null);

    await client.query('COMMIT');
    return { awarded: true, amount: safeAmount, previousBalance, newBalance };
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Tiger currency reward error:', e);
    return { awarded: false, error: 'Error al otorgar Tigrys' };
  } finally {
    client.release();
  }
}

app.get('/tiger-tasks/wallet', async (req, res) => {
  try {
    const userId = getOceanPayUserIdFromAuthHeader(req.headers.authorization);
    if (!userId) return res.status(401).json({ error: 'Token de Ocean Pay requerido' });
    const balance = await getTigerBalanceForUser(userId);
    res.json({ success: true, currency: TT_CURRENCY, balance });
  } catch (e) {
    console.error('Tiger wallet error:', e);
    res.status(500).json({ error: 'No se pudo cargar la billetera Tiger' });
  }
});

app.post('/tiger-tasks/rewards/daily', async (req, res) => {
  try {
    const userId = getOceanPayUserIdFromAuthHeader(req.headers.authorization);
    if (!userId) return res.status(401).json({ error: 'Token de Ocean Pay requerido' });
    const claimKey = new Date().toISOString().slice(0, 10);
    const result = await awardTigerCurrency({
      userId,
      amount: TT_DAILY_REWARD,
      claimType: 'daily',
      claimKey,
      reason: 'Recompensa diaria Tiger Tasks'
    });
    res.json({
      success: true,
      awarded: Boolean(result.awarded),
      amount: Number(result.amount || 0),
      newBalance: Number(result.newBalance || await getTigerBalanceForUser(userId)),
      message: result.message || (result.awarded ? `Recompensa diaria reclamada (+${TT_DAILY_REWARD} TIGRYS).` : 'Ya reclamaste la diaria de hoy.')
    });
  } catch (e) {
    console.error('Tiger daily reward error:', e);
    res.status(500).json({ error: 'No se pudo procesar la recompensa diaria' });
  }
});

app.post('/tiger-tasks/rewards/task-complete', async (req, res) => {
  try {
    const userId = getOceanPayUserIdFromAuthHeader(req.headers.authorization);
    if (!userId) return res.status(401).json({ error: 'Token de Ocean Pay requerido' });
    const taskId = String(req.body?.taskId || '').trim();
    if (!taskId) return res.status(400).json({ error: 'taskId requerido' });
    const claimKey = `${new Date().toISOString().slice(0, 10)}:${taskId}`;
    const result = await awardTigerCurrency({
      userId,
      amount: TT_TASK_REWARD,
      claimType: 'task_complete',
      claimKey,
      reason: `Tarea completada Tiger Tasks (${taskId})`
    });
    const statusCode = result.error ? 500 : 200;
    res.status(statusCode).json({
      success: !result.error,
      awarded: Boolean(result.awarded),
      amount: Number(result.amount || 0),
      newBalance: Number(result.newBalance || await getTigerBalanceForUser(userId)),
      message: result.message || (result.awarded ? `+${TT_TASK_REWARD} TIGRYS por tarea completada.` : 'No se pudo otorgar Tigrys por esta tarea.'),
      error: result.error || null
    });
  } catch (e) {
    console.error('Tiger task reward error:', e);
    res.status(500).json({ error: 'No se pudo procesar la recompensa por tarea' });
  }
});

app.get('/tiger-tasks/subscription/plans', (_req, res) => {
  res.json({
    success: true,
    projectId: TT_PROJECT_ID,
    currency: TT_CURRENCY,
    cadence: 'weekly',
    plans: TT_WEEKLY_PLANS.map(serializeTtPlan)
  });
});

app.get('/tiger-tasks/subscription/status', async (req, res) => {
  try {
    const userId = getOceanPayUserIdFromAuthHeader(req.headers.authorization);
    if (!userId) return res.status(401).json({ error: 'Token de Ocean Pay requerido' });
    const columns = await getTtSubscriptionColumnSet();
    const hasEndDate = columns.has('end_date');
    const hasNextPayment = columns.has('next_payment');
    const hasStatus = columns.has('status');
    const hasSubName = columns.has('sub_name');
    const expiryExpr = hasEndDate && hasNextPayment
      ? 'COALESCE(end_date, next_payment, created_at)'
      : (hasEndDate ? 'COALESCE(end_date, created_at)' : (hasNextPayment ? 'COALESCE(next_payment, created_at)' : 'created_at'));
    const statusClause = hasStatus ? "AND (status IS NULL OR LOWER(status) = 'active')" : '';

    const { rows } = await pool.query(
      `SELECT *, ${expiryExpr} AS effective_end_date
       FROM ocean_pay_subscriptions
       WHERE user_id = $1
         AND LOWER(COALESCE(project_id, '')) = LOWER($2)
         AND LOWER(COALESCE(currency, '')) = LOWER($3)
         ${statusClause}
       ORDER BY ${expiryExpr} DESC, created_at DESC
       LIMIT 1`,
      [userId, TT_PROJECT_ID, TT_CURRENCY]
    );
    const rawSub = rows[0] || null;
    const effectiveEnd = rawSub?.effective_end_date ? new Date(rawSub.effective_end_date) : null;
    const isActive = Boolean(rawSub) && effectiveEnd instanceof Date && !Number.isNaN(effectiveEnd.getTime()) && effectiveEnd.getTime() > Date.now();
    const planName = rawSub ? (rawSub.plan_name || (hasSubName ? rawSub.sub_name : '') || 'Cub Starter') : '';
    const planId = normalizeTtPlanName(planName);
    const plan = TT_PLAN_MAP.get(planId) || TT_WEEKLY_PLANS[0];

    res.json({
      success: true,
      projectId: TT_PROJECT_ID,
      plans: TT_WEEKLY_PLANS.map(serializeTtPlan),
      subscription: isActive ? {
        id: rawSub.id,
        active: true,
        planId,
        planName: plan.label,
        currency: String(rawSub.currency || TT_CURRENCY).toLowerCase(),
        price: Number(rawSub.price || plan.priceByCurrency[TT_CURRENCY] || 0),
        endsAt: effectiveEnd.toISOString(),
        perks: plan.perks
      } : null
    });
  } catch (e) {
    console.error('Tiger subscription status error:', e);
    res.status(500).json({ error: 'No se pudo obtener el estado de suscripciï¿½n Tiger' });
  }
});

app.post('/tiger-tasks/subscription/checkout', async (req, res) => {
  const userId = getOceanPayUserIdFromAuthHeader(req.headers.authorization);
  if (!userId) return res.status(401).json({ error: 'Token de Ocean Pay requerido' });

  const planId = String(req.body?.planId || '').trim();
  const plan = TT_PLAN_MAP.get(planId);
  if (!plan) return res.status(400).json({ error: 'Plan Tiger no vï¿½lido' });

  const price = Number(plan.priceByCurrency[TT_CURRENCY]);
  if (!Number.isFinite(price) || price <= 0) {
    return res.status(400).json({ error: 'Precio invï¿½lido del plan Tiger' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const cardId = await ensureTigerCardBalance(client, userId, true);
    if (!cardId) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'No tienes tarjeta activa en Ocean Pay' });
    }

    const { rows: balRows } = await client.query(
      `SELECT amount
       FROM ocean_pay_card_balances
       WHERE card_id = $1 AND currency_type = $2
       FOR UPDATE`,
      [cardId, TT_CURRENCY]
    );
    const currentBalance = Number(balRows[0]?.amount || 0);
    if (currentBalance < price) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Saldo insuficiente de TIGRYS' });
    }
    const newBalance = currentBalance - price;
    await client.query(
      `UPDATE ocean_pay_card_balances
       SET amount = $1
       WHERE card_id = $2 AND currency_type = $3`,
      [newBalance, cardId, TT_CURRENCY]
    );
    await client.query(
      `UPDATE ocean_pay_cards
       SET balances = jsonb_set(
         COALESCE(balances, '{}'::jsonb),
         '{tigrys}',
         to_jsonb($1::numeric),
         true
       )
       WHERE id = $2`,
      [newBalance, cardId]
    );

    const columns = await getTtSubscriptionColumnSet();
    const hasEndDate = columns.has('end_date');
    const hasNextPayment = columns.has('next_payment');
    const hasStatus = columns.has('status');
    const hasSubName = columns.has('sub_name');
    const hasIntervalDays = columns.has('interval_days');
    const hasStartDate = columns.has('start_date');
    const expiryExpr = hasEndDate && hasNextPayment
      ? 'COALESCE(end_date, next_payment, created_at)'
      : (hasEndDate ? 'COALESCE(end_date, created_at)' : (hasNextPayment ? 'COALESCE(next_payment, created_at)' : 'created_at'));
    const statusClause = hasStatus ? "AND (status IS NULL OR LOWER(status) = 'active')" : '';

    const { rows: existingRows } = await client.query(
      `SELECT id, ${expiryExpr} AS effective_end_date
       FROM ocean_pay_subscriptions
       WHERE user_id = $1
         AND LOWER(COALESCE(project_id, '')) = LOWER($2)
         AND LOWER(COALESCE(currency, '')) = LOWER($3)
         ${statusClause}
       ORDER BY ${expiryExpr} DESC, created_at DESC
       LIMIT 1
       FOR UPDATE`,
      [userId, TT_PROJECT_ID, TT_CURRENCY]
    );

    const now = new Date();
    const existing = existingRows[0] || null;
    const existingEnd = existing?.effective_end_date ? new Date(existing.effective_end_date) : null;
    const baseDate = existingEnd instanceof Date && !Number.isNaN(existingEnd.getTime()) && existingEnd.getTime() > now.getTime()
      ? existingEnd
      : now;
    const finalEnd = new Date(baseDate.getTime() + TT_WEEKLY_INTERVAL_DAYS * 24 * 60 * 60 * 1000);

    let subscriptionId = 0;
    if (existing?.id) {
      const updateFields = ['project_id = $1', 'plan_name = $2', 'price = $3', 'currency = $4', 'card_id = $5'];
      const updateValues = [TT_PROJECT_ID, plan.label, price, TT_CURRENCY, cardId];
      if (hasSubName) {
        updateFields.push(`sub_name = $${updateValues.length + 1}`);
        updateValues.push(plan.label);
      }
      if (hasStatus) {
        updateFields.push(`status = $${updateValues.length + 1}`);
        updateValues.push('active');
      }
      if (hasIntervalDays) {
        updateFields.push(`interval_days = $${updateValues.length + 1}`);
        updateValues.push(TT_WEEKLY_INTERVAL_DAYS);
      }
      if (hasNextPayment) {
        updateFields.push(`next_payment = $${updateValues.length + 1}`);
        updateValues.push(finalEnd);
      }
      if (hasEndDate) {
        updateFields.push(`end_date = $${updateValues.length + 1}`);
        updateValues.push(finalEnd);
      }
      updateValues.push(existing.id);
      const { rows: updated } = await client.query(
        `UPDATE ocean_pay_subscriptions
         SET ${updateFields.join(', ')}
         WHERE id = $${updateValues.length}
         RETURNING id`,
        updateValues
      );
      subscriptionId = Number(updated[0]?.id || existing.id);
    } else {
      const insertCols = ['user_id', 'project_id', 'plan_name', 'price', 'currency', 'card_id'];
      const insertVals = [userId, TT_PROJECT_ID, plan.label, price, TT_CURRENCY, cardId];
      if (hasSubName) {
        insertCols.push('sub_name');
        insertVals.push(plan.label);
      }
      if (hasStatus) {
        insertCols.push('status');
        insertVals.push('active');
      }
      if (hasStartDate) {
        insertCols.push('start_date');
        insertVals.push(now);
      }
      if (hasIntervalDays) {
        insertCols.push('interval_days');
        insertVals.push(TT_WEEKLY_INTERVAL_DAYS);
      }
      if (hasNextPayment) {
        insertCols.push('next_payment');
        insertVals.push(finalEnd);
      }
      if (hasEndDate) {
        insertCols.push('end_date');
        insertVals.push(finalEnd);
      }
      const placeholders = insertVals.map((_, idx) => `$${idx + 1}`).join(', ');
      const { rows: inserted } = await client.query(
        `INSERT INTO ocean_pay_subscriptions (${insertCols.join(', ')})
         VALUES (${placeholders})
         RETURNING id`,
        insertVals
      );
      subscriptionId = Number(inserted[0]?.id || 0);
    }

    await client.query(
      `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
       VALUES ($1, $2, $3, $4, $5)`,
      [userId, `Suscripciï¿½n semanal: ${plan.label}`, -price, TT_PROJECT_ID, TT_CURRENCY]
    );
    await client.query(
      `INSERT INTO ocean_pay_notifications (user_id, type, title, message)
       VALUES ($1, 'success', $2, $3)`,
      [userId, 'Tiger Tasks suscripciï¿½n activa', `Tu plan ${plan.label} estï¿½ activo hasta ${finalEnd.toLocaleString('es-ES')}.`]
    ).catch(() => null);

    await client.query('COMMIT');
    res.json({
      success: true,
      projectId: TT_PROJECT_ID,
      subscription: {
        id: subscriptionId,
        active: true,
        planId: plan.id,
        planName: plan.label,
        currency: TT_CURRENCY,
        price,
        endsAt: finalEnd.toISOString(),
        perks: plan.perks
      },
      charged: {
        currency: TT_CURRENCY,
        amount: price,
        previousBalance: currentBalance,
        newBalance
      }
    });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Tiger subscription checkout error:', e);
    res.status(500).json({ error: 'No se pudo procesar la suscripciï¿½n Tiger' });
  } finally {
    client.release();
  }
});

app.get('/oceanic-ethernet/index.html', (_req, res) => {
  try {
    const html = fs.readFileSync(join(__dirname, 'OceanicEthernet', 'index.html'), 'utf-8');
    res.type('html').send(html);
  } catch (e) {
    res.status(404).send('Archivo no encontrado');
  }
});

// Endpoint para sincronizar WildCredits desde Wild Explorer
app.post('/ocean-pay/wildcredits/sync', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.substring(7);
  let userId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    userId = (decoded.id || decoded.uid);
    // Asegurar que userId sea un entero (el id de ocean_pay_users es INTEGER)
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }

  const { wildCredits } = req.body;
  if (wildCredits === undefined || wildCredits === null) {
    return res.status(400).json({ error: 'wildCredits requerido' });
  }

  const wildCreditsValue = parseInt(wildCredits || '0');

  try {
    // Asegurar que la tabla existe con el esquema correcto (INTEGER)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ocean_pay_metadata(
        user_id INTEGER NOT NULL,
        key TEXT NOT NULL,
        value TEXT NOT NULL,
        PRIMARY KEY(user_id, key)
      )
      `);

    // Intentar actualizar o insertar
    await pool.query(`
      INSERT INTO ocean_pay_metadata(user_id, key, value)
    VALUES($1, 'wildcredits', $2)
      ON CONFLICT(user_id, key) 
      DO UPDATE SET value = $2
      `, [userId, wildCreditsValue.toString()]);

    // ADICIONAL: Actualizar el balance en la tarjeta principal para que Ocean Pay lo vea de inmediato
    await pool.query(`
      UPDATE ocean_pay_cards 
      SET balances = jsonb_set(COALESCE(balances, '{}':: jsonb), '{wildcredits}', to_jsonb($2:: numeric))
      WHERE user_id = $1 AND is_primary = true
      `, [userId, wildCreditsValue]);

    res.json({ success: true, wildcredits: wildCreditsValue });
  } catch (e) {
    // Si hay un error de tipo de dato (tabla existe con UUID), intentar recrearla
    if (e.code === '22P02' || e.message.includes('uuid')) {
      try {
        console.log('Recreando tabla ocean_pay_metadata con INTEGER...');
        await pool.query('DROP TABLE IF EXISTS ocean_pay_metadata CASCADE');
        await pool.query(`
          CREATE TABLE ocean_pay_metadata(
        user_id INTEGER NOT NULL,
        key TEXT NOT NULL,
        value TEXT NOT NULL,
        PRIMARY KEY(user_id, key)
      )
      `);
        await pool.query(`
          INSERT INTO ocean_pay_metadata(user_id, key, value)
    VALUES($1, 'wildcredits', $2)
      `, [userId, wildCreditsValue.toString()]);
        res.json({ success: true, wildcredits: wildCreditsValue });
      } catch (e2) {
        console.error('Error recreando tabla ocean_pay_metadata:', e2);
        res.status(500).json({ error: 'Error interno' });
      }
    } else if (e.code === '42P01') {
      // Si la tabla no existe, crearla
      try {
        await pool.query(`
          CREATE TABLE ocean_pay_metadata(
        user_id INTEGER NOT NULL,
        key TEXT NOT NULL,
        value TEXT NOT NULL,
        PRIMARY KEY(user_id, key)
      )
      `);
        await pool.query(`
          INSERT INTO ocean_pay_metadata(user_id, key, value)
    VALUES($1, 'wildcredits', $2)
      `, [userId, wildCreditsValue.toString()]);
        res.json({ success: true, wildcredits: wildCreditsValue });
      } catch (e2) {
        console.error('Error creando tabla ocean_pay_metadata:', e2);
        res.status(500).json({ error: 'Error interno' });
      }
    } else {
      console.error('Error sincronizando wildCredits:', e);
      res.status(500).json({ error: 'Error interno' });
    }
  }
});

// Endpoint para obtener WildCredits desde el servidor
app.get('/ocean-pay/wildcredits/balance', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.substring(7);
  let userId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    userId = (decoded.id || decoded.uid);
    // Asegurar que userId sea un entero (el id de ocean_pay_users es INTEGER)
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }

  try {
    const { rows } = await pool.query(`
      SELECT value FROM ocean_pay_metadata
      WHERE user_id = $1 AND key = 'wildcredits'
      `, [userId]);

    const wildCredits = rows.length > 0 ? parseInt(rows[0].value || '0') : 0;
    res.json({ wildcredits: wildCredits });
  } catch (e) {
    // Si la tabla no existe, devolver 0
    if (e.code === '42P01') {
      res.json({ wildcredits: 0 });
    } else {
      console.error('Error obteniendo wildCredits:', e);
      res.status(500).json({ error: 'Error interno' });
    }
  }
});

/* ===== WILDSHORTS - WILDGEMS ===== */
// Endpoint para obtener WildGems desde Ocean Pay
app.get('/wildshorts/wildgems/balance', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.substring(7);
  let userId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    userId = (decoded.id || decoded.uid);
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }

  try {
    const { rows } = await pool.query(`
      SELECT value FROM ocean_pay_metadata
      WHERE user_id = $1 AND key = 'wildgems'
      `, [userId]);

    const wildGems = rows.length > 0 ? parseInt(rows[0].value || '0') : 0;
    res.json({ wildgems: wildGems });
  } catch (e) {
    if (e.code === '42P01') {
      res.json({ wildgems: 0 });
    } else {
      console.error('Error obteniendo wildGems:', e);
      res.status(500).json({ error: 'Error interno' });
    }
  }
});

// Endpoint para sincronizar WildGems desde WildShorts
app.post('/wildshorts/wildgems/sync', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.substring(7);
  let userId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    userId = (decoded.id || decoded.uid);
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }

  const { wildGems } = req.body;
  if (wildGems === undefined || wildGems === null) {
    return res.status(400).json({ error: 'wildGems requerido' });
  }

  const wildGemsValue = parseInt(wildGems || '0');

  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ocean_pay_metadata(
        user_id INTEGER NOT NULL,
        key TEXT NOT NULL,
        value TEXT NOT NULL,
        PRIMARY KEY(user_id, key)
      )
      `);

    await pool.query(`
      INSERT INTO ocean_pay_metadata(user_id, key, value)
    VALUES($1, 'wildgems', $2)
      ON CONFLICT(user_id, key) 
      DO UPDATE SET value = $2
      `, [userId, wildGemsValue.toString()]);

    res.json({ success: true, wildgems: wildGemsValue });
  } catch (e) {
    console.error('Error sincronizando wildGems:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Endpoint para cambiar WildGems (compras, gastos, etc.)
app.post('/wildshorts/wildgems/change', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.substring(7);
  let userId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    userId = (decoded.id || decoded.uid);
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }

  const { amount, concepto = 'OperaciÃƒÂ³n', origen = 'WildShorts' } = req.body;
  if (amount === undefined) {
    return res.status(400).json({ error: 'amount requerido' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Obtener saldo actual
    const { rows } = await client.query(`
      SELECT value FROM ocean_pay_metadata
      WHERE user_id = $1 AND key = 'wildgems'
      FOR UPDATE
      `, [userId]);

    const current = parseInt(rows[0]?.value || '0');
    const newBalance = current + parseInt(amount);

    if (newBalance < 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Saldo insuficiente' });
    }

    // Actualizar saldo
    await client.query(`
      INSERT INTO ocean_pay_metadata(user_id, key, value)
    VALUES($1, 'wildgems', $2)
      ON CONFLICT(user_id, key) 
      DO UPDATE SET value = $2
      `, [userId, newBalance.toString()]);

    // Registrar transacciÃƒÂ³n
    await client.query(`
      INSERT INTO ocean_pay_txs(user_id, concepto, monto, origen, moneda)
    VALUES($1, $2, $3, $4, 'WG')
      ON CONFLICT DO NOTHING
      `, [userId, concepto, amount, origen]).catch(async () => {
      // Si falla por falta de columna moneda, intentar sin ella
      await client.query(`
        INSERT INTO ocean_pay_txs(user_id, concepto, monto, origen)
    VALUES($1, $2, $3, $4)
      `, [userId, concepto, amount, origen]);
    });

    await client.query('COMMIT');
    res.json({ success: true, newBalance });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Error cambiando wildGems:', e);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

/* ===== DINOBOX - AMBER ===== */
// Endpoint para obtener balance de Amber
app.get('/dinobox/amber/balance', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.substring(7);
  let userId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    userId = (decoded.id || decoded.uid) || decoded.id;
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }

  try {
    const { rows } = await pool.query(`
      SELECT value FROM ocean_pay_metadata
      WHERE user_id = $1 AND key = 'amber'
      `, [userId]);

    const amber = rows.length > 0 ? parseInt(rows[0].value || '0') : 0;
    res.json({ amber });
  } catch (e) {
    if (e.code === '42P01') {
      res.json({ amber: 0 });
    } else {
      console.error('Error obteniendo Amber:', e);
      res.status(500).json({ error: 'Error interno' });
    }
  }
});

// Endpoint para sincronizar Amber desde DinoBox
app.post('/dinobox/amber/sync', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.substring(7);
  let userId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    userId = (decoded.id || decoded.uid) || decoded.id;
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }

  const { amber } = req.body;
  if (amber === undefined || amber === null) {
    return res.status(400).json({ error: 'amber requerido' });
  }

  const amberValue = parseInt(amber || '0');

  try {
    await pool.query(`
      INSERT INTO ocean_pay_metadata(user_id, key, value)
    VALUES($1, 'amber', $2)
      ON CONFLICT(user_id, key) 
      DO UPDATE SET value = $2
      `, [userId, amberValue.toString()]);

    res.json({ success: true, amber: amberValue });
  } catch (e) {
    console.error('Error sincronizando Amber:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Endpoint para obtener balance de EcoTokens
app.get('/wild-savage/ecotokens/balance', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.substring(7);
  let userId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    userId = (decoded.id || decoded.uid);
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }

  try {
    const { rows } = await pool.query(`
      SELECT value FROM ocean_pay_metadata
      WHERE user_id = $1 AND key = 'ecotokens'
      `, [userId]);

    const ecotokens = rows.length > 0 ? parseInt(rows[0].value || '0') : 0;
    res.json({ ecotokens });
  } catch (e) {
    if (e.code === '42P01') {
      res.json({ ecotokens: 0 });
    } else {
      console.error('Error obteniendo EcoTokens:', e);
      res.status(500).json({ error: 'Error interno' });
    }
  }
});

// Endpoint para sincronizar EcoTokens desde Wild Savage
app.post('/wild-savage/ecotokens/sync', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.substring(7);
  let userId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    userId = (decoded.id || decoded.uid);
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }

  const { ecotokens } = req.body;
  if (ecotokens === undefined || ecotokens === null) {
    return res.status(400).json({ error: 'ecotokens requerido' });
  }

  const ecotokensValue = parseInt(ecotokens || '0');

  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ocean_pay_metadata(
        user_id INTEGER NOT NULL,
        key TEXT NOT NULL,
        value TEXT NOT NULL,
        PRIMARY KEY(user_id, key)
      )
      `);

    await pool.query(`
      INSERT INTO ocean_pay_metadata(user_id, key, value)
    VALUES($1, 'ecotokens', $2)
      ON CONFLICT(user_id, key) 
      DO UPDATE SET value = $2
      `, [userId, ecotokensValue.toString()]);

    res.json({ success: true, ecotokens: ecotokensValue });
  } catch (e) {
    console.error('Error sincronizando EcoTokens:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Endpoint para cambiar EcoTokens (ganar/gastar)
app.post('/wild-savage/ecotokens/change', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.substring(7);
  let userId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    userId = (decoded.id || decoded.uid);
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }

  const { amount, concepto = 'OperaciÃƒÂ³n', origen = 'Wild Savage' } = req.body;
  if (amount === undefined) {
    return res.status(400).json({ error: 'amount requerido' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Obtener saldo actual
    const { rows } = await client.query(`
      SELECT value FROM ocean_pay_metadata
      WHERE user_id = $1 AND key = 'ecotokens'
      FOR UPDATE
      `, [userId]);

    const current = parseInt(rows[0]?.value || '0');
    const newBalance = current + parseInt(amount);

    if (newBalance < 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Saldo insuficiente' });
    }

    // Actualizar saldo
    await client.query(`
      INSERT INTO ocean_pay_metadata(user_id, key, value)
    VALUES($1, 'ecotokens', $2)
      ON CONFLICT(user_id, key) 
      DO UPDATE SET value = $2
      `, [userId, newBalance.toString()]);

    // Registrar transacciÃƒÂ³n
    await client.query(`
      INSERT INTO ocean_pay_txs(user_id, concepto, monto, origen, moneda)
    VALUES($1, $2, $3, $4, 'ET')
      ON CONFLICT DO NOTHING
      `, [userId, concepto, amount, origen]).catch(async () => {
      await client.query(`
        INSERT INTO ocean_pay_txs(user_id, concepto, monto, origen)
    VALUES($1, $2, $3, $4)
      `, [userId, concepto, amount, origen]);
    });

    await client.query('COMMIT');
    res.json({ success: true, newBalance });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Error cambiando EcoTokens:', e);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

/* ===== WILDSHORTS - SUSCRIPCIONES ===== */
// Endpoint para suscribirse a un plan de WildShorts
app.post('/wildshorts/subscribe', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.substring(7);
  let userId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    userId = (decoded.id || decoded.uid);
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }

  const { planId, paymentMethod } = req.body; // paymentMethod: 'weekly' o 'pay-as-you-go'
  if (!planId || !paymentMethod) {
    return res.status(400).json({ error: 'planId y paymentMethod requeridos' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Obtener saldo de WildGems
    const { rows: gemsRows } = await client.query(`
      SELECT value FROM ocean_pay_metadata
      WHERE user_id = $1 AND key = 'wildgems'
      FOR UPDATE
    `, [userId]);

    const currentGems = parseInt(gemsRows[0]?.value || '0');

    // Calcular precio segÃƒÂºn mÃƒÂ©todo de pago
    // Para weekly: precio reducido (ej: 70% del precio mensual)
    // Para pay-as-you-go: no se cobra aquÃƒÂ­, se cobra por episodio
    const planPrices = {
      starter: { weekly: 350, payAsYouGo: 0 },
      explorer: { weekly: 840, payAsYouGo: 0 },
      adventurer: { weekly: 1750, payAsYouGo: 0 },
      legend: { weekly: 3500, payAsYouGo: 0 },
      ultra: { weekly: 6300, payAsYouGo: 0 },
      founder: { weekly: 14000, payAsYouGo: 0 }
    };

    const planPrice = planPrices[planId]?.[paymentMethod === 'weekly' ? 'weekly' : 'payAsYouGo'] || 0;

    if (paymentMethod === 'weekly' && currentGems < planPrice) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: `Saldo insuficiente.Necesitas ${planPrice} WildGems.` });
    }

    // Si es weekly, descontar inmediatamente
    if (paymentMethod === 'weekly') {
      const newBalance = currentGems - planPrice;
      await client.query(`
        INSERT INTO ocean_pay_metadata(user_id, key, value)
    VALUES($1, 'wildgems', $2)
        ON CONFLICT(user_id, key) 
        DO UPDATE SET value = $2
      `, [userId, newBalance.toString()]);

      // Registrar transacciÃƒÂ³n
      await client.query(`
        INSERT INTO ocean_pay_txs(user_id, concepto, monto, origen, moneda)
    VALUES($1, $2, $3, $4, 'WG')
      `, [userId, `SuscripciÃƒÂ³n ${planId} (WildShorts) - Semanal`, -planPrice, 'WildShorts']).catch(async () => {
        await client.query(`
          INSERT INTO ocean_pay_txs(user_id, concepto, monto, origen)
    VALUES($1, $2, $3, $4)
        `, [userId, `SuscripciÃƒÂ³n ${planId} (WildShorts) - Semanal`, -planPrice, 'WildShorts']);
      });
    }

    // Crear/actualizar suscripciÃƒÂ³n
    const now = new Date();
    const endsAt = paymentMethod === 'weekly'
      ? new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000) // 7 dÃƒÂ­as
      : null; // pay-as-you-go no tiene fecha de expiraciÃƒÂ³n

    // Crear tabla de suscripciones de WildShorts si no existe
    await client.query(`
      CREATE TABLE IF NOT EXISTS wildshorts_subs(
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      plan_id TEXT NOT NULL,
      payment_method TEXT NOT NULL,
      starts_at TIMESTAMP NOT NULL DEFAULT NOW(),
      ends_at TIMESTAMP,
      active BOOLEAN DEFAULT true,
      created_at TIMESTAMP DEFAULT NOW(),
      UNIQUE(user_id, plan_id, payment_method)
    )
      `);

    // Cerrar suscripciones anteriores del mismo plan
    await client.query(`
      UPDATE wildshorts_subs 
      SET active = false 
      WHERE user_id = $1 AND plan_id = $2 AND active = true
      `, [userId, planId]);

    // Crear nueva suscripciÃƒÂ³n
    const { rows: subRows } = await client.query(`
      INSERT INTO wildshorts_subs(user_id, plan_id, payment_method, starts_at, ends_at, active)
    VALUES($1, $2, $3, $4, $5, true)
      ON CONFLICT(user_id, plan_id, payment_method)
      DO UPDATE SET starts_at = $4, ends_at = $5, active = true
    RETURNING *
      `, [userId, planId, paymentMethod, now, endsAt]);

    await client.query('COMMIT');

    res.json({
      success: true,
      subscription: subRows[0],
      newBalance: paymentMethod === 'weekly' ? currentGems - planPrice : currentGems
    });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Error suscribiendo a WildShorts:', e);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

// Endpoint para obtener suscripciÃƒÂ³n activa de WildShorts
app.get('/wildshorts/subscription/:userId', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.substring(7);
  let userId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    userId = (decoded.id || decoded.uid);
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }

  try {
    const { rows } = await pool.query(`
    SELECT * FROM wildshorts_subs
      WHERE user_id = $1 AND active = true
    AND(ends_at IS NULL OR ends_at > NOW())
      ORDER BY created_at DESC
      LIMIT 1
      `, [userId]);

    res.json(rows[0] || null);
  } catch (e) {
    if (e.code === '42P01') {
      res.json(null);
    } else {
      console.error('Error obteniendo suscripciÃƒÂ³n:', e);
      res.status(500).json({ error: 'Error interno' });
    }
  }
});

// Endpoint para obtener WildGems (recompensas, bonos, etc.)
app.post('/wildshorts/wildgems/claim', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.substring(7);
  let userId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    userId = (decoded.id || decoded.uid);
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }

  const { type, amount } = req.body; // type: 'daily', 'welcome', 'bonus', etc.
  if (!type) {
    return res.status(400).json({ error: 'Tipo de recompensa requerido' });
  }

  // Crear tabla e ÃƒÂ­ndices FUERA de la transacciÃƒÂ³n (operaciones DDL)
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS wildgems_claims(
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        claim_type TEXT NOT NULL,
        amount INTEGER NOT NULL,
        claimed_at TIMESTAMP DEFAULT NOW()
      )
      `);

    // Crear ÃƒÂ­ndice simple para mejorar el rendimiento de las consultas
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_wildgems_claims_user_type 
      ON wildgems_claims(user_id, claim_type)
      `).catch(() => {
      // Ignorar errores si el ÃƒÂ­ndice ya existe
    });
  } catch (ddlError) {
    // Ignorar errores de DDL si la tabla/ÃƒÂ­ndice ya existe
    console.log('[WildGems] Tabla/ÃƒÂ­ndice ya existe o error al crear:', ddlError.message);
  }

  // Verificar lÃƒÂ­mites FUERA de la transacciÃƒÂ³n
  const now = new Date();

  // Verificar si ya reclamÃƒÂ³ hoy (para recompensas diarias)
  if (type === 'daily') {
    const { rows: dailyRows } = await pool.query(`
    SELECT * FROM wildgems_claims
      WHERE user_id = $1 AND claim_type = 'daily' 
      AND DATE(claimed_at) = DATE(NOW())
      `, [userId]);

    if (dailyRows.length > 0) {
      const nextClaim = new Date(dailyRows[0].claimed_at);
      nextClaim.setDate(nextClaim.getDate() + 1);
      nextClaim.setHours(0, 0, 0, 0);
      const hoursUntil = Math.ceil((nextClaim - now) / (1000 * 60 * 60));
      return res.status(400).json({
        error: `Ya reclamaste tu recompensa diaria hoy.PrÃƒÂ³xima recompensa en ${hoursUntil} horas.`,
        nextClaim: nextClaim.toISOString()
      });
    }
  }

  // Verificar si ya reclamÃƒÂ³ (para recompensas ÃƒÂºnicas)
  if (type === 'welcome') {
    const { rows: welcomeRows } = await pool.query(`
    SELECT * FROM wildgems_claims
      WHERE user_id = $1 AND claim_type = 'welcome'
      `, [userId]);

    if (welcomeRows.length > 0) {
      return res.status(400).json({ error: 'Ya reclamaste tu recompensa de bienvenida.' });
    }
  }

  // Verificar lÃƒÂ­mite de anuncios (mÃƒÂ¡ximo 5 por dÃƒÂ­a)
  if (type === 'ad_watch') {
    const { rows: adRows } = await pool.query(`
      SELECT COUNT(*) as count FROM wildgems_claims
      WHERE user_id = $1 AND claim_type = 'ad_watch' 
      AND DATE(claimed_at) = DATE(NOW())
      `, [userId]);

    if (parseInt(adRows[0].count) >= 5) {
      return res.status(400).json({ error: 'Has alcanzado el lÃƒÂ­mite de 5 anuncios por dÃƒÂ­a.' });
    }
  }

  // Verificar lÃƒÂ­mite de compartir (mÃƒÂ¡ximo 3 por dÃƒÂ­a)
  if (type === 'social_share') {
    const { rows: shareRows } = await pool.query(`
      SELECT COUNT(*) as count FROM wildgems_claims
      WHERE user_id = $1 AND claim_type = 'social_share' 
      AND DATE(claimed_at) = DATE(NOW())
      `, [userId]);

    if (parseInt(shareRows[0].count) >= 3) {
      return res.status(400).json({ error: 'Has alcanzado el lÃƒÂ­mite de 3 compartidos por dÃƒÂ­a.' });
    }
  }

  // Verificar si la columna moneda existe FUERA de la transacciÃƒÂ³n
  let hasMonedaColumn = false;
  try {
    const { rows: columnCheck } = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'ocean_pay_txs' AND column_name = 'moneda'
      `);
    hasMonedaColumn = columnCheck.length > 0;
  } catch (checkError) {
    // Si falla la verificaciÃƒÂ³n, asumir que no existe la columna (por defecto)
    hasMonedaColumn = false;
  }

  // Calcular cantidad si no se proporciona
  let gemsAmount = amount || 0;
  if (!gemsAmount) {
    const rewards = {
      daily: 50,         // 50 WildGems diarios
      welcome: 200,      // 200 WildGems de bienvenida
      bonus: 100,        // 100 WildGems de bono
      referral: 150,     // 150 WildGems por referido
      achievement: 75,   // 75 WildGems por logro
      ad_watch: 25,      // 25 WildGems por ver anuncio
      social_share: 100  // 100 WildGems por compartir en redes
    };
    gemsAmount = rewards[type] || 0;
  }

  if (gemsAmount <= 0) {
    return res.status(400).json({ error: 'Cantidad invÃƒÂ¡lida' });
  }

  // Conceptos para las transacciones
  const conceptos = {
    daily: 'Recompensa Diaria (WildShorts)',
    welcome: 'Recompensa de Bienvenida (WildShorts)',
    bonus: 'Bono Especial (WildShorts)',
    referral: 'Recompensa por Referido (WildShorts)',
    achievement: 'Logro Desbloqueado (WildShorts)',
    ad_watch: 'Recompensa por Ver Anuncio (WildShorts)',
    social_share: 'Recompensa por Compartir (WildShorts)'
  };

  // Ahora sÃƒÂ­, comenzar la transacciÃƒÂ³n para las operaciones DML
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Obtener saldo actual
    const { rows: gemsRows } = await client.query(`
      SELECT value FROM ocean_pay_metadata
      WHERE user_id = $1 AND key = 'wildgems'
      FOR UPDATE
      `, [userId]);

    const current = parseInt(gemsRows[0]?.value || '0');
    const newBalance = current + gemsAmount;

    // Actualizar saldo
    await client.query(`
      INSERT INTO ocean_pay_metadata(user_id, key, value)
    VALUES($1, 'wildgems', $2)
      ON CONFLICT(user_id, key) 
      DO UPDATE SET value = $2
      `, [userId, newBalance.toString()]);

    // Registrar reclamaciÃƒÂ³n
    await client.query(`
      INSERT INTO wildgems_claims(user_id, claim_type, amount)
    VALUES($1, $2, $3)
      `, [userId, type, gemsAmount]);

    // Insertar transacciÃƒÂ³n segÃƒÂºn la estructura de la tabla (ya sabemos si tiene moneda)
    if (hasMonedaColumn) {
      await client.query(`
        INSERT INTO ocean_pay_txs(user_id, concepto, monto, origen, moneda)
    VALUES($1, $2, $3, $4, 'WG')
      `, [userId, conceptos[type] || `Recompensa ${type} (WildShorts)`, gemsAmount, 'WildShorts']);
    } else {
      await client.query(`
        INSERT INTO ocean_pay_txs(user_id, concepto, monto, origen)
    VALUES($1, $2, $3, $4)
      `, [userId, conceptos[type] || `Recompensa ${type} (WildShorts)`, gemsAmount, 'WildShorts']);
    }

    await client.query('COMMIT');
    client.release();

    res.json({
      success: true,
      newBalance,
      amount: gemsAmount,
      type: type
    });
  } catch (e) {
    // Intentar hacer rollback si la transacciÃƒÂ³n estÃƒÂ¡ activa
    try {
      await client.query('ROLLBACK');
    } catch (rollbackError) {
      // Ignorar errores de rollback si la transacciÃƒÂ³n ya fue abortada
      console.log('[WildGems] Error en rollback (posiblemente ya abortado):', rollbackError.message);
    }
    client.release();

    console.error('Error reclamando WildGems:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Endpoint para verificar estado de recompensas
app.get('/wildshorts/wildgems/claims-status', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.substring(7);
  let userId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    userId = (decoded.id || decoded.uid);
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }

  try {
    // Verificar recompensa diaria
    const { rows: dailyRows } = await pool.query(`
    SELECT * FROM wildgems_claims
      WHERE user_id = $1 AND claim_type = 'daily' 
      AND DATE(claimed_at) = DATE(NOW())
      `, [userId]);

    // Verificar recompensa de bienvenida
    const { rows: welcomeRows } = await pool.query(`
    SELECT * FROM wildgems_claims
      WHERE user_id = $1 AND claim_type = 'welcome'
      `, [userId]);

    // Calcular prÃƒÂ³xima recompensa diaria
    let nextDaily = null;
    if (dailyRows.length > 0) {
      const lastClaim = new Date(dailyRows[0].claimed_at);
      nextDaily = new Date(lastClaim);
      nextDaily.setDate(nextDaily.getDate() + 1);
      nextDaily.setHours(0, 0, 0, 0);
    }

    res.json({
      daily: {
        claimed: dailyRows.length > 0,
        nextClaim: nextDaily?.toISOString() || null
      },
      welcome: {
        claimed: welcomeRows.length > 0
      }
    });
  } catch (e) {
    if (e.code === '42P01') {
      res.json({
        daily: { claimed: false, nextClaim: null },
        welcome: { claimed: false }
      });
    } else {
      console.error('Error verificando estado de recompensas:', e);
      res.status(500).json({ error: 'Error interno' });
    }
  }
});

// Endpoint para pagar por episodio (pay-as-you-go)

/* ===== SAVAGE SPACE ANIMALS - COSMIC DUST ===== */

app.post('/ssa/cosmicdust/sync', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  let userId;
  try {
    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    userId = parseInt(decoded.id || decoded.uid || decoded.sub) || (decoded.id || decoded.uid || decoded.sub);
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }

  const raw = req.body?.cosmicdust;
  if (raw === undefined || raw === null) {
    return res.status(400).json({ error: 'cosmicdust requerido' });
  }
  const nextDust = Math.max(0, Math.floor(Number(raw) || 0));
  const concept = String(req.body?.concept || 'Sincronizacion SSA');

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { rows: cards } = await client.query(
      'SELECT id, balances FROM ocean_pay_cards WHERE user_id = $1 AND is_primary = true FOR UPDATE',
      [userId]
    );
    if (!cards.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'No se encontrÃƒÂ³ tarjeta principal' });
    }

    const cardId = cards[0].id;
    const balances = cards[0].balances || {};
    balances.cosmicdust = nextDust;
    await client.query('UPDATE ocean_pay_cards SET balances = $1 WHERE id = $2', [balances, cardId]);

    await client.query(
      `INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount)
       VALUES ($1, 'cosmicdust', $2)
       ON CONFLICT (card_id, currency_type) DO UPDATE SET amount = $2`,
      [cardId, nextDust]
    );

    await client.query(
      `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
       VALUES ($1, $2, 0, 'Savage Space Animals', 'CD')`,
      [userId, `${concept} (saldo: ${nextDust})`]
    );

    await client.query('COMMIT');
    res.json({ success: true, cosmicdust: nextDust });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Error en /ssa/cosmicdust/sync:', e);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

app.get('/ssa/cosmicdust/balance', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  let userId;
  try {
    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    userId = parseInt(decoded.id || decoded.uid || decoded.sub) || (decoded.id || decoded.uid || decoded.sub);
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }

  try {
    const { rows } = await pool.query(
      `SELECT cb.amount
       FROM ocean_pay_cards c
       LEFT JOIN ocean_pay_card_balances cb
         ON cb.card_id = c.id AND cb.currency_type = 'cosmicdust'
       WHERE c.user_id = $1 AND c.is_primary = true
       LIMIT 1`,
      [userId]
    );
    const cosmicdust = rows.length > 0 ? Math.max(0, Math.floor(Number(rows[0].amount || 0))) : 0;
    res.json({ cosmicdust });
  } catch (e) {
    console.error('Error en /ssa/cosmicdust/balance:', e);
    res.json({ cosmicdust: 0 });
  }
});

/* ===== WILDWEAPON MAYHEM - MAYHEMCOINS ===== */

// Sincronizar MayhemCoins desde WildWeapon Mayhem
app.post('/wildweapon/mayhemcoins/sync', async (req, res) => {
  const authHeader = req.headers.authorization
    || (req.headers['x-ocean-pay-token'] ? `Bearer ${req.headers['x-ocean-pay-token']}` : null);
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.substring(7);
  let userId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    userId = (decoded.id || decoded.uid);
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }

  const { mayhemcoins } = req.body;
  if (mayhemcoins === undefined || mayhemcoins === null) {
    return res.status(400).json({ error: 'mayhemcoins requerido' });
  }

  const mcValue = parseInt(mayhemcoins || '0');

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Obtener tarjeta principal
    const { rows: cards } = await client.query(
      'SELECT id, balances FROM ocean_pay_cards WHERE user_id = $1 AND is_primary = true FOR UPDATE',
      [userId]
    );

    if (cards.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'No se encontrÃƒÂ³ tarjeta principal' });
    }

    const cardId = cards[0].id;
    const balances = cards[0].balances || {};

    // Actualizar JSONB
    balances.mayhemcoins = mcValue;
    await client.query('UPDATE ocean_pay_cards SET balances = $1 WHERE id = $2', [balances, cardId]);

    // Actualizar tabla SQL
    await client.query(`
      INSERT INTO ocean_pay_card_balances(card_id, currency_type, amount)
    VALUES($1, 'mayhemcoins', $2)
      ON CONFLICT(card_id, currency_type)
      DO UPDATE SET amount = $2
      `, [cardId, mcValue]);

    await client.query('COMMIT');
    res.json({ success: true, mayhemcoins: mcValue });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Error sincronizando MayhemCoins:', e);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

// Obtener balance de MayhemCoins
app.get('/wildweapon/mayhemcoins/balance', async (req, res) => {
  const authHeader = req.headers.authorization
    || (req.headers['x-ocean-pay-token'] ? `Bearer ${req.headers['x-ocean-pay-token']}` : null);
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.substring(7);
  let userId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    userId = (decoded.id || decoded.uid);
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }

  try {
    const { rows } = await pool.query(`
      SELECT cb.amount FROM ocean_pay_card_balances cb
      JOIN ocean_pay_cards c ON cb.card_id = c.id
      WHERE c.user_id = $1 AND c.is_primary = true AND cb.currency_type = 'mayhemcoins'
      `, [userId]);

    const mayhemcoins = rows.length > 0 ? parseFloat(rows[0].amount || 0) : 0;
    res.json({ mayhemcoins });
  } catch (e) {
    console.error('Error obteniendo MayhemCoins:', e);
    res.json({ mayhemcoins: 0 });
  }
});

// Cambiar MayhemCoins (ganar/gastar)
app.post('/wildweapon/mayhemcoins/change', async (req, res) => {
  const authHeader = req.headers.authorization
    || (req.headers['x-ocean-pay-token'] ? `Bearer ${req.headers['x-ocean-pay-token']}` : null);
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.substring(7);
  let userId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    userId = (decoded.id || decoded.uid);
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }

  const { amount, concepto = 'OperaciÃƒÂ³n', origen = 'WildWeapon Mayhem' } = req.body;
  if (amount === undefined) return res.status(400).json({ error: 'amount requerido' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Obtener tarjeta principal
    const { rows: cards } = await client.query(
      'SELECT id, balances FROM ocean_pay_cards WHERE user_id = $1 AND is_primary = true FOR UPDATE',
      [userId]
    );

    if (cards.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'No se encontrÃƒÂ³ tarjeta principal' });
    }

    const cardId = cards[0].id;
    const balances = cards[0].balances || {};

    // Obtener saldo actual de la tabla SQL (fuente de verdad)
    const { rows: balRows } = await client.query(
      "SELECT amount FROM ocean_pay_card_balances WHERE card_id = $1 AND currency_type = 'mayhemcoins' FOR UPDATE",
      [cardId]
    );

    const current = parseFloat(balRows[0]?.amount || 0);
    const jsonCurrent = parseFloat(balances.mayhemcoins || 0);
    const effectiveCurrent = Math.max(current, jsonCurrent);
    const newBalance = effectiveCurrent + parseFloat(amount);

    if (newBalance < 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Saldo insuficiente de MayhemCoins', current: effectiveCurrent });
    }

    // Actualizar JSONB
    balances.mayhemcoins = newBalance;
    await client.query('UPDATE ocean_pay_cards SET balances = $1 WHERE id = $2', [balances, cardId]);

    // Actualizar tabla SQL
    await client.query(`
      INSERT INTO ocean_pay_card_balances(card_id, currency_type, amount)
    VALUES($1, 'mayhemcoins', $2)
      ON CONFLICT(card_id, currency_type)
      DO UPDATE SET amount = $2
      `, [cardId, newBalance]);

    // Registrar transacciÃƒÂ³n
    await client.query(`
      INSERT INTO ocean_pay_txs(user_id, concepto, monto, origen, moneda)
    VALUES($1, $2, $3, $4, 'MC')
      `, [userId, concepto, amount, origen]);

    await client.query('COMMIT');
    res.json({ success: true, newBalance });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Error cambiando MayhemCoins:', e);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

const WILDWEAPON_STORE_PACKS = Object.freeze([
  {
    id: 'zeus_axe_founder_pack',
    name: 'Zeus Axe Founders Pack',
    rarity: 'mitico',
    currency: 'tides',
    price: 799,
    weaponId: 'zeus_axe'
  }
]);

// Catalogo de tienda WildWeapon (compra con Tides)
app.get('/wildweapon/store/catalog', async (req, res) => {
  const userId = getAuthenticatedOceanPayUserId(req);
  if (!userId) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const client = await pool.connect();
  try {
    const tidesBalance = await getUnifiedBalance(client, userId, 'tides');
    const { rows } = await client.query(
      `SELECT key, value
         FROM ocean_pay_metadata
        WHERE user_id = $1
          AND key LIKE 'wildweapon_store_pack_%'`,
      [userId]
    );
    const ownedPacks = {};
    for (const row of rows) {
      const key = String(row.key || '').replace('wildweapon_store_pack_', '');
      ownedPacks[key] = String(row.value || '').toLowerCase() === 'true';
    }
    return res.json({
      success: true,
      tidesBalance: Math.max(0, Math.floor(Number(tidesBalance || 0))),
      packages: WILDWEAPON_STORE_PACKS,
      ownedPacks
    });
  } catch (e) {
    console.error('Error en GET /wildweapon/store/catalog:', e);
    return res.status(500).json({ error: 'No se pudo cargar la tienda de WildWeapon' });
  } finally {
    client.release();
  }
});

// Comprar paquete de tienda WildWeapon con Tides
app.post('/wildweapon/store/purchase', async (req, res) => {
  const userId = getAuthenticatedOceanPayUserId(req);
  if (!userId) return res.status(401).json({ error: 'Token requerido' });

  const packId = String(req.body?.packId || '').trim();
  const pack = WILDWEAPON_STORE_PACKS.find((p) => p.id === packId);
  if (!pack) return res.status(400).json({ error: 'Paquete no válido' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const ownedKey = `wildweapon_store_pack_${pack.id}`;
    const { rows: ownedRows } = await client.query(
      `SELECT value
         FROM ocean_pay_metadata
        WHERE user_id = $1 AND key = $2
        FOR UPDATE`,
      [userId, ownedKey]
    );
    const alreadyOwned = String(ownedRows[0]?.value || '').toLowerCase() === 'true';
    if (alreadyOwned) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Ya posees este paquete' });
    }

    const currentTides = await getUnifiedBalance(client, userId, 'tides');
    const newBalance = Number(currentTides) - Number(pack.price || 0);
    if (newBalance < 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Saldo insuficiente de Tides', currentBalance: Math.max(0, Math.floor(Number(currentTides || 0))) });
    }

    await setUnifiedBalance(client, userId, 'tides', newBalance);
    await client.query(
      `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
       VALUES ($1, $2, $3, $4, $5)`,
      [userId, `WildWeapon Pack: ${pack.name}`, -Number(pack.price || 0), 'WildWeapon Store', 'tides']
    );

    if (ownedRows.length > 0) {
      await client.query(
        `UPDATE ocean_pay_metadata
            SET value = 'true'
          WHERE user_id = $1 AND key = $2`,
        [userId, ownedKey]
      );
    } else {
      await client.query(
        `INSERT INTO ocean_pay_metadata (user_id, key, value)
         VALUES ($1, $2, 'true')`,
        [userId, ownedKey]
      );
    }

    await client.query('COMMIT');
    return res.json({
      success: true,
      pack,
      newTidesBalance: Math.max(0, Math.floor(newBalance))
    });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Error en POST /wildweapon/store/purchase:', e);
    return res.status(500).json({ error: 'No se pudo completar la compra del paquete' });
  } finally {
    client.release();
  }
});

/* ===== ECOXION - ECOXIONUMS ===== */

// Cambiar Ecoxionums (ganar/gastar) usando fuente unificada por tarjeta
app.post('/ocean-pay/ecoxionums/change', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.substring(7);
  let authUserId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    authUserId = Number(decoded.id || decoded.uid || decoded.sub);
    if (!Number.isFinite(authUserId) || authUserId <= 0) {
      return res.status(401).json({ error: 'Token invï¿½lido' });
    }
  } catch (_e) {
    return res.status(401).json({ error: 'Token invï¿½lido' });
  }

  const delta = Number(req.body?.amount || 0);
  if (!Number.isFinite(delta) || delta === 0) {
    return res.status(400).json({ error: 'amount invï¿½lido' });
  }
  const concepto = String(req.body?.concepto || 'Operacion Ecoxion').trim() || 'Operacion Ecoxion';
  const origen = String(req.body?.origen || 'Ecoxion').trim() || 'Ecoxion';

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const primaryCard = await ensurePrimaryCardForUser(client, authUserId, true);
    if (!primaryCard) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'No se encontrï¿½ una tarjeta vï¿½lida' });
    }

    const cardId = Number(primaryCard.id);
    const current = await getUnifiedCardCurrencyBalance(client, cardId, ECOXION_CURRENCY, true);
    const newBalance = current + delta;
    if (newBalance < 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Saldo insuficiente de Ecoxionums', currentBalance: current });
    }

    await setUnifiedCardCurrencyBalance(client, {
      userId: authUserId,
      cardId,
      currency: ECOXION_CURRENCY,
      newBalance
    });

    await client.query(
      `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
       VALUES ($1, $2, $3, $4, $5)`,
      [authUserId, concepto, delta, origen, 'EX']
    );

    await client.query('COMMIT');
    return res.json({ success: true, newBalance });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Error en /ocean-pay/ecoxionums/change:', e);
    return res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

// Endpoint para obtener balance de Ecoxionums (Estandarizado a Cards)
app.get('/ocean-pay/ecoxionums/balance', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.substring(7);
  let userId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    userId = decoded.id || (decoded.id || decoded.uid) || decoded.sub;
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃ¡lido' });
  }

  try {
    const client = await pool.connect();
    try {
      const primaryCard = await getPrimaryCardForUser(client, userId, false);
      if (!primaryCard) return res.json({ ecoxionums: 0 });
      const ecoxionums = await getUnifiedCardCurrencyBalance(client, Number(primaryCard.id), ECOXION_CURRENCY, false);
      return res.json({ ecoxionums: Number(ecoxionums || 0) });
    } finally {
      client.release();
    }
  } catch (e) {
    console.error('Error obteniendo ecoxionums:', e);
    res.json({ ecoxionums: 0 });
  }
});

// Compatibilidad legacy para clientes que aï¿½n usan este endpoint (ej. WildShorts)
// y endpoint general usado por Ocean Pay / Velocity Surge.
app.post(['/ocean-pay/cards/change-balance', '/ocean-pay/currency/change'], async (req, res) => {
  const authHeader = String(req.headers.authorization || '');
  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  let userId;
  try {
    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    userId = Number(decoded.id || decoded.uid || decoded.sub);
    if (!Number.isFinite(userId) || userId <= 0) {
      return res.status(401).json({ error: 'Token invï¿½lido' });
    }
  } catch (_e) {
    return res.status(401).json({ error: 'Token invï¿½lido' });
  }

  const currencyType = String(req.body?.currencyType || req.body?.currency || '').trim().toLowerCase();
  const delta = Number(req.body?.amount);
  const concepto = String(req.body?.concepto || 'Operaciï¿½n').trim() || 'Operaciï¿½n';
  const origen = String(req.body?.origen || 'Ocean Pay').trim() || 'Ocean Pay';
  const cardNumberRaw = req.body?.cardNumber;
  const cardNumber = cardNumberRaw == null ? '' : String(cardNumberRaw).trim();
  const cardIdFromBody = Number(req.body?.cardId);

  if (!currencyType) return res.status(400).json({ error: 'currencyType requerido' });
  if (!Number.isFinite(delta) || delta === 0) return res.status(400).json({ error: 'amount invï¿½lido' });

  const txCurrencyCodeByType = {
    aquabux: 'ABX',
    ecoxionums: 'EX',
    wildcredits: 'WC',
    wildgems: 'WG',
    appbux: 'ABX',
    ecobooks: 'EB',
    ecotokens: 'ET',
    amber: 'AM',
    nxb: 'NXB',
    voltbit: 'VB',
    mayhemcoins: 'MC',
    cosmicdust: 'CD',
    wildwavetokens: 'WXT'
  };

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    let targetCard = null;

    if (Number.isFinite(cardIdFromBody) && cardIdFromBody > 0) {
      const { rows } = await client.query(
        `SELECT id
         FROM ocean_pay_cards
         WHERE id = $1 AND user_id = $2 AND COALESCE(is_active, true) = true
         FOR UPDATE`,
        [cardIdFromBody, userId]
      );
      targetCard = rows[0] || null;
    } else if (cardNumber) {
      const { rows } = await client.query(
        `SELECT id
         FROM ocean_pay_cards
         WHERE user_id = $1 AND card_number = $2 AND COALESCE(is_active, true) = true
         LIMIT 1
         FOR UPDATE`,
        [userId, cardNumber]
      );
      targetCard = rows[0] || null;
    }

    if (!targetCard) {
      targetCard = await ensurePrimaryCardForUser(client, userId, true);
    }

    if (!targetCard) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'No se encontrï¿½ una tarjeta vï¿½lida' });
    }

    const targetCardId = Number(targetCard.id);
    const currentBalance = await getUnifiedCardCurrencyBalance(client, targetCardId, currencyType, true);
    const newBalance = currentBalance + delta;

    if (newBalance < 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        error: 'Saldo insuficiente',
        currencyType,
        currentBalance
      });
    }

    await setUnifiedCardCurrencyBalance(client, {
      userId,
      cardId: targetCardId,
      currency: currencyType,
      newBalance
    });

    const txCurrency = txCurrencyCodeByType[currencyType] || currencyType.toUpperCase().slice(0, 10);
    await client.query(
      `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
       VALUES ($1, $2, $3, $4, $5)`,
      [userId, concepto, delta, origen, txCurrency]
    ).catch(async () => {
      await client.query(
        `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen)
         VALUES ($1, $2, $3, $4)`,
        [userId, concepto, delta, origen]
      );
    });

    await client.query('COMMIT');
    return res.json({
      success: true,
      currencyType,
      cardId: targetCardId,
      previousBalance: currentBalance,
      newBalance
    });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Error en /ocean-pay/cards/change-balance:', e);
    return res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});


// Changelogs centralizados para todos los proyectos (fuente: ows_store_timeline + sync GitHub)
app.get('/ows-store/changelogs', async (req, res) => {
  const projectFilter = String(req.query.project || req.query.slug || '').trim().toLowerCase();
  const includeInactive = normalizeNewsBoolean(req.query.include_inactive, false);
  const limit = Math.max(1, Math.min(500, normalizeNewsNumber(req.query.limit, 120)));
  const autoSync = normalizeNewsBoolean(req.query.autosync, true);
  const forceSync = normalizeNewsBoolean(req.query.force_sync, false);
  try {
    if (autoSync) {
      await ensureProjectChangelogSync({
        force: forceSync,
        projectSlug: projectFilter
      });
    }

    const { rows } = await pool.query(`
      SELECT *
      FROM ows_store_timeline
      WHERE kind = 'changelog'
      ORDER BY COALESCE(priority, 0) DESC, published_at DESC, created_at DESC
      LIMIT $1
    `, [limit * 2]);

    let list = rows.map(normalizeOwsNewsRow);
    if (!includeInactive) list = list.filter(r => r.is_active !== false);
    if (projectFilter) {
      list = list.filter((r) => {
        const names = Array.isArray(r.project_names) ? r.project_names : [];
        const slugs = Array.isArray(r.project_slugs) ? r.project_slugs : [];
        return names.some((name) => String(name || '').toLowerCase().includes(projectFilter))
          || slugs.some((slug) => String(slug || '').toLowerCase().includes(projectFilter));
      });
    }
    list = list.slice(0, limit);
    return res.json({ success: true, total: list.length, changelogs: list });
  } catch (err) {
    console.error('âŒ Error en GET /ows-store/changelogs:', err);
    return res.status(500).json({ error: 'Error interno' });
  }
});

// Sync manual de changelogs desde GitHub releases hacia ows_store_timeline
app.post('/ows-store/changelogs/sync', async (req, res) => {
  if (!requireOwsStoreAdmin(req, res)) return;
  const projectSlug = String(req.body?.project_slug || '').trim().toLowerCase();
  try {
    const result = await ensureProjectChangelogSync({
      force: true,
      projectSlug
    });
    return res.json({ success: true, sync: result });
  } catch (err) {
    console.error('âŒ Error en POST /ows-store/changelogs/sync:', err);
    return res.status(500).json({ error: 'Error interno' });
  }
});

function parseStudioAuthToken(req) {
  const authHeader = String(req.headers.authorization || '');
  if (!authHeader.toLowerCase().startsWith('bearer ')) return '';
  return authHeader.slice(7).trim();
}

function decodeStudioTokenOrNull(token) {
  if (!token) return null;
  try {
    return jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
  } catch (_err) {
    return null;
  }
}

function toFiniteNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function mergeBalanceMaps(primary = {}, secondary = {}) {
  const merged = {};
  const keys = new Set([
    ...Object.keys(primary || {}),
    ...Object.keys(secondary || {})
  ]);
  keys.forEach((key) => {
    const a = toFiniteNumber(primary?.[key], 0);
    const b = toFiniteNumber(secondary?.[key], 0);
    merged[key] = Math.max(a, b);
  });
  return merged;
}

const OCEAN_AI_CURRENCY = 'coralbits';
const OCEAN_AI_PROJECT_ID = 'Ocean AI';
const OCEAN_AI_PLAN_INTERVAL_DAYS = 7;
const OCEAN_AI_PLANS = Object.freeze({
  // Plan Delfin — acceso serie completa Delfin
  tide: {
    id: 'tide',
    name: 'Delfin',
    weeklyCost: 120,
    models: ['dolphin10', 'dolphin11', 'dolphin11m', 'dolphin11max', 'dolphin12'],
    benefits: ['Serie Delfin completa (1 a 1.2)', 'Herramientas Delfin', 'Velocidad mejorada', 'Historial extendido']
  },
  // Plan Ballena Starter — Ballena 1 y Mini
  coral: {
    id: 'coral',
    name: 'Ballena',
    weeklyCost: 280,
    models: ['dolphin10', 'dolphin11', 'dolphin11m', 'dolphin11max', 'dolphin12', 'whale1', 'whale1m'],
    benefits: ['Serie Delfin completa', 'Ballena 1 y Ballena 1 Mini', 'Herramientas Ballena', 'Mayor contexto']
  },
  // Plan Ballena Max — incluye Ballena 1 Max
  abyss: {
    id: 'abyss',
    name: 'Ballena Max',
    weeklyCost: 520,
    models: ['dolphin10', 'dolphin11', 'dolphin11m', 'dolphin11max', 'dolphin12', 'whale1', 'whale1m', 'whale1max'],
    benefits: ['Serie Delfin completa', 'Ballena 1, Mini y Max', 'Herramientas Ballena Max', 'Prioridad de respuesta']
  },
  // Plan Cobalt — Ballena completa incluyendo Blue Max
  cobalt: {
    id: 'cobalt',
    name: 'Ballena Blue',
    weeklyCost: 550,
    models: ['dolphin10', 'dolphin11', 'dolphin11m', 'dolphin11max', 'dolphin12', 'whale1', 'whale1m', 'whale1max', 'whale1bm'],
    benefits: ['Serie Delfin completa', 'Ballena 1 completa + Blue Max', 'Herramientas avanzadas', 'Prioridad alta']
  },
  // Plan Leviathan — todos los modelos incluyendo Ballena Blue Max y Tiburon
  leviathan: {
    id: 'leviathan',
    name: 'Leviathan',
    weeklyCost: 900,
    models: ['dolphin10', 'dolphin11', 'dolphin11m', 'dolphin11max', 'dolphin12', 'whale1', 'whale1m', 'whale1max', 'whale1bm', 'shark'],
    benefits: ['Todos los modelos', 'Ballena 1 Blue Max + Tiburon 1', 'Máxima prioridad', 'Sin restricciones']
  }
});

function sanitizeCoralBits(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.floor(n));
}

async function getPrimaryCardWithBalances(client, userId) {
  const { rows } = await client.query(
    `SELECT id, balances
       FROM ocean_pay_cards
      WHERE user_id = $1
      ORDER BY is_primary DESC, created_at ASC, id ASC
      LIMIT 1`,
    [userId]
  );
  return rows[0] || null;
}

async function getCoralBitsBalanceForUser(client, userId) {
  const card = await getPrimaryCardWithBalances(client, userId);
  if (!card?.id) return 0;
  const { rows } = await client.query(
    `SELECT amount
       FROM ocean_pay_card_balances
      WHERE card_id = $1
        AND currency_type = $2
      LIMIT 1`,
    [card.id, OCEAN_AI_CURRENCY]
  );
  const tableBal = toFiniteNumber(rows[0]?.amount, 0);
  const jsonBal = toFiniteNumber(card.balances?.[OCEAN_AI_CURRENCY], 0);
  return Math.max(tableBal, jsonBal);
}

async function resolveOceanPayUserByCredentials(client, username, password) {
  const normalizedUser = String(username || '').trim();
  const rawPassword = String(password || '').trim();
  if (!normalizedUser || !rawPassword) return null;

  const { rows } = await client.query(
    `SELECT id, username, pwd_hash, password
       FROM ocean_pay_users
      WHERE LOWER(username) = LOWER($1)
      LIMIT 1`,
    [normalizedUser]
  );
  if (!rows.length) return null;

  const user = rows[0];
  const candidateHashes = [user.pwd_hash, user.password].filter(Boolean);
  let ok = false;

  for (const candidate of candidateHashes) {
    try {
      if (await bcrypt.compare(rawPassword, String(candidate))) {
        ok = true;
        break;
      }
    } catch (_) {
      // no-op
    }
    if (String(candidate) === rawPassword) {
      ok = true;
      break;
    }
  }

  return ok ? { id: Number(user.id), username: String(user.username || normalizedUser) } : null;
}

async function getOceanAiActiveSubscription(client, userId) {
  const { rows } = await client.query(
    `SELECT id, plan_name, sub_name, project_id, price, currency, end_date, interval_days
       FROM ocean_pay_subscriptions
      WHERE user_id = $1
        AND project_id = $2
      ORDER BY end_date DESC NULLS LAST, id DESC
      LIMIT 1`,
    [userId, OCEAN_AI_PROJECT_ID]
  );
  const row = rows[0] || null;
  if (!row) return null;
  const endDate = row.end_date ? new Date(row.end_date) : null;
  const isActive = !!endDate && endDate.getTime() > Date.now();
  return {
    ...row,
    isActive,
    renewalAt: endDate ? endDate.toISOString() : null,
    expiresAt: endDate ? endDate.toISOString() : null
  };
}

function getOceanAiPlanByName(name) {
  const target = String(name || '').trim().toLowerCase();
  // Direct name match
  const direct = Object.values(OCEAN_AI_PLANS).find((p) => p.name.toLowerCase() === target);
  if (direct) return direct;
  // Legacy name aliases (old subscriptions stored with different names)
  const ALIASES = {
    'tiburon': 'leviathan',
    'ballena blue': 'cobalt',
    'ballena max': 'abyss',
    'ballena': 'coral',
    'delfin': 'tide',
    'delfin plus': 'tide',
  };
  const aliasKey = ALIASES[target];
  return aliasKey ? (OCEAN_AI_PLANS[aliasKey] || null) : null;
}

async function fetchGithubLatestReleaseLite(owner, repo) {
  const safeOwner = String(owner || '').trim();
  const safeRepo = String(repo || '').trim();
  if (!safeOwner || !safeRepo) return null;

  const headers = {
    'User-Agent': 'OWS-OceanAI',
    'Accept': 'application/vnd.github+json'
  };
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || '';
  if (token) headers.Authorization = `Bearer ${token}`;

  try {
    const apiRes = await fetch(`https://api.github.com/repos/${safeOwner}/${safeRepo}/releases/latest`, { headers });
    if (apiRes.ok) {
      const payload = await apiRes.json();
      return payload && typeof payload === 'object' ? payload : null;
    }
  } catch (_apiErr) {
    // fallback below
  }

  try {
    const latestRes = await fetch(`https://github.com/${safeOwner}/${safeRepo}/releases/latest`, {
      redirect: 'follow',
      headers: { 'User-Agent': 'OWS-OceanAI' }
    });
    if (!latestRes.ok) return null;

    const finalUrl = String(latestRes.url || '');
    const tagMatch = finalUrl.match(/\/releases\/tag\/([^/?#]+)/i);
    const tagName = tagMatch ? decodeURIComponent(tagMatch[1]) : '';
    if (!tagName) return null;

    return {
      tag_name: tagName,
      name: tagName,
      html_url: `https://github.com/${safeOwner}/${safeRepo}/releases/tag/${encodeURIComponent(tagName)}`,
      assets: []
    };
  } catch (_fallbackErr) {
    return null;
  }
}

function pickInstallerAssetUrlFromRelease(release) {
  const assets = Array.isArray(release?.assets) ? release.assets : [];
  const preferred = assets.find((a) => /\.(exe|msi)$/i.test(String(a?.name || '')));
  if (preferred?.browser_download_url) return String(preferred.browser_download_url);
  return '';
}

async function githubProxyHandler(req, res) {
  const GH_CACHE_TTL_MS = 5 * 60 * 1000;
  const GH_STALE_TTL_MS = 24 * 60 * 60 * 1000;
  if (!globalThis.__owsGithubProxyCache) globalThis.__owsGithubProxyCache = new Map();
  const proxyCache = globalThis.__owsGithubProxyCache;

  const owner = String(req.params.owner || '').trim();
  const repo = String(req.params.repo || '').trim();
  const tail = String(req.params[0] || '').replace(/^\/+/, '');
  if (!owner || !repo) {
    return res.status(400).json({ error: 'owner/repo requeridos' });
  }

  const queryIndex = String(req.originalUrl || '').indexOf('?');
  const query = queryIndex >= 0 ? String(req.originalUrl || '').slice(queryIndex) : '';
  const ghUrl = `https://api.github.com/repos/${owner}/${repo}${tail ? `/${tail}` : ''}${query}`;
  const cacheKey = ghUrl;
  const now = Date.now();
  const cached = proxyCache.get(cacheKey);
  if (cached && (now - cached.ts) < GH_CACHE_TTL_MS) {
    res.setHeader('Cache-Control', 'no-store, max-age=0');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('X-OWS-GH-Cache', 'hit');
    return res.json(cached.payload);
  }

  const buildReleaseFallbackFromHtml = async () => {
    const latestUrl = `https://github.com/${owner}/${repo}/releases/latest`;
    const latestRes = await fetch(latestUrl, {
      redirect: 'follow',
      headers: { 'User-Agent': 'OWS-Store-Proxy' }
    });
    if (!latestRes.ok) {
      throw new Error(`Fallback latest page failed: ${latestRes.status}`);
    }

    const finalUrl = String(latestRes.url || latestUrl);
    const html = await latestRes.text();
    const tagMatch = finalUrl.match(/\/releases\/tag\/([^/?#]+)/i);
    const tagName = tagMatch ? decodeURIComponent(tagMatch[1]) : '';
    if (!tagName) throw new Error('Fallback could not resolve release tag');

    const collectAssetsFromHtml = (sourceHtml) => {
      const names = new Set();
      const escapedTag = tagName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const assetRegex = new RegExp(`/` + owner + `/` + repo + `/releases/download/` + escapedTag + `/([^\"'<>\\s?#]+)`, 'gi');
      let match;
      while ((match = assetRegex.exec(String(sourceHtml || ''))) !== null) {
        const raw = decodeURIComponent(String(match[1] || '').trim());
        if (raw) names.add(raw);
      }
      return names;
    };

    const assetNames = new Set();
    const latestDownloadBase = `https://github.com/${owner}/${repo}/releases/latest/download`;

    // 1) Try latest.yml (works for Electron/NSIS repos, avoids GitHub API limits)
    try {
      const latestYmlRes = await fetch(`${latestDownloadBase}/latest.yml`, {
        redirect: 'follow',
        headers: { 'User-Agent': 'OWS-Store-Proxy' }
      });
      if (latestYmlRes.ok) {
        const yml = await latestYmlRes.text();
        const fileUrlMatches = [...String(yml || '').matchAll(/^\s*url:\s*([^\r\n#]+)\s*$/gmi)];
        const pathMatches = [...String(yml || '').matchAll(/^\s*path:\s*([^\r\n#]+)\s*$/gmi)];
        const addFromRaw = (rawValue) => {
          const raw = String(rawValue || '').trim().replace(/^['"]|['"]$/g, '');
          if (!raw) return;
          const normalized = raw.split('?')[0];
          const name = decodeURIComponent(normalized.split('/').pop() || '');
          if (name) assetNames.add(name);
        };
        fileUrlMatches.forEach((m) => addFromRaw(m[1]));
        pathMatches.forEach((m) => addFromRaw(m[1]));
      }
    } catch (_latestYmlErr) {
      // best-effort fallback only
    }

    // 2) Try expanded assets HTML page
    const expandedUrl = `https://github.com/${owner}/${repo}/releases/expanded_assets/${encodeURIComponent(tagName)}`;
    try {
      const expandedRes = await fetch(expandedUrl, {
        redirect: 'follow',
        headers: { 'User-Agent': 'OWS-Store-Proxy' }
      });
      if (expandedRes.ok) {
        const expandedHtml = await expandedRes.text();
        collectAssetsFromHtml(expandedHtml).forEach((n) => assetNames.add(n));
      }
    } catch (_expandedErr) {
      // best-effort fallback only
    }

    if (!assetNames.size) {
      collectAssetsFromHtml(html).forEach((n) => assetNames.add(n));
    }

    const assets = [...assetNames].map((name) => ({
      name,
      browser_download_url: `https://github.com/${owner}/${repo}/releases/download/${tagName}/${name}`,
      size: 0,
      updated_at: null
    }));

    const payload = {
      tag_name: tagName,
      name: tagName,
      html_url: `https://github.com/${owner}/${repo}/releases/tag/${tagName}`,
      draft: false,
      prerelease: false,
      published_at: null,
      created_at: null,
      body: '',
      assets
    };

    if (/^releases$/i.test(tail)) {
      return [payload];
    }
    return payload;
  };

  try {
    const headers = {
      'User-Agent': 'OWS-Store-Proxy',
      'Accept': 'application/vnd.github+json'
    };
    const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || '';
    if (token) headers.Authorization = `Bearer ${token}`;
    const ghRes = await fetch(ghUrl, { headers });
    const text = await ghRes.text();

    res.setHeader('Cache-Control', 'no-store, max-age=0');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');

    if (!ghRes.ok) {
      const isRateLimit = ghRes.status === 403 && /rate limit exceeded/i.test(String(text || ''));
      if (isRateLimit) {
        try {
          const fallbackPayload = await buildReleaseFallbackFromHtml();
          proxyCache.set(cacheKey, { ts: Date.now(), payload: fallbackPayload });
          res.setHeader('Cache-Control', 'no-store, max-age=0');
          res.setHeader('Pragma', 'no-cache');
          res.setHeader('Expires', '0');
          res.setHeader('X-OWS-GH-Fallback', 'html-release');
          return res.json(fallbackPayload);
        } catch (fallbackErr) {
          if (cached && (now - cached.ts) < GH_STALE_TTL_MS) {
            res.setHeader('Cache-Control', 'no-store, max-age=0');
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '0');
            res.setHeader('X-OWS-GH-Cache', 'stale');
            res.setHeader('X-OWS-GH-Fallback', 'stale-cache');
            return res.json(cached.payload);
          }
          return res.status(502).json({
            error: 'GitHub API rate limited y fallback fallido',
            status: ghRes.status,
            url: ghUrl,
            details: text || null,
            fallback_error: fallbackErr?.message || String(fallbackErr)
          });
        }
      }

      return res.status(ghRes.status).json({
        error: `GitHub API ${ghRes.status}`,
        status: ghRes.status,
        url: ghUrl,
        details: text || null
      });
    }

    try {
      const payload = JSON.parse(text);
      proxyCache.set(cacheKey, { ts: Date.now(), payload });
      res.setHeader('X-OWS-GH-Cache', 'miss');
      return res.json(payload);
    } catch (_parseErr) {
      return res.status(502).json({ error: 'Respuesta invalida de GitHub API', url: ghUrl });
    }
  } catch (err) {
    return res.status(500).json({ error: 'Error en proxy GitHub', details: err?.message || String(err) });
  }
}

function normalizeOfferSurface(value) {
  const raw = String(value || '').trim().toLowerCase();
  if (raw === 'ows-store' || raw === 'ows_store' || raw === 'store') return 'ows-store';
  return 'project';
}

function normalizeCommerceProjectSlug(value) {
  const slug = String(value || '').trim().toLowerCase();
  if (!slug) return '';
  if (slug === 'velocitysurge') return 'velocity-surge';
  return slug;
}

function parseOfferBoolean(value, fallback = false) {
  if (value === undefined || value === null || value === '') return Boolean(fallback);
  const v = String(value).trim().toLowerCase();
  if (['1', 'true', 'yes', 'y', 'on'].includes(v)) return true;
  if (['0', 'false', 'no', 'n', 'off'].includes(v)) return false;
  return Boolean(fallback);
}

function toOfferPrice(value, fallback = 0) {
  const n = Number(value);
  if (!Number.isFinite(n)) return Math.max(0, Number(fallback || 0));
  return Math.max(0, Number(n.toFixed(2)));
}

function getOfferPurchaseLimitFromMetadata(metadata = {}) {
  const meta = (metadata && typeof metadata === 'object') ? metadata : {};
  const rawLimit = Number(
    meta.max_purchases_per_user
    ?? meta.purchase_limit_per_user
    ?? meta.user_limit
    ?? 0
  );
  const normalizedLimit = Number.isFinite(rawLimit) ? Math.max(0, Math.floor(rawLimit)) : 0;
  if (normalizedLimit > 0) return normalizedLimit;
  return parseOfferBoolean(meta.one_time_per_user, false) ? 1 : 0;
}

function getOfferCounterKey(projectSlug = '', offerCode = '') {
  return `${String(projectSlug || '').trim().toLowerCase()}::${String(offerCode || '').trim().toLowerCase()}`;
}

function getOfferDefaultVisualKey(projectSlug = '', offerCode = '', metadata = {}) {
  const slug = String(projectSlug || '').toLowerCase();
  const code = String(offerCode || '').toLowerCase();
  const explicit = String(metadata?.visual_key || metadata?.illustration_key || '').trim();
  if (explicit) return explicit;
  if (slug.includes('velocity')) {
    if (code.includes('planet')) return 'galaxy_core';
    if (code.includes('cloudwing')) return 'signal_flow';
    return 'velocity_racers';
  }
  if (slug.includes('wildwave')) return 'signal_flow';
  if (slug.includes('wildtransfer')) return 'signal_flow';
  if (slug.includes('floret')) return 'forest_grid';
  if (slug.includes('wilddestiny')) return 'galaxy_core';
  return 'launch_orbit';
}

function mapProjectOfferRow(row, { surface = 'project' } = {}) {
  const normalizedSurface = normalizeOfferSurface(surface);
  const basePrice = toOfferPrice(row?.base_price, 0);
  const storePriceRaw = toOfferPrice(row?.ows_store_price, 0);
  const hasStoreOverride = storePriceRaw > 0;
  const effectivePrice = normalizedSurface === 'ows-store'
    ? (hasStoreOverride ? storePriceRaw : basePrice)
    : basePrice;
  const hasExclusiveDiscount = normalizedSurface === 'ows-store'
    && hasStoreOverride
    && storePriceRaw < basePrice;
  const discountPercent = hasExclusiveDiscount && basePrice > 0
    ? Math.max(1, Math.round(((basePrice - storePriceRaw) / basePrice) * 100))
    : 0;
  const metadata = (row?.metadata && typeof row.metadata === 'object') ? row.metadata : {};
  const rewardPayload = (row?.reward_payload && typeof row.reward_payload === 'object') ? row.reward_payload : {};
  const projectSlug = String(row?.project_slug || '');
  const offerCode = String(row?.offer_code || '');
  const illustration = {
    type: 'model2d',
    key: getOfferDefaultVisualKey(projectSlug, offerCode, metadata),
    primaryColor: String(metadata?.illustration_primary || metadata?.primary_color || ''),
    secondaryColor: String(metadata?.illustration_secondary || metadata?.secondary_color || ''),
    imageUrl: String(metadata?.illustration_image_url || ''),
    projectIconUrl: String(row?.project_icon_url || ''),
  };

  return {
    id: Number(row?.id || 0),
    projectSlug,
    projectName: String(row?.project_name || ''),
    projectDescription: String(row?.project_description || ''),
    projectIconUrl: String(row?.project_icon_url || ''),
    offerCode,
    title: String(row?.title || ''),
    description: String(row?.description || ''),
    currency: String(row?.currency || 'voltbit').toLowerCase(),
    basePrice,
    surfacePrice: effectivePrice,
    storePrice: hasStoreOverride ? storePriceRaw : null,
    hasStoreExclusiveDiscount: hasExclusiveDiscount,
    discountPercent,
    purchaseLimit: getOfferPurchaseLimitFromMetadata(metadata),
    isActive: Boolean(row?.is_active),
    startsAt: row?.starts_at || null,
    endsAt: row?.ends_at || null,
    illustration,
    rewardPayload,
    metadata,
    createdAt: row?.created_at || null,
    updatedAt: row?.updated_at || null
  };
}

function getOfferBalanceMapAndAmount(newBalance, currency) {
  const balances = {};
  balances[String(currency || 'voltbit').toLowerCase()] = Number(newBalance || 0);
  return balances;
}

app.get('/project-commerce/:slug/offers', async (req, res) => {
  const projectSlug = normalizeCommerceProjectSlug(req.params.slug);
  if (!projectSlug) return res.status(400).json({ error: 'slug requerido' });
  const surface = normalizeOfferSurface(req.query.surface);
  const includeInactive = parseOfferBoolean(req.query.include_inactive, false);
  const hidePurchased = parseOfferBoolean(req.query.hide_purchased, false);
  const nowIso = new Date().toISOString();
  const userId = getAuthenticatedOceanPayUserId(req);

  try {
    const values = [projectSlug, nowIso];
    let sql = `
      SELECT o.*,
             p.name AS project_name,
             p.description AS project_description,
             p.icon_url AS project_icon_url
      FROM ows_project_offers o
      JOIN ows_projects p ON p.slug = o.project_slug
      WHERE o.project_slug = $1
    `;
    if (!includeInactive) {
      sql += `
        AND o.is_active = TRUE
        AND (o.starts_at IS NULL OR o.starts_at <= $2::timestamp)
        AND (o.ends_at IS NULL OR o.ends_at >= $2::timestamp)
      `;
    }
    sql += ' ORDER BY o.created_at DESC, o.id DESC';

    const { rows } = await pool.query(sql, values);
    let mappedOffers = rows.map((row) => mapProjectOfferRow(row, { surface }));

    if (userId > 0 && mappedOffers.length > 0) {
      const { rows: purchasedRows } = await pool.query(
        `SELECT offer_code, COUNT(*)::int AS total
         FROM ows_project_offer_purchases
         WHERE user_id = $1
           AND project_slug = $2
           AND status = 'completed'
         GROUP BY offer_code`,
        [userId, projectSlug]
      );
      const purchasesMap = new Map(
        purchasedRows.map((r) => [String(r.offer_code || '').trim().toLowerCase(), Number(r.total || 0)])
      );

      mappedOffers = mappedOffers.map((offer) => {
        const purchaseLimit = Math.max(0, Number(offer?.purchaseLimit || 0));
        const userPurchaseCount = Number(purchasesMap.get(String(offer?.offerCode || '').trim().toLowerCase()) || 0);
        const remainingStockPerUser = purchaseLimit > 0
          ? Math.max(0, purchaseLimit - userPurchaseCount)
          : null;
        const soldOut = purchaseLimit > 0 && remainingStockPerUser <= 0;
        return {
          ...offer,
          userPurchaseCount,
          remainingStockPerUser,
          soldOut
        };
      });
    } else {
      mappedOffers = mappedOffers.map((offer) => ({
        ...offer,
        userPurchaseCount: 0,
        remainingStockPerUser: Number(offer?.purchaseLimit || 0) > 0 ? Number(offer.purchaseLimit) : null,
        soldOut: false
      }));
    }

    if (hidePurchased) {
      mappedOffers = mappedOffers.filter((offer) => !(offer?.soldOut === true));
    }

    return res.json({
      success: true,
      projectSlug,
      surface,
      offers: mappedOffers
    });
  } catch (err) {
    console.error('Error en GET /project-commerce/:slug/offers:', err);
    return res.status(500).json({ error: 'Error interno' });
  }
});

app.get('/project-commerce/offers/catalog', async (req, res) => {
  const surface = normalizeOfferSurface(req.query.surface);
  const includeInactive = parseOfferBoolean(req.query.include_inactive, false);
  const hidePurchased = parseOfferBoolean(req.query.hide_purchased, true);
  const nowIso = new Date().toISOString();
  const userId = getAuthenticatedOceanPayUserId(req);

  try {
    const values = [nowIso];
    let sql = `
      SELECT o.*,
             p.name AS project_name,
             p.description AS project_description,
             p.icon_url AS project_icon_url
      FROM ows_project_offers o
      JOIN ows_projects p ON p.slug = o.project_slug
      WHERE 1=1
    `;
    if (!includeInactive) {
      sql += `
        AND o.is_active = TRUE
        AND (o.starts_at IS NULL OR o.starts_at <= $1::timestamp)
        AND (o.ends_at IS NULL OR o.ends_at >= $1::timestamp)
      `;
    }
    sql += ' ORDER BY p.name ASC, o.created_at DESC, o.id DESC';

    const { rows } = await pool.query(sql, values);
    let mappedOffers = rows.map((row) => mapProjectOfferRow(row, { surface }));

    if (userId > 0 && mappedOffers.length > 0) {
      const { rows: purchasedRows } = await pool.query(
        `SELECT project_slug, offer_code, COUNT(*)::int AS total
         FROM ows_project_offer_purchases
         WHERE user_id = $1
           AND status = 'completed'
         GROUP BY project_slug, offer_code`,
        [userId]
      );
      const purchasesMap = new Map(
        purchasedRows.map((r) => [
          getOfferCounterKey(r.project_slug, r.offer_code),
          Number(r.total || 0)
        ])
      );

      mappedOffers = mappedOffers.map((offer) => {
        const purchaseLimit = Math.max(0, Number(offer?.purchaseLimit || 0));
        const key = getOfferCounterKey(offer?.projectSlug, offer?.offerCode);
        const userPurchaseCount = Number(purchasesMap.get(key) || 0);
        const remainingStockPerUser = purchaseLimit > 0
          ? Math.max(0, purchaseLimit - userPurchaseCount)
          : null;
        const soldOut = purchaseLimit > 0 && remainingStockPerUser <= 0;
        return {
          ...offer,
          userPurchaseCount,
          remainingStockPerUser,
          soldOut
        };
      });
    } else {
      mappedOffers = mappedOffers.map((offer) => ({
        ...offer,
        userPurchaseCount: 0,
        remainingStockPerUser: Number(offer?.purchaseLimit || 0) > 0 ? Number(offer.purchaseLimit) : null,
        soldOut: false
      }));
    }

    if (hidePurchased) {
      mappedOffers = mappedOffers.filter((offer) => !(offer?.soldOut === true));
    }

    return res.json({
      success: true,
      surface,
      offers: mappedOffers
    });
  } catch (err) {
    console.error('Error en GET /project-commerce/offers/catalog:', err);
    return res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/project-commerce/:slug/offers', async (req, res) => {
  if (!requireOwsStoreAdmin(req, res)) return;
  const projectSlug = normalizeCommerceProjectSlug(req.params.slug);
  const payload = req.body || {};
  const offerCode = String(payload.offer_code || payload.offerCode || '').trim().toLowerCase();
  const title = String(payload.title || '').trim();
  const description = String(payload.description || '').trim() || null;
  const currency = String(payload.currency || 'voltbit').trim().toLowerCase();
  const basePrice = toOfferPrice(payload.base_price ?? payload.basePrice, 0);
  const owsStorePrice = payload.ows_store_price !== undefined || payload.owsStorePrice !== undefined
    ? toOfferPrice(payload.ows_store_price ?? payload.owsStorePrice, 0)
    : null;
  const rewardPayload = (payload.reward_payload && typeof payload.reward_payload === 'object')
    ? payload.reward_payload
    : ((payload.rewardPayload && typeof payload.rewardPayload === 'object') ? payload.rewardPayload : {});
  const metadata = (payload.metadata && typeof payload.metadata === 'object') ? payload.metadata : {};
  const isActive = parseOfferBoolean(payload.is_active ?? payload.isActive, true);
  const startsAt = payload.starts_at || payload.startsAt || null;
  const endsAt = payload.ends_at || payload.endsAt || null;

  if (!projectSlug) return res.status(400).json({ error: 'slug requerido' });
  if (!offerCode) return res.status(400).json({ error: 'offer_code requerido' });
  if (!title) return res.status(400).json({ error: 'title requerido' });
  if (basePrice <= 0) return res.status(400).json({ error: 'base_price debe ser mayor a 0' });

  try {
    const projectExists = await pool.query('SELECT 1 FROM ows_projects WHERE slug = $1 LIMIT 1', [projectSlug]);
    if (!projectExists.rowCount) return res.status(404).json({ error: 'Proyecto no registrado en ows_projects' });

    const { rows } = await pool.query(
      `INSERT INTO ows_project_offers (
         project_slug, offer_code, title, description, currency, base_price, ows_store_price,
         reward_payload, metadata, is_active, starts_at, ends_at, updated_at
       )
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW())
       ON CONFLICT (project_slug, offer_code) DO UPDATE SET
         title = EXCLUDED.title,
         description = EXCLUDED.description,
         currency = EXCLUDED.currency,
         base_price = EXCLUDED.base_price,
         ows_store_price = EXCLUDED.ows_store_price,
         reward_payload = EXCLUDED.reward_payload,
         metadata = ows_project_offers.metadata || EXCLUDED.metadata,
         is_active = EXCLUDED.is_active,
         starts_at = EXCLUDED.starts_at,
         ends_at = EXCLUDED.ends_at,
         updated_at = NOW()
       RETURNING *`,
      [
        projectSlug,
        offerCode,
        title,
        description,
        currency,
        basePrice,
        owsStorePrice,
        rewardPayload || {},
        metadata || {},
        isActive,
        startsAt,
        endsAt
      ]
    );

    return res.json({
      success: true,
      offer: mapProjectOfferRow(rows[0], { surface: 'ows-store' })
    });
  } catch (err) {
    console.error('Error en POST /project-commerce/:slug/offers:', err);
    return res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/project-commerce/:slug/offers/:offerCode/purchase', async (req, res) => {
  const userId = getAuthenticatedOceanPayUserId(req);
  if (!userId) return res.status(401).json({ error: 'Token invalido' });
  const projectSlug = normalizeCommerceProjectSlug(req.params.slug);
  const offerCode = String(req.params.offerCode || '').trim().toLowerCase();
  const surface = normalizeOfferSurface(req.body?.surface || req.query?.surface);
  const nowIso = new Date().toISOString();
  if (!projectSlug || !offerCode) return res.status(400).json({ error: 'slug y offerCode requeridos' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { rows: offerRows } = await client.query(
      `SELECT *
       FROM ows_project_offers
       WHERE project_slug = $1
         AND offer_code = $2
         AND is_active = TRUE
         AND (starts_at IS NULL OR starts_at <= $3::timestamp)
         AND (ends_at IS NULL OR ends_at >= $3::timestamp)
       FOR UPDATE`,
      [projectSlug, offerCode, nowIso]
    );
    if (!offerRows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Oferta no disponible' });
    }

    const offerRow = offerRows[0];
    const mapped = mapProjectOfferRow(offerRow, { surface });
    const purchaseLimit = getOfferPurchaseLimitFromMetadata(offerRow?.metadata || {});
    const existingCountRes = await client.query(
      `SELECT COUNT(*)::int AS total
       FROM ows_project_offer_purchases
       WHERE project_slug = $1
         AND offer_code = $2
         AND user_id = $3
         AND status = 'completed'`,
      [projectSlug, offerCode, userId]
    );
    const existingCount = Number(existingCountRes.rows?.[0]?.total || 0);
    if (purchaseLimit > 0 && existingCount >= purchaseLimit) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: 'Stock agotado para esta oferta en tu cuenta',
        purchaseLimit,
        userPurchaseCount: existingCount,
        remainingStockPerUser: 0
      });
    }

    const currency = String(mapped.currency || 'voltbit').toLowerCase();
    const price = toOfferPrice(mapped.surfacePrice, 0);
    if (price <= 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Precio de oferta invalido' });
    }

    const currentBalance = await getUnifiedBalance(client, userId, currency);
    if (currentBalance < price) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        error: 'Saldo insuficiente',
        currency,
        currentBalance: Number(currentBalance || 0),
        required: price
      });
    }

    const newBalance = Number((currentBalance - price).toFixed(2));
    await setUnifiedBalance(client, userId, currency, newBalance);

    await client.query(
      `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        userId,
        `Compra oferta ${mapped.title}`,
        -price,
        `Project Commerce (${projectSlug})`,
        String(currency || 'voltbit').toUpperCase()
      ]
    );

    const { rows: purchaseRows } = await client.query(
      `INSERT INTO ows_project_offer_purchases (
         project_slug, offer_code, user_id, surface, currency, paid_amount,
         reward_payload, metadata, status, claimed_by_project
       )
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'completed',FALSE)
       RETURNING *`,
      [
        projectSlug,
        offerCode,
        userId,
        surface,
        currency,
        price,
        offerRow?.reward_payload || {},
        offerRow?.metadata || {}
      ]
    );

    await client.query('COMMIT');
    return res.json({
      success: true,
      projectSlug,
      surface,
      offer: mapped,
      purchase: {
        id: Number(purchaseRows[0]?.id || 0),
        createdAt: purchaseRows[0]?.created_at || null
      },
      balance: {
        currency,
        amount: newBalance,
        balances: getOfferBalanceMapAndAmount(newBalance, currency)
      },
      rewardPayload: (offerRow?.reward_payload && typeof offerRow.reward_payload === 'object') ? offerRow.reward_payload : {},
      stock: {
        purchaseLimit,
        userPurchaseCount: existingCount + 1,
        remainingStockPerUser: purchaseLimit > 0
          ? Math.max(0, purchaseLimit - (existingCount + 1))
          : null,
        soldOut: purchaseLimit > 0 && (existingCount + 1) >= purchaseLimit
      }
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error en POST /project-commerce/:slug/offers/:offerCode/purchase:', err);
    return res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

app.get('/project-commerce/:slug/purchases/pending', async (req, res) => {
  const userId = getAuthenticatedOceanPayUserId(req);
  if (!userId) return res.status(401).json({ error: 'Token invalido' });
  const projectSlug = normalizeCommerceProjectSlug(req.params.slug);
  if (!projectSlug) return res.status(400).json({ error: 'slug requerido' });

  try {
    const { rows } = await pool.query(
      `SELECT id, project_slug, offer_code, surface, currency, paid_amount, reward_payload, metadata, created_at
       FROM ows_project_offer_purchases
       WHERE user_id = $1
         AND project_slug = $2
         AND status = 'completed'
         AND claimed_by_project = FALSE
       ORDER BY created_at ASC, id ASC`,
      [userId, projectSlug]
    );
    return res.json({
      success: true,
      pending: rows.map((row) => ({
        id: Number(row.id || 0),
        projectSlug: String(row.project_slug || ''),
        offerCode: String(row.offer_code || ''),
        surface: String(row.surface || ''),
        currency: String(row.currency || ''),
        paidAmount: toOfferPrice(row.paid_amount, 0),
        rewardPayload: (row.reward_payload && typeof row.reward_payload === 'object') ? row.reward_payload : {},
        metadata: (row.metadata && typeof row.metadata === 'object') ? row.metadata : {},
        createdAt: row.created_at || null
      }))
    });
  } catch (err) {
    console.error('Error en GET /project-commerce/:slug/purchases/pending:', err);
    return res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/project-commerce/:slug/purchases/claim', async (req, res) => {
  const userId = getAuthenticatedOceanPayUserId(req);
  if (!userId) return res.status(401).json({ error: 'Token invalido' });
  const projectSlug = normalizeCommerceProjectSlug(req.params.slug);
  if (!projectSlug) return res.status(400).json({ error: 'slug requerido' });
  const requestedIds = Array.isArray(req.body?.purchase_ids)
    ? req.body.purchase_ids.map((v) => Number(v)).filter((n) => Number.isFinite(n) && n > 0)
    : [];

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const params = [userId, projectSlug];
    let idFilterSql = '';
    if (requestedIds.length > 0) {
      params.push(requestedIds);
      idFilterSql = ` AND id = ANY($${params.length}::int[])`;
    }

    const { rows } = await client.query(
      `SELECT id, project_slug, offer_code, surface, currency, paid_amount, reward_payload, metadata, created_at
       FROM ows_project_offer_purchases
       WHERE user_id = $1
         AND project_slug = $2
         AND status = 'completed'
         AND claimed_by_project = FALSE
         ${idFilterSql}
       ORDER BY created_at ASC, id ASC
       FOR UPDATE`,
      params
    );

    const ids = rows.map((r) => Number(r.id || 0)).filter((n) => n > 0);
    if (ids.length > 0) {
      await client.query(
        `UPDATE ows_project_offer_purchases
         SET claimed_by_project = TRUE, claimed_at = NOW()
         WHERE id = ANY($1::int[])`,
        [ids]
      );
    }

    await client.query('COMMIT');
    return res.json({
      success: true,
      claimed: rows.map((row) => ({
        id: Number(row.id || 0),
        projectSlug: String(row.project_slug || ''),
        offerCode: String(row.offer_code || ''),
        surface: String(row.surface || ''),
        currency: String(row.currency || ''),
        paidAmount: toOfferPrice(row.paid_amount, 0),
        rewardPayload: (row.reward_payload && typeof row.reward_payload === 'object') ? row.reward_payload : {},
        metadata: (row.metadata && typeof row.metadata === 'object') ? row.metadata : {},
        createdAt: row.created_at || null
      }))
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error en POST /project-commerce/:slug/purchases/claim:', err);
    return res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

// OWS Store catalog (fuente principal para launcher)
app.get('/ows-store/projects', async (req, res) => {
  const statusFilter = String(req.query.status || '').trim().toLowerCase();
  const includeUnavailable = normalizeNewsBoolean(req.query.include_unavailable, true);
  try {
    const values = [];
    const where = [];
    if (statusFilter) {
      values.push(statusFilter);
      where.push(`LOWER(status) = $${values.length}`);
    } else if (!includeUnavailable) {
      values.push('unavailable');
      where.push(`LOWER(status) <> $${values.length}`);
    }

    const sql = `
      SELECT *
      FROM ows_projects
      ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
      ORDER BY
        CASE LOWER(status)
          WHEN 'launched' THEN 0
          WHEN 'coming_soon' THEN 1
          ELSE 2
        END,
        COALESCE(release_date, last_update, created_at) DESC,
        name ASC
    `;
    const { rows } = await pool.query(sql, values);

    const canonicalSlugFromProject = (project) => {
      const slug = String(project?.slug || '').toLowerCase().trim();
      const name = String(project?.name || '').toLowerCase().trim();
      if (slug === 'ocean-pay' || slug === 'oceanpay' || name === 'ocean pay') return 'oceanpay';
      if (slug === 'floret-shop' || slug === 'floretshop' || name === 'floret shop') return 'floretshop';
      if (slug === 'savage-space-animals' || slug === 'savagespaceanimals' || slug === 'ssa' || name === 'savage space animals') return 'savagespaceanimals';
      if (slug === 'wild-transfer' || slug === 'wildtransfer' || name === 'wildtransfer' || name === 'wild transfer') return 'wildtransfer';
      if (slug === 'velocitysurge' || slug === 'velocity-surge' || name === 'velocity surge') return 'velocity-surge';
      if (slug === 'wildx' || slug === 'wild-wave' || slug === 'wildwave' || name === 'wildwave' || name === 'wild wave') return 'wildwave';
      if (slug === 'wildweapon' || slug === 'wildweapon-mayhem' || name === 'wildweapon mayhem') return 'wildweapon-mayhem';
      if (slug === 'owsstore' || slug === 'ows-store' || name === 'ows store') return 'ows-store';
      return slug || String(project?.slug || '').trim();
    };

    const projectScore = (project) => {
      const url = String(project?.url || '').toLowerCase();
      const metadata = (project?.metadata && typeof project.metadata === 'object') ? project.metadata : {};
      const repo = String(metadata?.repo || '').toLowerCase();
      const version = String(project?.version || '').trim().toLowerCase();
      const hasGithubReleaseUrl = url.includes('github.com/oceanandwild/') && url.includes('/releases');
      const hasRepo = repo.startsWith('oceanandwild/');
      const hasInstallerUrl = Boolean(String(project?.installer_url || '').trim());
      const launched = String(project?.status || '').toLowerCase() === 'launched';
      const nonPlaceholderVersion = version && version !== '0.0.0';

      let score = 0;
      if (hasGithubReleaseUrl) score += 100;
      if (hasRepo) score += 40;
      if (hasInstallerUrl) score += 10;
      if (launched) score += 5;
      if (nonPlaceholderVersion) score += 5;
      return score;
    };

    const byCanonical = new Map();
    for (const row of rows) {
      const metadata = (row.metadata && typeof row.metadata === 'object') ? row.metadata : {};
      const merged = { ...row, ...metadata, metadata };
      if (!merged.platforms && Array.isArray(metadata.platforms)) merged.platforms = metadata.platforms;
      if (!merged.platform && Array.isArray(merged.platforms) && merged.platforms.length === 1) merged.platform = merged.platforms[0];

      const canonical = canonicalSlugFromProject(merged);
      merged.slug = canonical || merged.slug;

      const current = byCanonical.get(canonical);
      if (!current) {
        byCanonical.set(canonical, merged);
        continue;
      }

      const currentScore = projectScore(current);
      const candidateScore = projectScore(merged);
      if (candidateScore > currentScore) {
        byCanonical.set(canonical, merged);
        continue;
      }
      if (candidateScore === currentScore) {
        const currentTs = Date.parse(current?.last_update || current?.created_at || '') || 0;
        const candidateTs = Date.parse(merged?.last_update || merged?.created_at || '') || 0;
        if (candidateTs >= currentTs) byCanonical.set(canonical, merged);
      }
    }

    const list = [...byCanonical.values()].sort((a, b) => {
      const sa = String(a?.name || '');
      const sb = String(b?.name || '');
      return sa.localeCompare(sb);
    });

    const RELEASE_PROBE_TTL_MS = 5 * 60 * 1000;
    if (!globalThis.__owsProjectReleaseProbeCache) globalThis.__owsProjectReleaseProbeCache = new Map();
    const releaseProbeCache = globalThis.__owsProjectReleaseProbeCache;

    const parseRepoFromProject = (project) => {
      const metadata = (project?.metadata && typeof project.metadata === 'object') ? project.metadata : {};
      const rawRepo = String(project?.repo || metadata?.repo || '').trim();
      const fromRepo = rawRepo.match(/^([\w.-]+)\/([\w.-]+)$/i);
      if (fromRepo) {
        return { owner: fromRepo[1], repo: fromRepo[2], full: `${fromRepo[1]}/${fromRepo[2]}` };
      }

      const urlCandidates = [
        String(project?.url || ''),
        String(project?.installer_url || '')
      ];
      for (const candidate of urlCandidates) {
        const m = candidate.match(/github\.com\/([\w.-]+)\/([\w.-]+)/i);
        if (m) return { owner: m[1], repo: m[2], full: `${m[1]}/${m[2]}` };
      }
      return null;
    };

    const waitingMessage = 'Esperando a Ocean and Wild Studios...';
    const persistedSlugs = new Set();

    const ensureComingSoonState = (project) => {
      const metadata = (project?.metadata && typeof project.metadata === 'object') ? project.metadata : {};
      project.status = 'coming_soon';
      project.pending_release = true;
      project.release_warning = waitingMessage;
      project.metadata = {
        ...metadata,
        pending_release: true
      };
      project.repo = project.repo || project.metadata.repo || null;
      if (!project.platforms && Array.isArray(project.metadata.platforms)) project.platforms = project.metadata.platforms;
      if (!project.platform && Array.isArray(project.platforms) && project.platforms.length === 1) project.platform = project.platforms[0];
      return project;
    };

    const promoteFromRelease = async (project, repoInfo, releasePayload) => {
      const releaseUrl = `https://github.com/${repoInfo.owner}/${repoInfo.repo}/releases/latest`;
      const installerUrl = pickInstallerAssetUrlFromRelease(releasePayload) || releaseUrl;
      const metadata = (project?.metadata && typeof project.metadata === 'object') ? project.metadata : {};
      const mergedMetadata = {
        ...metadata,
        repo: `${repoInfo.owner}/${repoInfo.repo}`,
        pending_release: false,
        install_type: metadata.install_type || 'external',
        platforms: Array.isArray(metadata.platforms) && metadata.platforms.length ? metadata.platforms : ['windows']
      };

      project.status = 'launched';
      project.pending_release = false;
      project.release_warning = '';
      project.release_date = null;
      project.url = releaseUrl;
      project.installer_url = installerUrl;
      project.metadata = mergedMetadata;
      project.repo = mergedMetadata.repo;
      project.platforms = mergedMetadata.platforms;
      if (!project.platform && Array.isArray(project.platforms) && project.platforms.length === 1) project.platform = project.platforms[0];

      const slug = String(project?.slug || '').trim().toLowerCase();
      if (!slug || persistedSlugs.has(slug)) return project;
      persistedSlugs.add(slug);

      try {
        await pool.query(
          `UPDATE ows_projects
              SET status = 'launched',
                  release_date = NULL,
                  url = COALESCE(NULLIF(url, ''), $2),
                  installer_url = COALESCE(NULLIF(installer_url, ''), $3),
                  metadata = COALESCE(metadata, '{}'::jsonb) || $4::jsonb,
                  last_update = NOW()
            WHERE slug = $1
              AND LOWER(status) = 'coming_soon'`,
          [slug, releaseUrl, installerUrl, JSON.stringify(mergedMetadata)]
        );
      } catch (persistErr) {
        console.warn(`[ows-store/projects] No se pudo persistir auto-promocion para ${slug}:`, persistErr?.message || persistErr);
      }

      return project;
    };

    await Promise.all(list.map(async (project) => {
      const currentStatus = String(project?.status || '').trim().toLowerCase();
      if (currentStatus !== 'coming_soon') return;

      const repoInfo = parseRepoFromProject(project);
      if (!repoInfo) {
        ensureComingSoonState(project);
        return;
      }

      const cacheKey = String(repoInfo.full || '').toLowerCase();
      const now = Date.now();
      const cached = releaseProbeCache.get(cacheKey);
      if (cached && (now - Number(cached.ts || 0)) < RELEASE_PROBE_TTL_MS) {
        if (cached.hasRelease) {
          await promoteFromRelease(project, repoInfo, cached.payload || null);
        } else {
          ensureComingSoonState(project);
        }
        return;
      }

      const releasePayload = await fetchGithubLatestReleaseLite(repoInfo.owner, repoInfo.repo);
      const hasRelease = Boolean(
        releasePayload &&
        (String(releasePayload.tag_name || '').trim() || String(releasePayload.name || '').trim() || String(releasePayload.html_url || '').trim())
      );

      releaseProbeCache.set(cacheKey, {
        ts: now,
        hasRelease,
        payload: hasRelease ? releasePayload : null
      });

      if (hasRelease) {
        await promoteFromRelease(project, repoInfo, releasePayload);
      } else {
        ensureComingSoonState(project);
      }
    }));

    return res.json(list);
  } catch (err) {
    console.error('Error en GET /ows-store/projects:', err);
    return res.status(500).json({ error: 'Error interno' });
  }
});

// Ocean AI helper: resumen de OWS Store (latest releases + catalogo segmentado)
app.get('/ocean-ai/ows-store/context', async (_req, res) => {
  try {
    const [release, androidRes, projectsRes] = await Promise.all([
      fetchGithubLatestReleaseLite('OceanandWild', 'owsdatabase'),
      pool.query(
        `SELECT *
         FROM ows_android_releases
         WHERE project_slug = 'ows-store'
           AND status = 'published'
         ORDER BY version_code DESC, published_at DESC, id DESC
         LIMIT 1`
      ),
      pool.query(
        `SELECT *
         FROM ows_projects
         ORDER BY
           CASE LOWER(status)
             WHEN 'launched' THEN 0
             WHEN 'coming_soon' THEN 1
             ELSE 2
           END,
           COALESCE(release_date, last_update, created_at) DESC,
           name ASC`
      )
    ]);

    const latestAndroid = androidRes.rows[0] || null;
    const windowsInstallerUrl = pickInstallerAssetUrlFromRelease(release);
    const fallbackWindowsUrl = String(release?.html_url || 'https://github.com/OceanandWild/owsdatabase/releases/latest');
    const windowsDownloadUrl = windowsInstallerUrl || fallbackWindowsUrl;
    const androidDownloadUrl = latestAndroid?.apk_url
      ? String(latestAndroid.apk_url)
      : 'https://owsdatabase.onrender.com/ows-store/android/releases/ows-store/latest/download';

    const canonicalProjectSlugForOceanAi = (value) => {
      const slug = String(value || '').trim().toLowerCase();
      if (!slug) return '';
      if (slug === 'ocean-pay' || slug === 'oceanpay') return 'oceanpay';
      if (slug === 'floret-shop' || slug === 'floretshop') return 'floretshop';
      if (slug === 'savage-space-animals' || slug === 'savagespaceanimals' || slug === 'ssa') return 'savagespaceanimals';
      if (slug === 'wild-transfer' || slug === 'wildtransfer') return 'wildtransfer';
      if (slug === 'velocitysurge' || slug === 'velocity-surge') return 'velocity-surge';
      if (slug === 'wildx' || slug === 'wild-wave' || slug === 'wildwave') return 'wildwave';
      if (slug === 'wildweapon' || slug === 'wildweapon-mayhem') return 'wildweapon-mayhem';
      if (slug === 'owsstore' || slug === 'ows-store') return 'ows-store';
      return slug;
    };

    const normalizeProject = (row) => {
      const metadata = (row?.metadata && typeof row.metadata === 'object') ? row.metadata : {};
      const merged = { ...row, ...metadata, metadata };
      const rawSlug = String(merged.slug || '').trim();
      const slug = canonicalProjectSlugForOceanAi(rawSlug || merged?.name || '');
      const name = String(merged.name || '').trim();
      const platformRaw = merged.platforms || merged.platform || metadata.platforms || metadata.platform || '';
      const platforms = Array.isArray(platformRaw)
        ? platformRaw
        : String(platformRaw || '')
          .split(',')
          .map((x) => String(x || '').trim())
          .filter(Boolean);
      return {
        slug,
        name,
        status: String(merged.status || '').trim().toLowerCase(),
        version: String(merged.version || '').trim(),
        releaseDate: merged.release_date || merged.releaseDate || null,
        description: String(merged.description || '').trim(),
        platforms,
        pendingRelease: Boolean(merged.pending_release || metadata.pending_release),
        placeholder: Boolean(merged.placeholder || metadata.placeholder || String(merged.version || '').trim() === '0.0.0')
      };
    };

    const normalizedProjects = (projectsRes.rows || []).map(normalizeProject).filter((p) => p.slug && p.name);
    const bySlug = new Map();
    for (const item of normalizedProjects) {
      if (!bySlug.has(item.slug)) bySlug.set(item.slug, item);
    }
    const allProjects = [...bySlug.values()];
    const filtered = allProjects.filter((p) => p.slug !== 'ows-store');
    const forcedUpcoming = new Set(['naturepedia', 'dinobox']);
    const upcoming = filtered.filter((p) => forcedUpcoming.has(String(p.slug || '').trim().toLowerCase()));
    const available = filtered.filter((p) => !upcoming.some((u) => u.slug === p.slug));

    return res.json({
      success: true,
      store: {
        repo: 'OceanandWild/owsdatabase',
        windows: {
          version: String(release?.tag_name || release?.name || '').trim() || null,
          releaseUrl: String(release?.html_url || '').trim() || null,
          downloadUrl: windowsDownloadUrl
        },
        android: latestAndroid ? {
          versionName: latestAndroid.version_name || null,
          versionCode: Number(latestAndroid.version_code || 0),
          downloadUrl: androidDownloadUrl,
          publishedAt: latestAndroid.published_at || null
        } : {
          versionName: null,
          versionCode: 0,
          downloadUrl: androidDownloadUrl,
          publishedAt: null
        }
      },
      projects: {
        available,
        upcoming
      },
      notes: {
        installProjectsInsideStore: true
      }
    });
  } catch (err) {
    console.error('Error en GET /ocean-ai/ows-store/context:', err);
    return res.status(500).json({ error: 'Error interno al preparar contexto OWS Store' });
  }
});

app.post('/ows-store/push/register', async (req, res) => {
  const payload = req.body || {};
  const deviceId = String(payload.device_id || payload.deviceId || '').trim();
  if (!deviceId) return res.status(400).json({ error: 'device_id requerido' });

  const platform = normalizeOwsPushPlatform(payload.platform || payload.device_platform || 'web');
  const provider = normalizeOwsPushProvider(payload.provider || payload.push_provider || 'local');
  const pushToken = String(payload.push_token || payload.pushToken || '').trim() || null;
  const endpoint = String(payload.endpoint || '').trim() || null;
  const keys = (payload.keys && typeof payload.keys === 'object') ? payload.keys : {};
  const p256dh = String(payload.p256dh || keys.p256dh || '').trim() || null;
  const auth = String(payload.auth || keys.auth || '').trim() || null;
  const appVersion = String(payload.app_version || payload.appVersion || '').trim() || null;
  const metadata = (payload.metadata && typeof payload.metadata === 'object') ? payload.metadata : {};
  const token = parseStudioAuthToken(req);
  const decoded = decodeStudioTokenOrNull(token);
  const userId = Number(decoded?.id || decoded?.uid || decoded?.sub || 0) || null;

  try {
    const { rows } = await pool.query(
      `INSERT INTO ows_store_push_devices (
         device_id, user_id, platform, provider, push_token, endpoint, p256dh, auth, app_version, metadata, is_active, updated_at, last_seen_at
       )
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,TRUE,NOW(),NOW())
       ON CONFLICT (device_id, platform) DO UPDATE SET
         user_id = COALESCE(EXCLUDED.user_id, ows_store_push_devices.user_id),
         provider = EXCLUDED.provider,
         push_token = COALESCE(EXCLUDED.push_token, ows_store_push_devices.push_token),
         endpoint = COALESCE(EXCLUDED.endpoint, ows_store_push_devices.endpoint),
         p256dh = COALESCE(EXCLUDED.p256dh, ows_store_push_devices.p256dh),
         auth = COALESCE(EXCLUDED.auth, ows_store_push_devices.auth),
         app_version = COALESCE(EXCLUDED.app_version, ows_store_push_devices.app_version),
         metadata = COALESCE(ows_store_push_devices.metadata, '{}'::jsonb) || EXCLUDED.metadata,
         is_active = TRUE,
         updated_at = NOW(),
         last_seen_at = NOW()
       RETURNING id, device_id, platform, provider, is_active, last_seen_at`,
      [deviceId, userId, platform, provider, pushToken, endpoint, p256dh, auth, appVersion, metadata]
    );
    return res.json({ success: true, subscription: rows[0] || null });
  } catch (err) {
    console.error('Error en POST /ows-store/push/register:', err);
    return res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/ows-store/push/unregister', async (req, res) => {
  const payload = req.body || {};
  const deviceId = String(payload.device_id || payload.deviceId || '').trim();
  if (!deviceId) return res.status(400).json({ error: 'device_id requerido' });
  const platform = normalizeOwsPushPlatform(payload.platform || payload.device_platform || 'web');
  try {
    const { rowCount } = await pool.query(
      `UPDATE ows_store_push_devices
       SET is_active = FALSE, updated_at = NOW()
       WHERE device_id = $1
         AND ($2 = 'all' OR platform = $2)`,
      [deviceId, platform]
    );
    return res.json({ success: true, updated: Number(rowCount || 0) });
  } catch (err) {
    console.error('Error en POST /ows-store/push/unregister:', err);
    return res.status(500).json({ error: 'Error interno' });
  }
});

app.get('/ows-store/push/inbox', async (req, res) => {
  const deviceId = String(req.query.device_id || req.query.deviceId || '').trim();
  if (!deviceId) return res.status(400).json({ error: 'device_id requerido' });
  const platform = normalizeOwsPushPlatform(req.query.platform || 'web');
  const limit = Math.max(1, Math.min(50, normalizeNewsNumber(req.query.limit, 20)));
  try {
    await pool.query(
      `UPDATE ows_store_push_devices
       SET last_seen_at = NOW(), updated_at = NOW(), is_active = TRUE
       WHERE device_id = $1
         AND ($2 = 'all' OR platform = $2)`,
      [deviceId, platform]
    ).catch(() => {});

    const { rows } = await pool.query(
      `SELECT *
       FROM ows_store_push_notifications
       WHERE device_id = $1
         AND (platform = 'all' OR $2 = 'all' OR platform = $2)
         AND delivered_at IS NULL
       ORDER BY created_at DESC
       LIMIT $3`,
      [deviceId, platform, limit]
    );
    const ids = rows.map((row) => Number(row.id || 0)).filter((id) => id > 0);
    if (ids.length) {
      await pool.query(
        `UPDATE ows_store_push_notifications
         SET delivered_at = NOW()
         WHERE id = ANY($1::int[])`,
        [ids]
      );
    }
    return res.json({
      success: true,
      notifications: rows.map((row) => ({
        id: Number(row.id || 0),
        platform: String(row.platform || ''),
        project_slug: String(row.project_slug || ''),
        version: String(row.version || ''),
        title: String(row.title || ''),
        body: String(row.body || ''),
        payload: (row.payload && typeof row.payload === 'object') ? row.payload : {},
        dedupe_key: String(row.dedupe_key || ''),
        created_at: row.created_at || null
      }))
    });
  } catch (err) {
    console.error('Error en GET /ows-store/push/inbox:', err);
    return res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/ows-store/push/inbox/:id/ack', async (req, res) => {
  const id = Number(req.params.id || 0);
  const deviceId = String(req.body?.device_id || req.body?.deviceId || '').trim();
  if (!Number.isFinite(id) || id <= 0) return res.status(400).json({ error: 'id invalido' });
  if (!deviceId) return res.status(400).json({ error: 'device_id requerido' });
  try {
    const { rowCount } = await pool.query(
      `UPDATE ows_store_push_notifications
       SET acknowledged_at = NOW()
       WHERE id = $1
         AND device_id = $2`,
      [id, deviceId]
    );
    return res.json({ success: true, updated: Number(rowCount || 0) });
  } catch (err) {
    console.error('Error en POST /ows-store/push/inbox/:id/ack:', err);
    return res.status(500).json({ error: 'Error interno' });
  }
});

// OWS News feed (array simple para compatibilidad con launcher)
app.get('/ows-news/updates', async (req, res) => {
  const includeInactive = normalizeNewsBoolean(req.query.include_inactive, false);
  const limit = Math.max(1, Math.min(300, normalizeNewsNumber(req.query.limit, 120)));
  try {
    const { rows } = await pool.query(
      `SELECT *
       FROM ows_store_timeline
       ORDER BY COALESCE(priority, 0) DESC, published_at DESC, created_at DESC
       LIMIT $1`,
      [limit * 2]
    );

    let list = rows.map(normalizeOwsNewsRow);
    if (!includeInactive) list = list.filter((x) => x.is_active !== false && x.isActive !== false);
    list = list.slice(0, limit);
    return res.json(list);
  } catch (err) {
    console.error('Error en GET /ows-news/updates:', err);
    return res.status(500).json({ error: 'Error interno' });
  }
});

// OWS News upsert/create via API admin token
app.post('/ows-news/updates', async (req, res) => {
  if (!requireOwsStoreAdmin(req, res)) return;
  const payload = req.body || {};
  const title = String(payload.title || '').trim();
  if (!title) return res.status(400).json({ error: 'title requerido' });

  const projectNames = toNewsArray(payload.project_names || payload.projectNames || []);
  const projectSlugs = toNewsArray(payload.project_slugs || payload.projectSlugs || []);
  const changes = toNewsArray(payload.changes || []);
  const description = String(payload.description || '').trim() || null;
  const entryType = normalizeTimelineEntryType(payload.entry_type || payload.entryType || payload.kind || 'changelog');
  const platforms = toNewsArray(payload.platforms || []).map((x) => String(x || '').toLowerCase()).filter(Boolean);
  const model2dKey = String(payload.model_2d_key || payload.model2dKey || '').trim() || null;
  const model2dPayload = (payload.model_2d_payload && typeof payload.model_2d_payload === 'object')
    ? payload.model_2d_payload
    : ((payload.model2d && typeof payload.model2d === 'object') ? payload.model2d : {});
  const bannerMeta = (payload.banner_meta && typeof payload.banner_meta === 'object')
    ? payload.banner_meta
    : ((payload.bannerMeta && typeof payload.bannerMeta === 'object') ? payload.bannerMeta : {});
  const isActive = normalizeNewsBoolean(payload.is_active ?? payload.isActive, true);
  const priority = normalizeNewsNumber(payload.priority, 0);
  const updateDate = payload.update_date || payload.updateDate || null;
  const eventStart = payload.event_start || payload.eventStart || null;
  const eventEnd = payload.event_end || payload.eventEnd || null;

  try {
    const syncKey = String(bannerMeta?.sync_key || '').trim();
    let row = null;
    if (syncKey) {
      row = await upsertOwsNewsEntryBySyncKey({
        syncKey,
        projectNames,
        projectSlugs,
        title,
        description,
        changes,
        updateDate,
        entryType,
        platforms: platforms.length ? platforms : ['windows'],
        model2dKey,
        model2dPayload,
        bannerMeta,
        isActive,
        priority,
        eventStart,
        eventEnd
      });
    } else {
      const refs = normalizeTimelineProjectRefs(projectNames, projectSlugs);
      const lines = normalizeTimelineLines(changes);
      const details = {
        changes: lines,
        source: 'ows_news_updates_api'
      };
      const { rows } = await pool.query(
        `INSERT INTO ows_store_timeline (
           project_slugs, project_names, title, description, content_lines, details, published_at, kind, platforms,
           model_2d_key, model_2d_payload, visual_meta, is_active, priority, starts_at, ends_at
         )
         VALUES ($1,$2,$3,$4,$5,$6,COALESCE($7, NOW()),$8,$9,$10,$11,$12,$13,$14,$15,$16)
         RETURNING *`,
        [
          refs.projectSlugs,
          refs.projectNames,
          title,
          description,
          lines,
          details,
          updateDate,
          entryType,
          platforms,
          model2dKey,
          model2dPayload,
          bannerMeta,
          isActive,
          priority,
          eventStart,
          eventEnd
        ]
      );
      row = rows[0] || null;
    }

    return res.json({ success: true, update: normalizeOwsNewsRow(row) });
  } catch (err) {
    console.error('Error en POST /ows-news/updates:', err);
    return res.status(500).json({ error: 'Error interno' });
  }
});

// Update parcial de OWS News por id (admin)
app.patch('/ows-news/updates/:id', async (req, res) => {
  if (!requireOwsStoreAdmin(req, res)) return;
  const id = String(req.params.id || '').trim();
  if (!id) return res.status(400).json({ error: 'id requerido' });

  const payload = req.body || {};
  const updates = [];
  const values = [];
  const pushUpdate = (field, value) => {
    updates.push(`${field} = $${values.length + 1}`);
    values.push(value);
  };

  if (payload.title !== undefined) {
    const title = String(payload.title || '').trim();
    if (!title) return res.status(400).json({ error: 'title requerido' });
    pushUpdate('title', title);
  }

  if (payload.project_names !== undefined || payload.projectNames !== undefined) {
    const projectNames = toNewsArray(payload.project_names || payload.projectNames || []);
    const refs = normalizeTimelineProjectRefs(projectNames, []);
    pushUpdate('project_names', projectNames);
    pushUpdate('project_slugs', refs.projectSlugs);
  }

  if (payload.project_slugs !== undefined || payload.projectSlugs !== undefined) {
    const projectSlugs = toNewsArray(payload.project_slugs || payload.projectSlugs || [])
      .map((x) => normalizeProjectSlug(x))
      .filter(Boolean);
    pushUpdate('project_slugs', projectSlugs);
  }

  if (payload.description !== undefined) {
    const description = String(payload.description || '').trim() || null;
    pushUpdate('description', description);
  }

  if (payload.changes !== undefined) {
    const changes = toNewsArray(payload.changes || []);
    pushUpdate('content_lines', changes);
    pushUpdate('details', { changes, source: 'ows_news_updates_api_patch' });
  }

  if (payload.entry_type !== undefined || payload.entryType !== undefined || payload.kind !== undefined) {
    const entryType = normalizeTimelineEntryType(payload.entry_type || payload.entryType || payload.kind || 'changelog');
    pushUpdate('kind', entryType);
  }

  if (payload.platforms !== undefined) {
    const platforms = toNewsArray(payload.platforms || [])
      .map((x) => String(x || '').toLowerCase())
      .filter(Boolean);
    pushUpdate('platforms', platforms);
  }

  if (payload.model_2d_key !== undefined || payload.model2dKey !== undefined) {
    const model2dKey = String(payload.model_2d_key || payload.model2dKey || '').trim() || null;
    pushUpdate('model_2d_key', model2dKey);
  }

  if (payload.model_2d_payload !== undefined || payload.model2d !== undefined) {
    const model2dPayload = (payload.model_2d_payload && typeof payload.model_2d_payload === 'object')
      ? payload.model_2d_payload
      : ((payload.model2d && typeof payload.model2d === 'object') ? payload.model2d : {});
    pushUpdate('model_2d_payload', model2dPayload);
  }

  if (payload.banner_meta !== undefined || payload.bannerMeta !== undefined) {
    const bannerMeta = (payload.banner_meta && typeof payload.banner_meta === 'object')
      ? payload.banner_meta
      : ((payload.bannerMeta && typeof payload.bannerMeta === 'object') ? payload.bannerMeta : {});
    pushUpdate('visual_meta', bannerMeta);
  }

  if (payload.is_active !== undefined || payload.isActive !== undefined) {
    const isActive = normalizeNewsBoolean(payload.is_active ?? payload.isActive, true);
    pushUpdate('is_active', isActive);
  }

  if (payload.priority !== undefined) {
    const priority = normalizeNewsNumber(payload.priority, 0);
    pushUpdate('priority', priority);
  }

  if (payload.update_date !== undefined || payload.updateDate !== undefined) {
    const updateDate = payload.update_date || payload.updateDate || null;
    pushUpdate('published_at', updateDate);
  }

  if (payload.event_start !== undefined || payload.eventStart !== undefined) {
    const eventStart = payload.event_start || payload.eventStart || null;
    pushUpdate('starts_at', eventStart);
  }

  if (payload.event_end !== undefined || payload.eventEnd !== undefined) {
    const eventEnd = payload.event_end || payload.eventEnd || null;
    pushUpdate('ends_at', eventEnd);
  }

  if (!updates.length) {
    return res.status(400).json({ error: 'Sin cambios para aplicar' });
  }

  try {
    const { rows } = await pool.query(
      `UPDATE ows_store_timeline
       SET ${updates.join(', ')}, updated_at = NOW()
       WHERE id = $${values.length + 1}
       RETURNING *`,
      [...values, id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Update no encontrado' });
    return res.json({ success: true, update: normalizeOwsNewsRow(rows[0]) });
  } catch (err) {
    console.error('Error en PATCH /ows-news/updates/:id:', err);
    return res.status(500).json({ error: 'Error interno' });
  }
});

// Proxy GitHub para evitar limites/CORS en cliente
app.get('/ows-store/github/repos/:owner/:repo', githubProxyHandler);
app.get('/ows-store/github/repos/:owner/:repo/*', githubProxyHandler);

// Perfil Ocean Pay usado por apps (cards + balances unificados)
app.get('/ocean-pay/me', async (req, res) => {
  const token = parseStudioAuthToken(req);
  const decoded = decodeStudioTokenOrNull(token);
  if (!decoded) return res.status(401).json({ error: 'Token invalido' });

  const userId = Number(decoded.id || decoded.uid || decoded.sub || 0);
  if (!userId) return res.status(401).json({ error: 'Usuario invalido' });

  try {
    const userRes = await pool.query(
      `SELECT id, username, unique_id, created_at, aquabux, ecoxionums, appbux
       FROM ocean_pay_users
       WHERE id = $1
       LIMIT 1`,
      [userId]
    );
    if (!userRes.rows.length) return res.status(404).json({ error: 'Usuario no encontrado' });
    const user = userRes.rows[0];

    const cardsRes = await pool.query(
      `SELECT
         c.id, c.user_id, c.card_number, c.cvv, c.expiry_date, c.is_primary, c.is_active, c.card_name, c.balances,
         COALESCE(
           jsonb_object_agg(b.currency_type, b.amount) FILTER (WHERE b.currency_type IS NOT NULL),
           '{}'::jsonb
         ) AS balance_map
       FROM ocean_pay_cards c
       LEFT JOIN ocean_pay_card_balances b ON b.card_id = c.id
       WHERE c.user_id = $1 AND c.is_active = true
       GROUP BY c.id
       ORDER BY c.is_primary DESC, c.id ASC`,
      [userId]
    );

    const walletBalances = await getAllUnifiedBalances(pool, userId);

    const cards = cardsRes.rows.map((row) => {
      const tableMap = (row.balance_map && typeof row.balance_map === 'object') ? row.balance_map : {};
      const jsonMap = (row.balances && typeof row.balances === 'object') ? row.balances : {};
      // La wallet unificada manda sobre fuentes legacy para evitar lecturas desfasadas.
      const balances = { ...tableMap, ...jsonMap, ...walletBalances };
      return {
        ...row,
        balances
      };
    });

    const primaryCard = cards.find((c) => c.is_primary) || cards[0] || null;
    const primaryBalances = primaryCard?.balances || {};

    const mergedUserBalances = {
      ...primaryBalances,
      ...walletBalances
    };

    return res.json({
      success: true,
      id: user.id,
      uid: user.id,
      username: user.username,
      unique_id: user.unique_id,
      created_at: user.created_at,
      aquabux: toFiniteNumber(mergedUserBalances.aquabux, 0),
      ecoxionums: toFiniteNumber(mergedUserBalances.ecoxionums, 0),
      appbux: toFiniteNumber(mergedUserBalances.appbux, 0),
      balances: mergedUserBalances,
      cards
    });
  } catch (err) {
    console.error('Error en GET /ocean-pay/me:', err);
    return res.status(500).json({ error: 'Error interno' });
  }
});

// Ocean AI -> Ocean Pay bridge (credenciales Ocean Pay)
app.post('/ocean-ai/connect-ocean-pay', async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '').trim();
  if (!username || !password) {
    return res.status(400).json({ error: 'Usuario y contraseï¿½a requeridos' });
  }

  const client = await pool.connect();
  try {
    const user = await resolveOceanPayUserByCredentials(client, username, password);
    if (!user) {
      return res.status(401).json({ error: 'Credenciales de Ocean Pay invï¿½lidas' });
    }
    const coralBits = await getCoralBitsBalanceForUser(client, user.id);
    return res.json({
      success: true,
      connected: true,
      userId: user.id,
      username: user.username,
      coralBits
    });
  } catch (err) {
    console.error('Error en POST /ocean-ai/connect-ocean-pay:', err);
    return res.status(500).json({ error: 'Error interno al conectar Ocean Pay' });
  } finally {
    client.release();
  }
});

app.post('/ocean-ai/subscriptions/status', async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '').trim();
  if (!username || !password) {
    return res.status(400).json({ error: 'Usuario y contraseï¿½a requeridos' });
  }

  const client = await pool.connect();
  try {
    const user = await resolveOceanPayUserByCredentials(client, username, password);
    if (!user) {
      return res.status(401).json({ error: 'Credenciales de Ocean Pay invï¿½lidas' });
    }
    const sub = await getOceanAiActiveSubscription(client, user.id);
    const plan = sub ? (getOceanAiPlanByName(sub.plan_name) || null) : null;

    return res.json({
      success: true,
      userId: user.id,
      username: user.username,
      active: Boolean(sub?.isActive),
      planId: plan?.id || null,
      planName: sub?.plan_name || null,
      weeklyCost: Number(sub?.price || plan?.weeklyCost || 0),
      renewalAt: sub?.renewalAt || null,
      expiresAt: sub?.expiresAt || null,
      models: plan?.models || ['oceanFree'],
      benefits: plan?.benefits || []
    });
  } catch (err) {
    console.error('Error en POST /ocean-ai/subscriptions/status:', err);
    return res.status(500).json({ error: 'Error interno al consultar suscripciï¿½n Ocean AI' });
  } finally {
    client.release();
  }
});

app.post('/ocean-ai/subscriptions/subscribe', async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '').trim();
  const planId = String(req.body?.planId || '').trim().toLowerCase();
  const plan = OCEAN_AI_PLANS[planId];

  if (!username || !password) {
    return res.status(400).json({ error: 'Usuario y contraseï¿½a requeridos' });
  }
  if (!plan) {
    return res.status(400).json({ error: 'Plan Ocean AI invï¿½lido' });
  }

  const client = await pool.connect();
  try {
    const user = await resolveOceanPayUserByCredentials(client, username, password);
    if (!user) {
      return res.status(401).json({ error: 'Credenciales de Ocean Pay invï¿½lidas' });
    }

    await client.query('BEGIN');
    const card = await getPrimaryCardWithBalances(client, user.id);
    if (!card?.id) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Usuario sin tarjeta principal en Ocean Pay' });
    }

    const currentBal = await getUnifiedCardCurrencyBalance(client, Number(card.id), OCEAN_AI_CURRENCY, true);
    if (currentBal < plan.weeklyCost) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: `Saldo insuficiente de ${OCEAN_AI_CURRENCY.toUpperCase()}` });
    }

    const nextBalance = currentBal - plan.weeklyCost;
    await setUnifiedCardCurrencyBalance(client, {
      userId: Number(user.id),
      cardId: Number(card.id),
      currency: OCEAN_AI_CURRENCY,
      newBalance: nextBalance
    });

    const activeSub = await getOceanAiActiveSubscription(client, user.id);
    const baseDate = activeSub?.isActive && activeSub.expiresAt ? new Date(activeSub.expiresAt) : new Date();
    const renewalDate = new Date(baseDate.getTime() + (OCEAN_AI_PLAN_INTERVAL_DAYS * 24 * 60 * 60 * 1000));

    if (activeSub?.id) {
      await client.query(
        `UPDATE ocean_pay_subscriptions
            SET plan_name = $1,
                sub_name = $2,
                price = $3,
                currency = $4,
                card_id = $5,
                end_date = $6,
                interval_days = $7,
                next_payment = $6,
                status = 'active'
          WHERE id = $8`,
        [plan.name, plan.name, plan.weeklyCost, OCEAN_AI_CURRENCY, card.id, renewalDate, OCEAN_AI_PLAN_INTERVAL_DAYS, activeSub.id]
      );
    } else {
      await client.query(
        `INSERT INTO ocean_pay_subscriptions
          (user_id, card_id, project_id, sub_name, plan_name, price, currency, interval_days, end_date, next_payment, status)
         VALUES
          ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9, 'active')`,
        [user.id, card.id, OCEAN_AI_PROJECT_ID, plan.name, plan.name, plan.weeklyCost, OCEAN_AI_CURRENCY, OCEAN_AI_PLAN_INTERVAL_DAYS, renewalDate]
      );
    }

    await client.query('COMMIT');
    return res.json({
      success: true,
      active: true,
      planId: plan.id,
      planName: plan.name,
      weeklyCost: plan.weeklyCost,
      renewalAt: renewalDate.toISOString(),
      expiresAt: renewalDate.toISOString(),
      models: plan.models,
      benefits: plan.benefits,
      coralBitsBalance: nextBalance
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error en POST /ocean-ai/subscriptions/subscribe:', err);
    return res.status(500).json({ error: 'Error interno al activar plan de Ocean AI' });
  } finally {
    client.release();
  }
});

// Endpoint para Ocean AI: sincroniza saldo de Coral Bits por usuario/contraseï¿½a de Ocean Pay
app.post('/ocean-ai/coralbits/sync', async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '').trim();
  const coralBits = sanitizeCoralBits(req.body?.coralBits);
  if (!username || !password) {
    return res.status(400).json({ error: 'Usuario y contraseï¿½a requeridos' });
  }

  const client = await pool.connect();
  try {
    const user = await resolveOceanPayUserByCredentials(client, username, password);
    if (!user) {
      return res.status(401).json({ error: 'Credenciales de Ocean Pay invï¿½lidas' });
    }

    await client.query('BEGIN');
    const card = await getPrimaryCardWithBalances(client, user.id);
    if (!card?.id) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Usuario sin tarjeta principal en Ocean Pay' });
    }

    await client.query(
      `INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount)
       VALUES ($1, $2, $3)
       ON CONFLICT (card_id, currency_type)
       DO UPDATE SET amount = EXCLUDED.amount`,
      [card.id, OCEAN_AI_CURRENCY, coralBits]
    );

    await client.query(
      `UPDATE ocean_pay_cards
          SET balances = jsonb_set(
            COALESCE(balances, '{}'::jsonb),
            $2::text[],
            to_jsonb($3::numeric),
            true
          )
        WHERE id = $1`,
      [card.id, [OCEAN_AI_CURRENCY], coralBits]
    );

    await client.query('COMMIT');
    return res.json({
      success: true,
      synced: true,
      userId: user.id,
      username: user.username,
      coralBits
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error en POST /ocean-ai/coralbits/sync:', err);
    return res.status(500).json({ error: 'Error interno al sincronizar Coral Bits' });
  } finally {
    client.release();
  }
});

// Endpoint para Ocean AI: consulta saldo por usuario/contraseï¿½a de Ocean Pay
app.post('/ocean-ai/coralbits/balance', async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '').trim();
  if (!username || !password) {
    return res.status(400).json({ error: 'Usuario y contraseï¿½a requeridos' });
  }

  const client = await pool.connect();
  try {
    const user = await resolveOceanPayUserByCredentials(client, username, password);
    if (!user) {
      return res.status(401).json({ error: 'Credenciales de Ocean Pay invï¿½lidas' });
    }
    const coralBits = await getCoralBitsBalanceForUser(client, user.id);
    return res.json({
      success: true,
      userId: user.id,
      username: user.username,
      coralBits
    });
  } catch (err) {
    console.error('Error en POST /ocean-ai/coralbits/balance:', err);
    return res.status(500).json({ error: 'Error interno al consultar Coral Bits' });
  } finally {
    client.release();
  }
});

const OCEAN_PASS_PLAN = Object.freeze({
  id: 'ocean-pass-standard',
  name: 'Ocean Pass',
  durationDays: 30,
  rewardAmount: 750,
  rewardEveryHours: 24
});

const OCEAN_PASS_CURRENCY_PRICES = Object.freeze({
  tides: 199,
  aurex: 199,
  aquabux: 1200,
  ecoxionums: 900,
  wildcredits: 1400,
  wildgems: 160,
  voltbit: 180,
  appbux: 1000,
  amber: 800,
  nxb: 420,
  mayhemcoins: 2600,
  relayshards: 720
});

function getOceanPassPriceForCurrency(currency) {
  const key = String(currency || '').trim().toLowerCase();
  if (!key) return null;
  const amount = OCEAN_PASS_CURRENCY_PRICES[key];
  if (!Number.isFinite(amount)) return null;
  return { currency: key, amount };
}

const AUREX_PACKAGES = Object.freeze([
  { id: 'tides-200', title: 'Tides 200', tidesAmount: 200, priceUyu: 99, bonus: 0 },
  { id: 'tides-600', title: 'Tides 600', tidesAmount: 600, priceUyu: 249, bonus: 20 },
  { id: 'tides-1500', title: 'Tides 1500', tidesAmount: 1500, priceUyu: 499, bonus: 80 },
  { id: 'tides-3200', title: 'Tides 3200', tidesAmount: 3200, priceUyu: 899, bonus: 200 },
  { id: 'tides-5000', title: 'Tides 5000', tidesAmount: 5000, priceUyu: 1299, bonus: 380 },
  { id: 'tides-8500', title: 'Tides 8500', tidesAmount: 8500, priceUyu: 1999, bonus: 900 },
  { id: 'tides-15000', title: 'Tides 15000', tidesAmount: 15000, priceUyu: 3299, bonus: 2100 },
  { id: 'tides-30000', title: 'Tides 30000', tidesAmount: 30000, priceUyu: 5999, bonus: 5000 }
]);

function getAurexPackageById(packageId) {
  let key = String(packageId || '').trim().toLowerCase();
  if (key.startsWith('aurex-')) key = `tides-${key.slice('aurex-'.length)}`;
  return AUREX_PACKAGES.find((pkg) => pkg.id === key) || null;
}

async function ensureOceanPayGlobalGoalTables(client) {
  await client.query(`
    CREATE TABLE IF NOT EXISTS ocean_pay_global_goals (
      id SERIAL PRIMARY KEY,
      slug TEXT NOT NULL UNIQUE,
      title TEXT NOT NULL,
      description TEXT,
      goal_type TEXT NOT NULL CHECK (goal_type IN ('spend', 'earn')),
      target_amount NUMERIC(20,2) NOT NULL,
      reward_currency TEXT NOT NULL DEFAULT 'tides',
      reward_amount NUMERIC(20,2) NOT NULL,
      eligible_currencies TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'active',
      starts_at TIMESTAMP NOT NULL DEFAULT NOW(),
      ends_at TIMESTAMP NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
  `);

  await client.query(`
    CREATE TABLE IF NOT EXISTS ocean_pay_global_goal_claims (
      goal_id INTEGER NOT NULL REFERENCES ocean_pay_global_goals(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES ocean_pay_users(id) ON DELETE CASCADE,
      claimed_at TIMESTAMP NOT NULL DEFAULT NOW(),
      PRIMARY KEY (goal_id, user_id)
    );
  `);
}

function normalizeGoalCurrencies(input) {
  if (Array.isArray(input)) {
    return input.map((v) => String(v || '').trim().toLowerCase()).filter(Boolean);
  }
  const raw = String(input || '').trim();
  if (!raw) return [];
  return raw.split(',').map((v) => v.trim().toLowerCase()).filter(Boolean);
}

function parseGoalCurrencies(raw) {
  return normalizeGoalCurrencies(String(raw || '').split(','));
}

function expandGoalCurrencyAliases(currencies) {
  const aliasMap = {
    aquabux: ['aquabux', 'bux', 'ab'],
    wildgems: ['wildgems', 'wg'],
    wildcredits: ['wildcredits', 'wc'],
    ecoxionums: ['ecoxionums', 'ex'],
    ecobits: ['ecobits', 'ecorebits', 'ecb'],
    appbux: ['appbux', 'abx'],
    nxb: ['nxb'],
    voltbit: ['voltbit', 'vb'],
    amber: ['amber'],
    relayshards: ['relayshards'],
    tides: ['tides', 'aurex']
  };
  const out = new Set();
  for (const raw of normalizeGoalCurrencies(currencies)) {
    const key = String(raw || '').trim().toLowerCase();
    const aliases = aliasMap[key] || [key];
    for (const a of aliases) out.add(a);
  }
  return [...out];
}

async function getActiveGlobalGoal(client) {
  await ensureOceanPayGlobalGoalTables(client);
  const { rows } = await client.query(
    `SELECT *
       FROM ocean_pay_global_goals
      WHERE status = 'active'
        AND starts_at <= NOW()
        AND (ends_at IS NULL OR ends_at >= NOW())
      ORDER BY updated_at DESC, id DESC
      LIMIT 1`
  );
  return rows[0] || null;
}

async function computeGlobalGoalProgress(client, goal) {
  const eligibleCurrencies = expandGoalCurrencyAliases(parseGoalCurrencies(goal?.eligible_currencies));
  if (!eligibleCurrencies.length) return 0;
  const goalType = String(goal?.goal_type || 'spend').toLowerCase();
  const txPredicate = goalType === 'earn'
    ? `(COALESCE(t.monto, 0) > 0)`
    : `(COALESCE(t.monto, 0) < 0)`;

  const { rows } = await client.query(
    `SELECT COALESCE(SUM(ABS(COALESCE(t.monto, 0))), 0)::numeric AS total
       FROM ocean_pay_txs t
      WHERE LOWER(COALESCE(t.moneda, '')) = ANY($1::text[])
        AND t.created_at >= $2
        AND ($3::timestamp IS NULL OR t.created_at <= $3)
        AND ${txPredicate}
        AND LOWER(COALESCE(t.origen, '')) <> 'global goal reward'`,
    [eligibleCurrencies, goal.starts_at, goal.ends_at || null]
  );
  return Number(rows[0]?.total || 0);
}

function serializeOceanPassRow(row) {
  return {
    active: Boolean(row?.is_active),
    expiry: row?.expiry || null,
    nextRenewAt: row?.next_renew_at || null,
    hasDebt: Boolean(row?.has_debt),
    debtAmount: toFiniteNumber(row?.debt_amount, 0),
    missions: [],
    lastRewardClaim: row?.last_reward_claim || null,
    minutesTracked: 0,
    planId: String(row?.plan_id || OCEAN_PASS_PLAN.id),
    planName: OCEAN_PASS_PLAN.name,
    billingCurrency: String(row?.billing_currency || '').toLowerCase(),
    billingAmount: toFiniteNumber(row?.billing_amount, 0),
    rewardAmount: OCEAN_PASS_PLAN.rewardAmount,
    rewardEveryHours: OCEAN_PASS_PLAN.rewardEveryHours,
    pricing: OCEAN_PASS_CURRENCY_PRICES
  };
}

function getAuthenticatedOceanPayUserId(req) {
  const token = parseStudioAuthToken(req);
  const decoded = decodeStudioTokenOrNull(token);
  if (!decoded) return 0;
  const userId = Number(decoded.id || decoded.uid || decoded.sub || 0);
  return Number.isFinite(userId) && userId > 0 ? userId : 0;
}

async function getPrimaryCardForOceanPassUser(client, userId) {
  const { rows } = await client.query(
    `SELECT id
       FROM ocean_pay_cards
      WHERE user_id = $1
      ORDER BY is_primary DESC, created_at ASC, id ASC
      LIMIT 1`,
    [userId]
  );
  return rows[0] || null;
}

// Estado de Ocean Pass (fallback seguro para clientes)
app.get('/ocean-pay/pass/status', async (req, res) => {
  const userId = getAuthenticatedOceanPayUserId(req);
  if (!userId) return res.status(401).json({ error: 'Token invalido' });

  try {
    const { rows } = await pool.query(
      `SELECT user_id, is_active, expiry, has_debt, debt_amount, missions, last_reward_claim, minutes_tracked,
              plan_id, billing_currency, billing_amount, next_renew_at
         FROM ocean_pass
        WHERE user_id = $1
        LIMIT 1`,
      [userId]
    );

    if (!rows.length) {
      return res.json({
        active: false,
        expiry: null,
        nextRenewAt: null,
        hasDebt: false,
        debtAmount: 0,
        missions: [],
        lastRewardClaim: null,
        minutesTracked: 0,
        planId: OCEAN_PASS_PLAN.id,
        planName: OCEAN_PASS_PLAN.name,
        billingCurrency: null,
        billingAmount: 0,
        rewardAmount: OCEAN_PASS_PLAN.rewardAmount,
        rewardEveryHours: OCEAN_PASS_PLAN.rewardEveryHours,
        pricing: OCEAN_PASS_CURRENCY_PRICES
      });
    }

    return res.json(serializeOceanPassRow(rows[0]));
  } catch (err) {
    console.error('Error en GET /ocean-pay/pass/status:', err);
    return res.status(500).json({ error: 'Error interno' });
  }
});

// Activar/renovar suscripcion Ocean Pass (obligatoria, sin misiones)
app.post('/ocean-pay/pass/activate', async (req, res) => {
  const userId = getAuthenticatedOceanPayUserId(req);
  if (!userId) return res.status(401).json({ error: 'Token invalido' });

  const requestedCurrency = String(req.body?.currency || '').trim().toLowerCase();
  const price = getOceanPassPriceForCurrency(requestedCurrency);
  if (!price) {
    return res.status(400).json({ error: 'Divisa no valida para Ocean Pass' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const primaryCard = await getPrimaryCardForOceanPassUser(client, userId);
    if (!primaryCard?.id) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'No tienes una tarjeta principal activa en Ocean Pay' });
    }

    const { rows: balRows } = await client.query(
      `SELECT amount
         FROM ocean_pay_card_balances
        WHERE card_id = $1 AND currency_type = $2
        FOR UPDATE`,
      [primaryCard.id, price.currency]
    );
    const currentBalance = toFiniteNumber(balRows[0]?.amount, 0);
    if (currentBalance < price.amount) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: `Saldo insuficiente en ${price.currency.toUpperCase()}` });
    }

    await client.query(
      `INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount)
       VALUES ($1, $2, $3)
       ON CONFLICT (card_id, currency_type)
       DO UPDATE SET amount = ocean_pay_card_balances.amount - $3`,
      [primaryCard.id, price.currency, price.amount]
    );

    const now = new Date();
    const { rows: existingRows } = await client.query(
      `SELECT expiry
         FROM ocean_pass
        WHERE user_id = $1
        FOR UPDATE`,
      [userId]
    );
    const currentExpiry = existingRows[0]?.expiry ? new Date(existingRows[0].expiry) : null;
    const base = currentExpiry && currentExpiry > now ? currentExpiry : now;
    const nextExpiry = new Date(base.getTime() + (OCEAN_PASS_PLAN.durationDays * 24 * 60 * 60 * 1000));

    await client.query(
      `INSERT INTO ocean_pass (
         user_id, is_active, expiry, has_debt, debt_amount, missions, minutes_tracked, last_reward_claim,
         plan_id, billing_currency, billing_amount, next_renew_at
       )
       VALUES ($1, TRUE, $2, FALSE, 0, '[]'::jsonb, 0, COALESCE((SELECT last_reward_claim FROM ocean_pass WHERE user_id = $1), NULL), $3, $4, $5, $2)
       ON CONFLICT (user_id) DO UPDATE SET
         is_active = TRUE,
         expiry = EXCLUDED.expiry,
         has_debt = FALSE,
         debt_amount = 0,
         missions = '[]'::jsonb,
         minutes_tracked = 0,
         plan_id = EXCLUDED.plan_id,
         billing_currency = EXCLUDED.billing_currency,
         billing_amount = EXCLUDED.billing_amount,
         next_renew_at = EXCLUDED.next_renew_at`,
      [userId, nextExpiry, OCEAN_PASS_PLAN.id, price.currency, price.amount]
    );

    await client.query(
      `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
       VALUES ($1, $2, $3, $4, $5)`,
      [userId, `Ocean Pass - Suscripcion (${OCEAN_PASS_PLAN.durationDays} dias)`, -price.amount, 'Ocean Pass', price.currency]
    );

    await client.query('COMMIT');

    const { rows: passRows } = await pool.query(
      `SELECT user_id, is_active, expiry, has_debt, debt_amount, missions, last_reward_claim, minutes_tracked,
              plan_id, billing_currency, billing_amount, next_renew_at
         FROM ocean_pass
        WHERE user_id = $1
        LIMIT 1`,
      [userId]
    );
    return res.json({ success: true, ...serializeOceanPassRow(passRows[0]) });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error en POST /ocean-pay/pass/activate:', err);
    return res.status(500).json({ error: 'No se pudo activar Ocean Pass' });
  } finally {
    client.release();
  }
});

// Compatibilidad: track no-op (misiones desactivadas por modelo de suscripcion)
app.post('/ocean-pay/pass/track', async (req, res) => {
  const userId = getAuthenticatedOceanPayUserId(req);
  if (!userId) return res.status(401).json({ error: 'Token invalido' });
  return res.json({ success: true, tracked: false, mode: 'subscription' });
});

// Pagar deuda legacy de Ocean Pass
app.post('/ocean-pay/pass/pay-debt', async (req, res) => {
  const userId = getAuthenticatedOceanPayUserId(req);
  if (!userId) return res.status(401).json({ error: 'Token invalido' });

  const requestedCurrency = String(req.body?.currency || '').trim().toLowerCase();
  if (!requestedCurrency) return res.status(400).json({ error: 'Divisa requerida' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { rows: passRows } = await client.query(
      `SELECT has_debt, debt_amount
         FROM ocean_pass
        WHERE user_id = $1
        FOR UPDATE`,
      [userId]
    );
    if (!passRows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'No tienes registro de Ocean Pass' });
    }

    const debtAmount = toFiniteNumber(passRows[0].debt_amount, 0);
    if (!passRows[0].has_debt || debtAmount <= 0) {
      await client.query('ROLLBACK');
      return res.json({ success: true, paid: 0, message: 'No hay deuda pendiente' });
    }

    const primaryCard = await getPrimaryCardForOceanPassUser(client, userId);
    if (!primaryCard?.id) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'No tienes una tarjeta principal activa en Ocean Pay' });
    }

    const { rows: balRows } = await client.query(
      `SELECT amount
         FROM ocean_pay_card_balances
        WHERE card_id = $1 AND currency_type = $2
        FOR UPDATE`,
      [primaryCard.id, requestedCurrency]
    );
    const currentBalance = toFiniteNumber(balRows[0]?.amount, 0);
    if (currentBalance < debtAmount) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: `Saldo insuficiente en ${requestedCurrency.toUpperCase()}` });
    }

    await client.query(
      `INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount)
       VALUES ($1, $2, 0)
       ON CONFLICT (card_id, currency_type)
       DO UPDATE SET amount = ocean_pay_card_balances.amount - $3`,
      [primaryCard.id, requestedCurrency, debtAmount]
    );

    await client.query(
      `UPDATE ocean_pass
          SET has_debt = FALSE,
              debt_amount = 0,
              is_active = TRUE
        WHERE user_id = $1`,
      [userId]
    );

    await client.query(
      `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
       VALUES ($1, $2, $3, $4, $5)`,
      [userId, 'Ocean Pass - Pago de deuda', -debtAmount, 'Ocean Pass', requestedCurrency]
    );

    await client.query('COMMIT');
    return res.json({ success: true, paid: debtAmount, currency: requestedCurrency });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error en POST /ocean-pay/pass/pay-debt:', err);
    return res.status(500).json({ error: 'No se pudo pagar la deuda' });
  } finally {
    client.release();
  }
});

// Reclamar regalo de Ocean Pass (cada 24h, 750 en divisa elegida)
app.post('/ocean-pay/pass/claim-reward', async (req, res) => {
  const userId = getAuthenticatedOceanPayUserId(req);
  if (!userId) return res.status(401).json({ error: 'Token invalido' });

  const currency = String(req.body?.currency || '').trim().toLowerCase();
  if (!Object.prototype.hasOwnProperty.call(OCEAN_PASS_CURRENCY_PRICES, currency)) {
    return res.status(400).json({ error: 'Divisa de recompensa no valida' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { rows: passRows } = await client.query(
      `SELECT is_active, has_debt, last_reward_claim
         FROM ocean_pass
        WHERE user_id = $1
        FOR UPDATE`,
      [userId]
    );
    if (!passRows.length || !passRows[0].is_active || passRows[0].has_debt) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Ocean Pass no esta activo' });
    }

    const lastClaimAt = passRows[0].last_reward_claim ? new Date(passRows[0].last_reward_claim).getTime() : 0;
    const now = Date.now();
    const cooldownMs = OCEAN_PASS_PLAN.rewardEveryHours * 60 * 60 * 1000;
    if (lastClaimAt && now - lastClaimAt < cooldownMs) {
      const remaining = cooldownMs - (now - lastClaimAt);
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Recompensa aun en recarga', remainingMs: remaining });
    }

    const primaryCard = await getPrimaryCardForOceanPassUser(client, userId);
    if (!primaryCard?.id) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'No tienes una tarjeta principal activa en Ocean Pay' });
    }

    const rewardAmount = OCEAN_PASS_PLAN.rewardAmount;
    await client.query(
      `INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount)
       VALUES ($1, $2, $3)
       ON CONFLICT (card_id, currency_type)
       DO UPDATE SET amount = ocean_pay_card_balances.amount + $3`,
      [primaryCard.id, currency, rewardAmount]
    );

    await client.query(
      `UPDATE ocean_pass
          SET last_reward_claim = NOW()
        WHERE user_id = $1`,
      [userId]
    );

    await client.query(
      `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
       VALUES ($1, $2, $3, $4, $5)`,
      [userId, 'Ocean Pass - Regalo diario', rewardAmount, 'Ocean Pass', currency]
    );

    await client.query('COMMIT');
    return res.json({ success: true, amount: rewardAmount, currency, rewardEveryHours: OCEAN_PASS_PLAN.rewardEveryHours });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error en POST /ocean-pay/pass/claim-reward:', err);
    return res.status(500).json({ error: 'No se pudo reclamar la recompensa' });
  } finally {
    client.release();
  }
});

// Registrar o actualizar un proyecto (Upsert)
app.post('/ows-store/projects', async (req, res) => {
  const { slug, name, description, icon_url, banner_url, url, version, status, release_date, metadata, installer_url } = req.body;
  if (!slug || !name || !url) return res.status(400).json({ error: 'Faltan campos obligatorios (slug, name, url)' });

  try {
    const { rows } = await pool.query(
      `INSERT INTO ows_projects (slug, name, description, icon_url, banner_url, url, version, status, release_date, metadata, installer_url)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       ON CONFLICT (slug) DO UPDATE SET
         name = EXCLUDED.name,
         description = EXCLUDED.description,
         icon_url = EXCLUDED.icon_url,
         banner_url = EXCLUDED.banner_url,
         url = EXCLUDED.url,
         version = EXCLUDED.version,
        status = EXCLUDED.status,
        release_date = COALESCE(EXCLUDED.release_date, ows_projects.release_date),
         metadata = ows_projects.metadata || EXCLUDED.metadata,
         installer_url = COALESCE(EXCLUDED.installer_url, ows_projects.installer_url),
         last_update = NOW()
       RETURNING *`,
      [slug, name, description, icon_url, banner_url, url, version || '1.0.0', status || 'launched', release_date, metadata || {}, installer_url || null]
    );
    res.json({ success: true, project: rows[0] });
  } catch (err) {
    console.error('Ã¢ÂÅ’ Error en POST /ows-store/projects:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Actualizar versiÃƒÂ³n rÃƒÂ¡pidamente (Patch)
app.patch('/ows-store/projects/:slug/version', async (req, res) => {
  const { slug } = req.params;
  const { version, changelog = '' } = req.body;
  if (!version) return res.status(400).json({ error: 'VersiÃƒÂ³n requerida' });

  try {
    const { rows } = await pool.query(
      'UPDATE ows_projects SET version = $1, last_update = NOW() WHERE slug = $2 RETURNING *',
      [version, slug]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Proyecto no encontrado' });
    const project = rows[0];
    const pushSummary = await queueOwsStorePushUpdate({
      projectSlug: project.slug || slug,
      projectName: project.name || slug,
      version,
      changelog
    });
    res.json({
      success: true,
      project,
      push: {
        queued: Number(pushSummary?.queued || 0),
        pushed_now: Number(pushSummary?.pushedNow || 0),
        dedupe_key: String(pushSummary?.dedupeKey || '')
      }
    });
  } catch (err) {
    console.error('Ã¢ÂÅ’ Error en PATCH /ows-store/projects/:version:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Obtener ÃƒÂºltimo release Android publicado por slug
// Actualizar metadata de un proyecto (description, name, etc.)
app.patch('/ows-store/projects/:slug', async (req, res) => {
  if (!requireOwsStoreAdmin(req, res)) return;
  const { slug } = req.params;
  const allowed = ['description', 'name', 'status', 'platform', 'banner_url', 'icon_url'];
  const updates = {};
  for (const key of allowed) {
    if (req.body[key] !== undefined) updates[key] = req.body[key];
  }
  if (Object.keys(updates).length === 0) {
    return res.status(400).json({ error: 'No hay campos validos para actualizar' });
  }
  try {
    const setClauses = Object.keys(updates).map((k, i) => `${k} = $${i + 1}`).join(', ');
    const values = [...Object.values(updates), slug];
    const { rows } = await pool.query(
      `UPDATE ows_projects SET ${setClauses}, last_update = NOW() WHERE slug = $${values.length} RETURNING *`,
      values
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Proyecto no encontrado' });
    res.json({ success: true, project: rows[0] });
  } catch (err) {
    console.error('Error en PATCH /ows-store/projects/:slug:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});


// Eliminar proyecto de OWS Store
app.delete('/ows-store/projects/:slug', async (req, res) => {
  if (!requireOwsStoreAdmin(req, res)) return;
  const { slug } = req.params;
  try {
    const { rows } = await pool.query(
      'DELETE FROM ows_projects WHERE slug = $1 RETURNING slug',
      [slug]
    );
    if (!rows.length) return res.status(404).json({ error: 'Proyecto no encontrado' });
    res.json({ success: true, deleted: rows[0].slug });
  } catch (err) {
    console.error('Error en DELETE /ows-store/projects/:slug:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

app.get('/ows-store/android/releases/:slug/latest', async (req, res) => {
  const { slug } = req.params;
  const includeDraft = String(req.query.include_draft || '').toLowerCase() === 'true';
  try {
    const whereStatus = includeDraft ? '' : "AND status = 'published'";
    const { rows } = await pool.query(
      `SELECT *
       FROM ows_android_releases
       WHERE project_slug = $1
         ${whereStatus}
       ORDER BY version_code DESC, published_at DESC, id DESC
       LIMIT 1`,
      [slug]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Release Android no encontrada' });
    res.setHeader('Cache-Control', 'no-store, max-age=0');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.json({ success: true, release: rows[0] });
  } catch (err) {
    console.error('Ã¢ÂÅ’ Error en GET /ows-store/android/releases/:slug/latest:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Descargar APK Android de la ultima release publicada (redirige al asset final de GitHub Releases)
app.get('/ows-store/android/releases/:slug/latest/download', async (req, res) => {
  const { slug } = req.params;
  try {
    const { rows } = await pool.query(
      `SELECT *
       FROM ows_android_releases
       WHERE project_slug = $1
         AND status = 'published'
       ORDER BY version_code DESC, published_at DESC, id DESC
       LIMIT 1`,
      [slug]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Release Android no encontrada' });
    const release = rows[0];
    const sourceUrl = String(release.apk_url || '').trim();
    if (!sourceUrl) return res.status(404).json({ error: 'Release Android sin apk_url' });
    // Redireccion directa al asset final para evitar descargas colgadas en navegadores moviles.
    // Mantiene el endpoint estable en OWS Store y delega la transferencia al origen real (GitHub Releases).
    res.setHeader('Cache-Control', 'no-store, max-age=0');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    return res.redirect(302, sourceUrl);
  } catch (err) {
    console.error('Ã¢ÂÅ’ Error en GET /ows-store/android/releases/:slug/latest/download:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Listar releases Android (opcionalmente por slug)
app.get('/ows-store/android/releases', async (req, res) => {
  const slug = String(req.query.slug || '').trim();
  const limit = Math.min(Math.max(Number(req.query.limit || 50), 1), 200);
  try {
    const { rows } = slug
      ? await pool.query(
        `SELECT *
         FROM ows_android_releases
         WHERE project_slug = $1
         ORDER BY published_at DESC, version_code DESC, id DESC
         LIMIT $2`,
        [slug, limit]
      )
      : await pool.query(
        `SELECT *
         FROM ows_android_releases
         ORDER BY published_at DESC, version_code DESC, id DESC
         LIMIT $1`,
        [limit]
      );
    res.json(rows);
  } catch (err) {
    console.error('Ã¢ÂÅ’ Error en GET /ows-store/android/releases:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Registrar o actualizar release Android
app.post('/ows-store/android/releases', async (req, res) => {
  if (!requireOwsStoreAdmin(req, res)) return;

  const {
    project_slug,
    package_id,
    version_name,
    version_code,
    apk_url,
    sha256,
    size_bytes,
    min_store_version,
    release_notes,
    status,
    is_mandatory,
    published_at
  } = req.body || {};

  if (!project_slug || !package_id || !version_name || !version_code || !apk_url) {
    return res.status(400).json({ error: 'Campos requeridos: project_slug, package_id, version_name, version_code, apk_url' });
  }

  const numericVersionCode = Number(version_code);
  if (!Number.isInteger(numericVersionCode) || numericVersionCode <= 0) {
    return res.status(400).json({ error: 'version_code debe ser entero positivo' });
  }

  try {
    const projectExists = await pool.query('SELECT 1 FROM ows_projects WHERE slug = $1 LIMIT 1', [project_slug]);
    if (projectExists.rowCount === 0) {
      return res.status(404).json({ error: 'Proyecto no registrado en ows_projects' });
    }

    const { rows } = await pool.query(
      `INSERT INTO ows_android_releases (
         project_slug, package_id, version_name, version_code, apk_url,
         sha256, size_bytes, min_store_version, release_notes, status, is_mandatory, published_at
       )
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,COALESCE($12, NOW()))
       ON CONFLICT (project_slug, version_code) DO UPDATE SET
         package_id = EXCLUDED.package_id,
         version_name = EXCLUDED.version_name,
         apk_url = EXCLUDED.apk_url,
         sha256 = EXCLUDED.sha256,
         size_bytes = EXCLUDED.size_bytes,
         min_store_version = EXCLUDED.min_store_version,
         release_notes = EXCLUDED.release_notes,
         status = EXCLUDED.status,
         is_mandatory = EXCLUDED.is_mandatory,
         published_at = COALESCE(EXCLUDED.published_at, ows_android_releases.published_at)
       RETURNING *`,
      [
        project_slug,
        package_id,
        version_name,
        numericVersionCode,
        apk_url,
        sha256 || null,
        Number(size_bytes || 0),
        min_store_version || null,
        release_notes || null,
        status || 'published',
        Boolean(is_mandatory),
        published_at || null
      ]
    );

    res.json({ success: true, release: rows[0] });
  } catch (err) {
    console.error('Ã¢ÂÅ’ Error en POST /ows-store/android/releases:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Check de update Android por proyecto
app.post('/ows-store/android/check-update', async (req, res) => {
  const { project_slug, package_id, installed_version_code, installed_version_name } = req.body || {};
  if (!project_slug) return res.status(400).json({ error: 'project_slug requerido' });

  const installedCode = Number(installed_version_code || 0);
  try {
    const { rows } = await pool.query(
      `SELECT *
       FROM ows_android_releases
       WHERE project_slug = $1
         AND status = 'published'
         AND ($2::text IS NULL OR package_id = $2)
       ORDER BY version_code DESC, published_at DESC, id DESC
       LIMIT 1`,
      [project_slug, package_id || null]
    );

    if (rows.length === 0) {
      return res.json({ success: true, update_available: false, reason: 'no_release' });
    }

    const latest = rows[0];
    const updateAvailable = Number(latest.version_code || 0) > (Number.isFinite(installedCode) ? installedCode : 0);

    return res.json({
      success: true,
      update_available: updateAvailable,
      installed: {
        version_code: Number.isFinite(installedCode) ? installedCode : 0,
        version_name: installed_version_name || null
      },
      latest
    });
  } catch (err) {
    console.error('Ã¢ÂÅ’ Error en POST /ows-store/android/check-update:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

/* ----------  APPBUX ENDPOINTS  ---------- */
// Obtener balance de AppBux
app.get('/ocean-pay/appbux/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    // Obtener el balance de AppBux solo de la tarjeta primaria
    const { rows } = await pool.query(`
      SELECT COALESCE(opcb.amount, 0) as total 
      FROM ocean_pay_card_balances opcb
      JOIN ocean_pay_cards opc ON opcb.card_id = opc.id
      WHERE opc.user_id = $1 AND opcb.currency_type = 'appbux'
      ORDER BY opc.is_primary DESC, opc.id ASC
      LIMIT 1
    `, [userId]);

    res.json({ appbux: parseFloat(rows[0]?.total || 0) });
  } catch (err) {
    console.error('Ã¢ÂÅ’ Error en /ocean-pay/appbux/:userId', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Cambiar balance de AppBux
app.post('/ocean-pay/appbux/change', async (req, res) => {
  const { userId, amount, concepto = 'OperaciÃƒÂ³n', origen = 'AllApp', cardId } = req.body;

  if (!userId || amount === undefined) {
    return res.status(400).json({ error: 'Faltan datos' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1. Determinar la tarjeta objetivo
    let targetCardId = cardId;
    if (!targetCardId) {
      const { rows: primaryRows } = await client.query(
        'SELECT id FROM ocean_pay_cards WHERE user_id = $1 AND is_primary = true',
        [userId]
      );
      if (primaryRows.length > 0) {
        targetCardId = primaryRows[0].id;
      } else {
        const { rows: firstCardRows } = await client.query(
          'SELECT id FROM ocean_pay_cards WHERE user_id = $1 LIMIT 1',
          [userId]
        );
        if (firstCardRows.length > 0) targetCardId = firstCardRows[0].id;
      }
    }

    if (!targetCardId) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'No se encontrÃƒÂ³ una tarjeta vÃƒÂ¡lida' });
    }

    // 2. VALIDAR: Si es un gasto (amount < 0), verificar saldo suficiente en la tarjeta
    if (amount < 0) {
      const { rows: balanceRows } = await client.query(
        `SELECT COALESCE(amount, 0) as current_balance 
         FROM ocean_pay_card_balances 
         WHERE card_id = $1 AND currency_type = 'appbux'`,
        [targetCardId]
      );
      const currentCardBalance = parseFloat(balanceRows[0]?.current_balance || 0);

      if (currentCardBalance + amount < 0) {
        await client.query('ROLLBACK');
        return res.status(400).json({
          error: 'Saldo insuficiente en la tarjeta seleccionada',
          currentBalance: currentCardBalance,
          required: Math.abs(amount)
        });
      }
    }

    // 3. Update legacy user table total balance (for compatibility)
    await client.query(
      'UPDATE ocean_pay_users SET appbux = appbux + $1 WHERE id = $2',
      [amount, userId]
    );

    // 4. Update card balance
    await client.query(`
      INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount)
      VALUES ($1, 'appbux', $2)
      ON CONFLICT (card_id, currency_type)
      DO UPDATE SET amount = ocean_pay_card_balances.amount + $2
    `, [targetCardId, amount]);

    // 5. Register transaction
    try {
      await client.query(
        `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
         VALUES ($1, $2, $3, $4, 'ABX')`,
        [userId, concepto, amount, origen]
      );
    } catch (e) {
      await client.query(
        `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen)
         VALUES ($1, $2, $3, $4)`,
        [userId, concepto, amount, origen]
      );
    }

    // 6. Calculate return balance (Primary Card only)
    const { rows: totalRows } = await client.query(`
      SELECT COALESCE(opcb.amount, 0) as total 
      FROM ocean_pay_card_balances opcb
      JOIN ocean_pay_cards opc ON opcb.card_id = opc.id
      WHERE opc.user_id = $1 AND opcb.currency_type = 'appbux'
      ORDER BY opc.is_primary DESC, opc.id ASC
      LIMIT 1
    `, [userId]);

    const newBalance = parseFloat(totalRows[0]?.total || 0);

    await client.query('COMMIT');
    res.json({ success: true, newBalance });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Ã¢ÂÅ’ Error en /ocean-pay/appbux/change:', err);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

/* ----------  OCEAN PAY V2 ENDPOINTS  ---------- */

// 1. Transferencia entre tarjetas propias
app.post('/ocean-pay/transfer', async (req, res) => {
  const { userId, fromCardId, toCardId, currency, amount } = req.body;

  if (!userId || !fromCardId || !toCardId || !currency || amount <= 0) {
    return res.status(400).json({ error: 'Datos incompletos o invÃƒÂ¡lidos' });
  }

  if (fromCardId === toCardId) {
    return res.status(400).json({ error: 'No puedes transferir a la misma tarjeta' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Verificar propiedad de tarjetas
    const { rows: cards } = await client.query(
      'SELECT id, user_id FROM ocean_pay_cards WHERE id IN ($1, $2)',
      [fromCardId, toCardId]
    );

    if (cards.length !== 2 || cards.some(c => c.user_id != userId)) {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: 'Tarjetas invÃƒÂ¡lidas o no pertenecen al usuario' });
    }

    // Verificar saldo origen
    const { rows: balanceRows } = await client.query(
      'SELECT amount FROM ocean_pay_card_balances WHERE card_id = $1 AND currency_type = $2',
      [fromCardId, currency]
    );
    const currentBalance = parseFloat(balanceRows[0]?.amount || 0);

    if (currentBalance < amount) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Saldo insuficiente en tarjeta origen' });
    }

    // Descontar origen
    await client.query(`
      INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount)
      VALUES ($1, $2, $3)
      ON CONFLICT (card_id, currency_type)
      DO UPDATE SET amount = ocean_pay_card_balances.amount - $3
    `, [fromCardId, currency, amount]);

    // Sumar destino
    await client.query(`
      INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount)
      VALUES ($1, $2, $3)
      ON CONFLICT (card_id, currency_type)
      DO UPDATE SET amount = ocean_pay_card_balances.amount + $3
    `, [toCardId, currency, amount]);

    // Registrar transacciÃƒÂ³n
    await client.query(
      `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
       VALUES ($1, $2, $3, 'Transferencia Interna', $4)`,
      [userId, `Transferencia a tarjeta ${toCardId}`, -amount, currency]
    );

    await client.query('COMMIT');
    res.json({ success: true, message: 'Transferencia exitosa' });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Ã¢ÂÅ’ Error en /ocean-pay/transfer:', err);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});


// 3. EstadÃƒÂ­sticas de uso de divisas (Misc)
app.get('/ocean-pay/stats/tx-usage/:userId', async (req, res) => {
  const { userId } = req.params;

  try {
    // Top divisas ingresos (monto > 0)
    const { rows: incomeRows } = await pool.query(`
      SELECT moneda, COUNT(*) as count, SUM(monto) as total
      FROM ocean_pay_txs
      WHERE user_id = $1 AND monto > 0
      GROUP BY moneda
      ORDER BY count DESC
      LIMIT 5
    `, [userId]);

    // Top divisas gastos (monto < 0)
    const { rows: expenseRows } = await pool.query(`
      SELECT moneda, COUNT(*) as count, SUM(ABS(monto)) as total
      FROM ocean_pay_txs
      WHERE user_id = $1 AND monto < 0
      GROUP BY moneda
      ORDER BY count DESC
      LIMIT 5
    `, [userId]);

    res.json({
      income: incomeRows,
      expenses: expenseRows
    });

  } catch (err) {
    console.error('Ã¢ÂÅ’ Error en /ocean-pay/stats/tx-usage:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

/* ----------  DELETE ACCOUNT  ---------- */
app.delete('/ocean-pay/delete-account', async (req, res) => {
  const auth = req.headers.authorization;
  const { userId, username } = req.body;

  if (!userId || !username) {
    return res.status(400).json({ error: 'Faltan datos' });
  }

  // Verificar token si estÃƒÂ¡ presente
  if (auth) {
    try {
      const token = auth.split(' ')[1];
      const payload = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');

      // Verificar que el token corresponda al usuario
      if ((payload.id || payload.uid) !== userId) {
        return res.status(403).json({ error: 'No autorizado' });
      }
    } catch (e) {
      return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
    }
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Verificar que el usuario existe y el username coincide
    const { rows: userRows } = await client.query(
      'SELECT id, username FROM ocean_pay_users WHERE id = $1',
      [userId]
    );

    if (userRows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    if (userRows[0].username !== username) {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: 'El nombre de usuario no coincide' });
    }

    console.log(`Ã°Å¸â€”â€˜Ã¯Â¸Â Eliminando cuenta de Ocean Pay: ${username} (${userId})`);

    // Eliminar transacciones
    await client.query('DELETE FROM ocean_pay_txs WHERE user_id = $1', [userId]);

    // Eliminar metadata
    await client.query('DELETE FROM ocean_pay_metadata WHERE user_id = $1', [userId]);

    // Eliminar de users (EcoCoreBits)
    await client.query('DELETE FROM users WHERE id = $1', [userId]);

    // Eliminar transacciones de EcoCoreBits
    await client.query('DELETE FROM ecocore_txs WHERE user_id = $1', [userId]);

    // Eliminar suscripciones de Ecoxion
    await client.query('DELETE FROM ecoxion_subscriptions WHERE user_id = $1', [userId]);

    // Finalmente, eliminar el usuario de Ocean Pay
    await client.query('DELETE FROM ocean_pay_users WHERE id = $1', [userId]);

    await client.query('COMMIT');

    console.log(`Ã¢Å“â€¦ Cuenta eliminada exitosamente: ${username}`);
    res.json({ success: true, message: 'Cuenta eliminada permanentemente' });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Ã¢ÂÅ’ Error en /ocean-pay/delete-account:', err);
    res.status(500).json({ error: 'Error interno al eliminar la cuenta' });
  } finally {
    client.release();
  }
});

/* ----------  WILDCREDITS TRANSACTIONS  ---------- */
app.post('/ocean-pay/wildcredits/transaction', async (req, res) => {
  const { userId, amount, concepto = 'OperaciÃƒÂ³n', origen = 'Wild Explorer' } = req.body;
  if (!userId || amount === undefined) {
    return res.status(400).json({ error: 'Faltan datos' });
  }

  try {
    // Insertar transacciÃƒÂ³n en ocean_pay_txs con moneda 'WC'
    await pool.query(
      `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
       VALUES ($1, $2, $3, $4, 'WC')`,
      [userId, concepto, amount, origen]
    );

    res.json({ success: true });
  } catch (e) {
    console.error('Ã¢ÂÅ’ Error en /ocean-pay/wildcredits/transaction:', e);
    // Si falla por falta de columna moneda, intentar sin ella
    try {
      await pool.query(
        `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen)
         VALUES ($1, $2, $3, $4)`,
        [userId, concepto, amount, origen]
      );
      res.json({ success: true });
    } catch (e2) {
      res.status(500).json({ error: 'Error interno' });
    }
  }
});

// RUTA CORREGIDA: /oceanic-ethernet/register
app.post('/oceanic-ethernet/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Faltan datos' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const hashedPassword = await bcrypt.hash(password, 10);

    // 1. CREAR EL USUARIO EN OCEANIC ETHERNET
    const { rows: oeUserRows } = await client.query(
      'INSERT INTO oceanic_ethernet_users (username, pwd_hash) VALUES ($1, $2) RETURNING id, username',
      [username, hashedPassword]
    );
    const oeUser = oeUserRows[0];

    // 2. ASEGURAR Y OBTENER EL ID DEL USUARIO EN OCEAN PAY (TABLA PADRE)
    let opUserId;
    try {
      const opResult = await client.query(
        'INSERT INTO ocean_pay_users (username, pwd_hash) VALUES ($1, $2) RETURNING id',
        [username, hashedPassword]
      );
      opUserId = opResult.rows[0].id;
    } catch (e) {
      if (e.code === '23505') {
        const existingOpUser = await client.query('SELECT id FROM ocean_pay_users WHERE username = $1', [username]);
        if (existingOpUser.rows.length === 0) throw new Error("Error crÃƒÂ­tico: usuario duplicado pero ID no recuperado.");
        opUserId = existingOpOpUser.rows[0].id;
      } else {
        throw e;
      }
    }

    // 3. [CORRECCIÃƒâ€œN 42P10] SELECT ANTES DE INSERTAR METADATA (EVITA ON CONFLICT)
    const existingMeta = await client.query(
      'SELECT 1 FROM ocean_pay_metadata WHERE user_id = $1 AND key = $2',
      [opUserId, 'internet_gb']
    );

    if (existingMeta.rows.length === 0) {
      await client.query(`
            INSERT INTO ocean_pay_metadata (user_id, key, value)
            VALUES ($1, 'internet_gb', '0')
        `, [opUserId]); // Ã¢Å“â€¦ CORREGIDO: Usamos opUserId
    }

    // 4. Vincular usuario de OceanicEthernet con el de Ocean Pay
    // Nota: AquÃƒÂ­ se mantiene ON CONFLICT porque la tabla oceanic_ethernet_user_links tiene un UNIQUE constraint.
    await client.query(`
      INSERT INTO oceanic_ethernet_user_links (oe_user_id, external_user_id, external_system)
      VALUES ($1, $2, $3)
      ON CONFLICT (external_user_id, external_system) DO NOTHING
    `, [oeUser.id, opUserId, 'OceanPay']);

    await client.query('COMMIT');
    res.json({ success: true, user: { id: oeUser.id, username: oeUser.username, opId: opUserId } });

  } catch (e) {
    await client.query('ROLLBACK');
    if (e.code === '23505') {
      return res.status(409).json({ error: 'Este usuario ya existe. Si es tu cuenta, usa la opciÃƒÂ³n "Iniciar sesiÃƒÂ³n".' });
    }
    console.error('Error en oceanic-ethernet/register:', e);
    res.status(500).json({ error: 'Error interno del servidor' });
  } finally {
    client.release();
  }
});

// Login separado para OceanicEthernet
app.post('/oceanic-ethernet/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Faltan datos' });

  try {
    const { rows } = await pool.query(`
      SELECT id, pwd_hash
      FROM oceanic_ethernet_users
      WHERE username = $1
    `, [username]);

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Usuario o contraseÃƒÂ±a incorrectos' });
    }

    const ok = await bcrypt.compare(password, rows[0].pwd_hash);
    if (!ok) {
      return res.status(401).json({ error: 'Usuario o contraseÃƒÂ±a incorrectos' });
    }

    const token = jwt.sign({ uid: rows[0].id, un: username, source: 'oceanic-ethernet' }, process.env.STUDIO_SECRET, { expiresIn: '7d' });

    // Asegurar que existe el registro de internet_gb (inicializar si no existe)
    try {
      await pool.query(`
        INSERT INTO ocean_pay_metadata (user_id, key, value)
        VALUES ($1, 'internet_gb', '0')
        ON CONFLICT (user_id, key) DO NOTHING
      `, [rows[0].id]);
    } catch (e) {
      // Ignorar errores de inicializaciÃƒÂ³n
      console.error('Error inicializando internet_gb:', e);
    }

    // Obtener saldo de internet
    let internetBalance = 0;
    try {
      const { rows: metaRows } = await pool.query(`
        SELECT value FROM ocean_pay_metadata
        WHERE user_id = $1 AND key = 'internet_gb'
      `, [rows[0].id]);

      if (metaRows.length > 0) {
        internetBalance = parseFloat(metaRows[0].value || '0');
      }
    } catch (e) {
      // Si falla, usar 0 como valor por defecto
      internetBalance = 0;
    }

    res.json({
      token,
      user: {
        id: rows[0].id,
        username,
        internetBalance
      }
    });
  } catch (err) {
    console.error('Error en oceanic-ethernet/login:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Vincular usuario de OceanicEthernet con usuario externo (NatMarket, AllApp, etc.)
app.post('/oceanic-ethernet/link-user', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.substring(7);
  let userId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    userId = (decoded.id || decoded.uid);
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }

  const { externalUserId, externalSystem } = req.body;

  if (!externalUserId || !externalSystem) {
    return res.status(400).json({ error: 'Faltan datos' });
  }

  try {
    await pool.query(`
      INSERT INTO oceanic_ethernet_user_links (oe_user_id, external_user_id, external_system)
      VALUES ($1, $2, $3)
      ON CONFLICT (external_user_id, external_system) 
      DO UPDATE SET oe_user_id = EXCLUDED.oe_user_id
    `, [userId, externalUserId, externalSystem]);

    res.json({ success: true, message: 'Usuario vinculado correctamente' });
  } catch (err) {
    console.error('Error vinculando usuario:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Obtener saldo de internet
app.get('/oceanic-ethernet/balance/:userId', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.substring(7);
  let oeUserId; // Renombramos a oeUserId para mayor claridad
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    oeUserId = (decoded.id || decoded.uid);
    oeUserId = parseInt(oeUserId) || oeUserId;
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }

  const { userId: paramUserId } = req.params;
  const paramUserIdNum = parseInt(paramUserId);

  // Verificar que el usuario del token coincida con el parÃƒÂ¡metro
  if (oeUserId !== paramUserIdNum) {
    return res.status(403).json({ error: 'No autorizado' });
  }

  // =========================================================================
  // Ã°Å¸â€™Â¡ CORRECCIÃƒâ€œN CRÃƒÂTICA (Error 23503: Foreign Key Violation)
  // Traducir el ID de Oceanic Ethernet (oeUserId) al ID de Ocean Pay (opUserId)
  // =========================================================================
  let opUserId;
  try {
    const linkResult = await pool.query(
      `SELECT external_user_id 
         FROM oceanic_ethernet_user_links 
         WHERE oe_user_id = $1 AND external_system = 'OceanPay'`,
      [oeUserId]
    );

    if (linkResult.rows.length === 0) {
      console.log(`Usuario OceanicEthernet (ID: ${oeUserId}) no vinculado a Ocean Pay.`);
      return res.json({ balance: 0 }); // El usuario no estÃƒÂ¡ vinculado, el balance es 0
    }

    opUserId = parseInt(linkResult.rows[0].external_user_id); // Ã¢Å“â€¦ PARSE TO INTEGER

    // A partir de aquÃƒÂ­, solo usamos opUserId para las consultas a ocean_pay_metadata

    // Intentar obtener desde metadata primero
    const { rows: metaRows } = await pool.query(`
      SELECT value FROM ocean_pay_metadata
      WHERE user_id = $1 AND key = 'internet_gb'
    `, [opUserId]); // Ã¢Å“â€¦ CORREGIDO: Usando opUserId como INTEGER

    if (metaRows.length > 0) {
      const balance = parseFloat(metaRows[0].value || '0');
      return res.json({ balance });
    }

    // Si no existe en metadata, crear registro con 0
    await pool.query(`
      INSERT INTO ocean_pay_metadata (user_id, key, value)
      VALUES ($1, 'internet_gb', '0')
      ON CONFLICT (user_id, key) DO NOTHING
    `, [opUserId]); // Ã¢Å“â€¦ CORREGIDO: Usando opUserId

    res.json({ balance: 0 });
  } catch (err) {
    console.error('Ã¢ÂÅ’ Error en /oceanic-ethernet/balance/:userId', err);
    // Si la tabla no existe, devolver 0
    if (err.code === '42P01') {
      res.json({ balance: 0 });
    } else {
      res.status(500).json({ error: 'Error interno' });
    }
  }
});

// Obtener balances de Ocean Pay para recarga
app.get('/oceanic-ethernet/ocean-pay-balances', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.substring(7);
  let opUserId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    opUserId = (decoded.id || decoded.uid);
    opUserId = parseInt(opUserId) || opUserId;
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }

  try {
    // Obtener balances de todas las divisas
    const { rows: userRows } = await pool.query(
      'SELECT aquabux, appbux FROM ocean_pay_users WHERE id = $1',
      [opUserId]
    );

    if (userRows.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const user = userRows[0];
    const balances = {
      'AB': user.aquabux || 0,
      'ABX': user.appbux || 0
    };

    // Obtener Ecoxionums
    try {
      const { rows: ecoxRows } = await pool.query(
        'SELECT value FROM ocean_pay_metadata WHERE user_id = $1 AND key = $2',
        [opUserId, 'ecoxionums']
      );
      balances['EX'] = ecoxRows.length > 0 ? parseFloat(ecoxRows[0].value || '0') : 0;
    } catch (e) {
      balances['EX'] = 0;
    }

    // Obtener EcoCoreBits (desde tabla ecorebits_users)
    try {
      const { rows: ecbRows } = await pool.query(
        'SELECT balance FROM ecorebits_users WHERE user_id = $1',
        [opUserId]
      );
      balances['ECB'] = ecbRows.length > 0 ? (ecbRows[0].balance || 0) : 0;
    } catch (e) {
      balances['ECB'] = 0;
    }

    // Obtener WildCredits
    try {
      const { rows: wcRows } = await pool.query(
        'SELECT value FROM ocean_pay_metadata WHERE user_id = $1 AND key = $2',
        [opUserId, 'wildcredits']
      );
      balances['WC'] = wcRows.length > 0 ? parseInt(wcRows[0].value || '0') : 0;
    } catch (e) {
      balances['WC'] = 0;
    }

    // Obtener WildGems (desde tabla wildshorts_users)
    try {
      const { rows: wgRows } = await pool.query(
        'SELECT wildgems FROM wildshorts_users WHERE user_id = $1',
        [opUserId]
      );
      balances['WG'] = wgRows.length > 0 ? (wgRows[0].wildgems || 0) : 0;
    } catch (e) {
      balances['WG'] = 0;
    }

    res.json(balances);
  } catch (err) {
    console.error('Ã¢ÂÅ’ Error en /oceanic-ethernet/ocean-pay-balances:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Solicitar recarga de internet
app.post('/oceanic-ethernet/recharge', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.substring(7);
  let userId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    userId = (decoded.id || decoded.uid);
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }

  const { userId: bodyUserId, amount, currency, cost } = req.body;
  const opToken = req.headers['x-ocean-pay-token'];

  if (!bodyUserId || amount === undefined || amount <= 0) {
    return res.status(400).json({ error: 'Datos invÃƒÂ¡lidos' });
  }

  // Si hay opToken vinculado, obtener su userId para validaciÃƒÂ³n
  let opUserId = null;
  if (opToken && opToken.trim() !== '') {
    try {
      const decoded = jwt.verify(opToken, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
      opUserId = (decoded.id || decoded.uid);
      opUserId = parseInt(opUserId) || opUserId;
      console.log('Ã¢Å“â€¦ Token de Ocean Pay vÃƒÂ¡lido, opUserId:', opUserId);
    } catch (e) {
      console.error('Ã¢ÂÅ’ Error verificando token de Ocean Pay:', e.message);
      // Si el token es invÃƒÂ¡lido, continuar sin opUserId
    }
  }

  // Validar autorizaciÃƒÂ³n:
  // IMPORTANTE: El saldo de internet es especÃƒÂ­fico de cada cuenta de OceanicEthernet
  // Siempre validamos que el bodyUserId coincida con el userId del token de OceanicEthernet
  // El token de Ocean Pay solo se usa para procesar el pago, no para determinar a quÃƒÂ© cuenta se aplica el saldo
  const bodyUserIdInt = parseInt(bodyUserId);

  // Validar que el usuario estÃƒÂ¡ recargando su propia cuenta de OceanicEthernet
  if (userId !== bodyUserIdInt) {
    console.error('Ã¢ÂÅ’ Error de autorizaciÃƒÂ³n en recarga:', {
      tokenUserId: userId,
      bodyUserId: bodyUserIdInt,
      opUserId: opUserId,
      hasOpToken: !!opToken && opToken.trim() !== '',
      message: 'El userId del token de OceanicEthernet no coincide con el bodyUserId'
    });
    return res.status(403).json({
      error: 'No autorizado: solo puedes recargar tu propia cuenta de OceanicEthernet.'
    });
  }

  // Si hay opToken, validar que sea vÃƒÂ¡lido (para procesar el pago)
  if (opToken && opToken.trim() !== '' && currency && cost) {
    if (!opUserId) {
      console.error('Ã¢ÂÅ’ Token de Ocean Pay invÃƒÂ¡lido o no decodificable');
      return res.status(401).json({ error: 'Token de Ocean Pay invÃƒÂ¡lido. Por favor, vuelve a vincular tu cuenta de Ocean Pay.' });
    }
  }

  console.log('Ã¢Å“â€¦ AutorizaciÃƒÂ³n exitosa para recarga:', {
    tokenUserId: userId,
    bodyUserId: bodyUserIdInt,
    username: 'OceanicEthernet',
    opUserId: opUserId,
    usandoOceanPay: !!(opToken && opToken.trim() !== '')
  });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Mapeo de nombres de divisas
    const currencyNames = {
      'AB': 'AquaBux',
      'EX': 'Ecoxionums',
      'ECB': 'EcoCoreBits',
      'WC': 'WildCredits',
      'ABX': 'AppBux',
      'WG': 'WildGems'
    };

    // Si hay divisa y costo, procesar pago desde Ocean Pay
    if (currency && cost && opToken) {
      // opUserId ya fue obtenido arriba en la validaciÃƒÂ³n
      if (!opUserId) {
        await client.query('ROLLBACK');
        return res.status(401).json({ error: 'Token de Ocean Pay invÃƒÂ¡lido' });
      }

      // Verificar si la columna moneda existe
      let hasMonedaColumn = false;
      try {
        const { rows: columnCheck } = await client.query(`
          SELECT column_name 
          FROM information_schema.columns 
          WHERE table_name = 'ocean_pay_txs' AND column_name = 'moneda'
        `);
        hasMonedaColumn = columnCheck.length > 0;
      } catch (e) {
        // Si falla la verificaciÃƒÂ³n, asumir que no existe
        hasMonedaColumn = false;
      }

      // Procesar pago segÃƒÂºn la divisa
      let paymentSuccess = false;

      // IMPORTANTE: Redondear el costo al entero mÃƒÂ¡s cercano para divisas INTEGER
      // Las divisas en ocean_pay_users (aquabux, appbux) son INTEGER, no aceptan decimales
      let roundedCost = Math.round(cost);
      if (roundedCost <= 0 && cost > 0) {
        // Si el costo es mayor que 0 pero se redondea a 0, usar 1 como mÃƒÂ­nimo
        roundedCost = 1;
      }

      if (currency === 'AB') {
        // AquaBux (INTEGER)
        const { rows } = await client.query(
          'SELECT aquabux FROM ocean_pay_users WHERE id = $1 FOR UPDATE',
          [opUserId]
        );
        if (rows.length === 0) {
          await client.query('ROLLBACK');
          return res.status(404).json({ error: 'Usuario de Ocean Pay no encontrado' });
        }
        const currentBalance = rows[0].aquabux || 0;
        if (currentBalance < roundedCost) {
          await client.query('ROLLBACK');
          return res.status(400).json({ error: 'Saldo insuficiente' });
        }
        await client.query(
          'UPDATE ocean_pay_users SET aquabux = aquabux - $1 WHERE id = $2',
          [roundedCost, opUserId]
        );
        if (hasMonedaColumn) {
          await client.query(
            'INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda) VALUES ($1, $2, $3, $4, $5)',
            [opUserId, `Recarga OceanicEthernet: ${amount} GB`, -roundedCost, 'OceanicEthernet', 'AB']
          );
        } else {
          await client.query(
            'INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen) VALUES ($1, $2, $3, $4)',
            [opUserId, `Recarga OceanicEthernet: ${amount} GB`, -roundedCost, 'OceanicEthernet']
          );
        }
        paymentSuccess = true;
      } else if (currency === 'ABX') {
        // AppBux (INTEGER)
        const { rows } = await client.query(
          'SELECT appbux FROM ocean_pay_users WHERE id = $1 FOR UPDATE',
          [opUserId]
        );
        if (rows.length === 0) {
          await client.query('ROLLBACK');
          return res.status(404).json({ error: 'Usuario de Ocean Pay no encontrado' });
        }
        const currentBalance = rows[0].appbux || 0;
        if (currentBalance < roundedCost) {
          await client.query('ROLLBACK');
          return res.status(400).json({ error: 'Saldo insuficiente' });
        }
        await client.query(
          'UPDATE ocean_pay_users SET appbux = appbux - $1 WHERE id = $2',
          [roundedCost, opUserId]
        );
        if (hasMonedaColumn) {
          await client.query(
            'INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda) VALUES ($1, $2, $3, $4, $5)',
            [opUserId, `Recarga OceanicEthernet: ${amount} GB`, -roundedCost, 'OceanicEthernet', 'ABX']
          );
        } else {
          await client.query(
            'INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen) VALUES ($1, $2, $3, $4)',
            [opUserId, `Recarga OceanicEthernet: ${amount} GB`, -roundedCost, 'OceanicEthernet']
          );
        }
        paymentSuccess = true;
      } else if (currency === 'EX') {
        // Ecoxionums
        const { rows } = await client.query(
          'SELECT value FROM ocean_pay_metadata WHERE user_id = $1 AND key = $2 FOR UPDATE',
          [opUserId, 'ecoxionums']
        );
        const currentBalance = rows.length > 0 ? parseFloat(rows[0].value || '0') : 0;
        if (currentBalance < cost) {
          await client.query('ROLLBACK');
          return res.status(400).json({ error: 'Saldo insuficiente' });
        }
        const newBalance = currentBalance - cost;
        if (rows.length > 0) {
          await client.query(
            'UPDATE ocean_pay_metadata SET value = $1 WHERE user_id = $2 AND key = $3',
            [newBalance.toString(), opUserId, 'ecoxionums']
          );
        }
        if (hasMonedaColumn) {
          await client.query(
            'INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda) VALUES ($1, $2, $3, $4, $5)',
            [opUserId, `Recarga OceanicEthernet: ${amount} GB`, -cost, 'OceanicEthernet', 'EX']
          );
        } else {
          await client.query(
            'INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen) VALUES ($1, $2, $3, $4)',
            [opUserId, `Recarga OceanicEthernet: ${amount} GB`, -cost, 'OceanicEthernet']
          );
        }
        paymentSuccess = true;
      } else if (currency === 'ECB') {
        // EcoCoreBits
        const { rows } = await client.query(
          'SELECT balance FROM ecorebits_users WHERE user_id = $1 FOR UPDATE',
          [opUserId]
        );
        if (rows.length === 0) {
          await client.query('ROLLBACK');
          return res.status(404).json({ error: 'Usuario de EcoConsole no encontrado' });
        }
        const currentBalance = rows[0].balance || 0;
        if (currentBalance < cost) {
          await client.query('ROLLBACK');
          return res.status(400).json({ error: 'Saldo insuficiente' });
        }
        await client.query(
          'UPDATE ecorebits_users SET balance = balance - $1 WHERE user_id = $2',
          [cost, opUserId]
        );
        if (hasMonedaColumn) {
          await client.query(
            'INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda) VALUES ($1, $2, $3, $4, $5)',
            [opUserId, `Recarga OceanicEthernet: ${amount} GB`, -cost, 'OceanicEthernet', 'ECB']
          );
        } else {
          await client.query(
            'INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen) VALUES ($1, $2, $3, $4)',
            [opUserId, `Recarga OceanicEthernet: ${amount} GB`, -cost, 'OceanicEthernet']
          );
        }
        paymentSuccess = true;
      } else if (currency === 'WC') {
        // WildCredits
        const { rows } = await client.query(
          'SELECT value FROM ocean_pay_metadata WHERE user_id = $1 AND key = $2 FOR UPDATE',
          [opUserId, 'wildcredits']
        );
        const currentBalance = rows.length > 0 ? parseInt(rows[0].value || '0') : 0;
        if (currentBalance < cost) {
          await client.query('ROLLBACK');
          return res.status(400).json({ error: 'Saldo insuficiente' });
        }
        const newBalance = currentBalance - cost;
        if (rows.length > 0) {
          await client.query(
            'UPDATE ocean_pay_metadata SET value = $1 WHERE user_id = $2 AND key = $3',
            [newBalance.toString(), opUserId, 'wildcredits']
          );
        } else {
          await client.query(
            'INSERT INTO ocean_pay_metadata (user_id, key, value) VALUES ($1, $2, $3)',
            [opUserId, 'wildcredits', newBalance.toString()]
          );
        }
        if (hasMonedaColumn) {
          await client.query(
            'INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda) VALUES ($1, $2, $3, $4, $5)',
            [opUserId, `Recarga OceanicEthernet: ${amount} GB`, -finalWcCost, 'OceanicEthernet', 'WC']
          );
        } else {
          await client.query(
            'INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen) VALUES ($1, $2, $3, $4)',
            [opUserId, `Recarga OceanicEthernet: ${amount} GB`, -finalWcCost, 'OceanicEthernet']
          );
        }
        paymentSuccess = true;
      } else if (currency === 'WG') {
        // WildGems (verificar si es INTEGER)
        const { rows } = await client.query(
          'SELECT wildgems FROM wildshorts_users WHERE user_id = $1 FOR UPDATE',
          [opUserId]
        );
        if (rows.length === 0) {
          await client.query('ROLLBACK');
          return res.status(404).json({ error: 'Usuario de WildShorts no encontrado' });
        }
        // Redondear el costo para WildGems (probablemente INTEGER)
        const wgRoundedCost = Math.round(cost);
        const finalWgCost = wgRoundedCost <= 0 && cost > 0 ? 1 : wgRoundedCost;
        const currentBalance = rows[0].wildgems || 0;
        if (currentBalance < finalWgCost) {
          await client.query('ROLLBACK');
          return res.status(400).json({ error: 'Saldo insuficiente' });
        }
        await client.query(
          'UPDATE wildshorts_users SET wildgems = wildgems - $1 WHERE user_id = $2',
          [finalWgCost, opUserId]
        );
        if (hasMonedaColumn) {
          await client.query(
            'INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda) VALUES ($1, $2, $3, $4, $5)',
            [opUserId, `Recarga OceanicEthernet: ${amount} GB`, -finalWgCost, 'OceanicEthernet', 'WG']
          );
        } else {
          await client.query(
            'INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen) VALUES ($1, $2, $3, $4)',
            [opUserId, `Recarga OceanicEthernet: ${amount} GB`, -finalWgCost, 'OceanicEthernet']
          );
        }
        paymentSuccess = true;
      }

      if (!paymentSuccess) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Divisa no vÃƒÂ¡lida' });
      }
    }

    // Obtener balance actual de internet
    // IMPORTANTE: Siempre usar el userId de OceanicEthernet para el saldo de internet
    // El saldo de internet es especÃƒÂ­fico de cada cuenta de OceanicEthernet
    // Solo usamos opUserId para procesar el pago desde Ocean Pay, pero el saldo se aplica a la cuenta de OceanicEthernet
    const internetUserId = userId; // Siempre usar el ID de OceanicEthernet para el saldo de internet

    const { rows: metaRows } = await client.query(`
      SELECT value FROM ocean_pay_metadata
      WHERE user_id = $1 AND key = 'internet_gb'
      FOR UPDATE
    `, [internetUserId]);

    const currentBalance = metaRows.length > 0 ? parseFloat(metaRows[0].value || '0') : 0;
    const newBalance = currentBalance + amount;

    // Actualizar o insertar balance
    if (metaRows.length > 0) {
      await client.query(`
        UPDATE ocean_pay_metadata
        SET value = $1
        WHERE user_id = $2 AND key = 'internet_gb'
      `, [newBalance.toString(), internetUserId]);
    } else {
      await client.query(`
        INSERT INTO ocean_pay_metadata (user_id, key, value)
        VALUES ($1, 'internet_gb', $2)
      `, [internetUserId, newBalance.toString()]);
    }

    // Registrar transacciÃƒÂ³n en tabla propia de OceanicEthernet (usar userId de OceanicEthernet para el historial)
    const concepto = currency
      ? `Recarga de ${amount} GB (Pagado con ${currencyNames[currency] || currency})`
      : `Recarga de ${amount} GB`;
    await client.query(
      `INSERT INTO oceanic_ethernet_txs (user_id, concepto, monto, origen)
       VALUES ($1, $2, $3, $4)`,
      [userId, concepto, amount, 'OceanicEthernet']
    );

    await client.query('COMMIT');
    res.json({ success: true, newBalance });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Ã¢ÂÅ’ Error en /oceanic-ethernet/recharge:', err);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

// Consumir internet (para usar desde otros proyectos)
app.post('/oceanic-ethernet/consume', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.substring(7);
  let userId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    userId = (decoded.id || decoded.uid);
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }

  const { userId: bodyUserId, amount, concepto = 'Uso de internet', origen = 'AllApp' } = req.body;

  if (!bodyUserId || amount === undefined || amount <= 0) {
    return res.status(400).json({ error: 'Datos invÃƒÂ¡lidos' });
  }

  if (userId !== parseInt(bodyUserId)) {
    return res.status(403).json({ error: 'No autorizado' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Obtener balance actual (inicializar si no existe para usuarios de Ocean Pay)
    const { rows: metaRows } = await client.query(`
      SELECT value FROM ocean_pay_metadata
      WHERE user_id = $1 AND key = 'internet_gb'
      FOR UPDATE
    `, [userId]);

    let currentBalance;
    if (metaRows.length > 0) {
      currentBalance = parseFloat(metaRows[0].value || '0');
    } else {
      // Si no existe, inicializar en 0 para usuarios de Ocean Pay
      await client.query(`
        INSERT INTO ocean_pay_metadata (user_id, key, value)
        VALUES ($1, 'internet_gb', '0')
        ON CONFLICT (user_id, key) DO NOTHING
      `, [userId]);
      currentBalance = 0;
    }

    const newBalance = currentBalance - amount;

    if (newBalance < 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Saldo insuficiente' });
    }

    // Actualizar balance
    await client.query(`
      UPDATE ocean_pay_metadata
      SET value = $1
      WHERE user_id = $2 AND key = 'internet_gb'
    `, [newBalance.toString(), userId]);

    // Registrar transacciÃƒÂ³n en tabla propia de OceanicEthernet
    await client.query(
      `INSERT INTO oceanic_ethernet_txs (user_id, concepto, monto, origen)
       VALUES ($1, $2, $3, $4)`,
      [userId, concepto, -amount, origen]
    );

    await client.query('COMMIT');
    res.json({ success: true, newBalance });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Ã¢ÂÅ’ Error en /oceanic-ethernet/consume:', err);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

// Obtener transacciones de internet
app.get('/oceanic-ethernet/transactions/:userId', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.substring(7);
  let userId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    userId = (decoded.id || decoded.uid);
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }

  const { userId: paramUserId } = req.params;
  const paramUserIdNum = parseInt(paramUserId);

  if (userId !== paramUserIdNum) {
    return res.status(403).json({ error: 'No autorizado' });
  }

  try {
    // Obtener transacciones de la tabla propia de OceanicEthernet
    const { rows } = await pool.query(`
      SELECT concepto, monto as amount, origen, created_at
      FROM oceanic_ethernet_txs
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT 50
    `, [userId]);

    res.json(rows);
  } catch (err) {
    console.error('Ã¢ÂÅ’ Error en /oceanic-ethernet/transactions/:userId', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Obtener historial reciente (ÃƒÂºltimo minuto) para tiempo real
app.get('/oceanic-ethernet/recent/:userId', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.substring(7);
  let userId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    userId = (decoded.id || decoded.uid);
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }

  const { userId: paramUserId } = req.params;
  const paramUserIdNum = parseInt(paramUserId);

  if (userId !== paramUserIdNum) {
    return res.status(403).json({ error: 'No autorizado' });
  }

  try {
    // Obtener transacciones de los ÃƒÂºltimos 60 segundos de la tabla propia
    const { rows } = await pool.query(`
      SELECT concepto, monto as amount, origen, created_at
      FROM oceanic_ethernet_txs
      WHERE user_id = $1 
        AND created_at > NOW() - INTERVAL '1 minute'
      ORDER BY created_at DESC
    `, [userId]);

    res.json(rows);
  } catch (err) {
    console.error('Ã¢ÂÅ’ Error en /oceanic-ethernet/recent/:userId', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/api/report-error', async (req, res) => {
  const { userId, type, description, extensions, userAgent, url, timestamp } = req.body;
  if (!type || !description) return res.status(400).json({ error: 'Faltan campos' });

  try {
    await pool.query(
      `INSERT INTO error_reports (user_id, type, description, extensions, user_agent, url, created_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [userId, type, description, extensions, userAgent, url, timestamp]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error('Ã¢ÂÅ’ report-error', e);
    res.status(500).json({ error: 'No se pudo guardar' });
  }
});

app.get('/admin/error-reports', async (req, res) => {
  const secret = req.headers['x-admin-secret'];
  if (secret !== (process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret')) return res.status(401).json({ error: 'No autorizado' });

  const { rows } = await pool.query(
    'SELECT id,user_id,type,description,extensions,created_at FROM error_reports ORDER BY created_at DESC LIMIT 200'
  );
  res.json(rows);
});

// GET /api/extensions/categories/:userId
app.get('/api/extensions/categories/:userId', async (req, res) => {
  const { userId } = req.params;
  const { rows } = await pool.query(
    'SELECT categories FROM user_categories WHERE user_id = $1',
    [userId]
  );
  res.json(rows[0]?.categories || {});
});

// POST /api/extensions/categories/:userId
app.post('/api/extensions/categories/:userId', async (req, res) => {
  const { userId } = req.params;
  const { categories } = req.body; // { catId: { name, color, items[] } }
  await pool.query(
    `INSERT INTO user_categories (user_id, categories)
     VALUES ($1, $2)
     ON CONFLICT (user_id) DO UPDATE SET categories = $2`,
    [userId, JSON.stringify(categories)]
  );
  res.json({ success: true });
});

// GET /api/events/active
app.get("/api/events/active", async (_req, res) => {
  // GET /api/events/active
  const now = new Date();
  const { rows } = await pool.query(
    `SELECT id,
          name,
          keyword,
          emoji,
          banner_color,
          description,
          startat,
          endat,
          rewardbits
   FROM events
   WHERE startat <= $1
     AND endat   >= $1
     AND finished = false
   ORDER BY startat DESC
   LIMIT 1`,
    [now]
  );
  if (!rows.length) return res.json(null);

  // Campos opcionales con fallback
  const ev = rows[0];
  res.json({
    id: ev.id,
    keyword: ev.keyword,
    name: ev.name,
    emoji: ev.emoji || 'Ã°Å¸Å½Â',
    bannerColor: ev.banner_color || 'linear-gradient(90deg,#64a7ff,#b388ff)',
    description: ev.description || 'Reclama tu recompensa diaria.',
    rewardBits: ev.rewardbits || 100,
    endAt: ev.endat
  });
  res.json(rows[0] || null);
});

// POST /api/events/claim
app.post("/api/events/claim", async (req, res) => {
  const { userId, eventId } = req.body;
  if (!userId || !eventId) return res.status(400).json({ error: "Faltan datos" });

  const event = await pool.query(
    `SELECT * FROM events WHERE id = $1 AND finished = false`,
    [eventId]
  );
  if (event.rows.length === 0) return res.status(404).json({ error: "Evento no encontrado" });

  const ev = event.rows[0];
  const { rows } = await pool.query(
    `SELECT * FROM user_events WHERE user_id = $1 AND event_id = $2`,
    [userId, eventId]
  );

  let day = 1;
  let lastClaim = null;
  if (rows.length > 0) {
    day = rows[0].day + 1;
    lastClaim = new Date(rows[0].last_claim);
    const now = new Date();
    const diffDays = Math.floor((now - lastClaim) / (1000 * 60 * 60 * 24));
    if (diffDays < 1) return res.status(429).json({ error: "Ya reclamaste hoy" });
    if (day > 7) return res.json({ error: "Evento completado", completed: true });
  }

  // Recompensa diaria
  const reward = day === 7 ? "extension" : "ecoxionums";
  const amount = day === 7 ? 0 : 500 + (day * 50); // 550, 600, 650...

  if (reward === "ecoxionums") {
    await pool.query(
      `UPDATE users SET balance = balance + $1 WHERE id = $2`,
      [amount, userId]
    );
  }

  // Guardar progreso
  await pool.query(
    `INSERT INTO user_events (user_id, event_id, day, last_claim, completed)
     VALUES ($1, $2, $3, NOW(), $4)
     ON CONFLICT (user_id, event_id)
     DO UPDATE SET day = $3, last_claim = NOW(), completed = $4`,
    [userId, eventId, day, day === 7]
  );

  // Entregar extensiÃƒÂ³n dÃƒÂ­a 7
  if (day === 7) {
    const state = await loadState(userId);
    state.installed["halloween-2025"] = {
      id: "halloween-2025",
      enabled: true,
      version: "1.0.0"
    };
    await saveState(state);
  }

  res.json({ success: true, day, reward, amount });
});

// GET /api/events/claim-status/:userId
app.get('/api/events/claim-status/:userId', async (req, res) => {
  const { userId } = req.params;

  // 1. Ã‚Â¿Hay evento activo?
  const now = new Date();
  const { rows } = await pool.query(
    `SELECT id, keyword, startat, endat
     FROM events
     WHERE startat <= $1
       AND endat   >= $1
       AND finished = false
     ORDER BY startat DESC
     LIMIT 1`,
    [now]
  );
  if (!rows.length) return res.json({ day: 0, completed: true }); // sin evento

  const event = rows[0];

  // Ã°Å¸â€¢â€œ PrÃƒÂ³ximo reinicio diario (medianoche UTC o local)
  const nextReset = new Date(now);
  nextReset.setUTCHours(24, 0, 0, 0); // medianoche UTC siguiente dÃƒÂ­a
  const msLeft = Math.max(0, nextReset - now);

  // 2. Ã‚Â¿CuÃƒÂ¡ntos dÃƒÂ­as ha reclamado este usuario?
  const { rows: userRows } = await pool.query(
    `SELECT COUNT(*) AS claimed
     FROM user_events
     WHERE user_id = $1
       AND event_id = $2`,
    [userId, event.id]
  );
  const claimed = parseInt(userRows[0].claimed, 10);
  const day = claimed + 1;
  const completed = claimed >= 7;

  res.json({
    day,
    completed,
    nextReset: nextReset.toISOString(),
    msLeft
  });
});

app.get('/api/ecorebits/user', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    const usernameToken = decoded.un || decoded.username;
    if (!usernameToken) return res.status(401).json({ message: 'Token invÃƒÂ¡lido' });

    // BUSCAR ID BANCARIO REAL POR NOMBRE (Evita errores de ID cruzados)
    const { rows: userRows } = await pool.query(
      'SELECT id, username FROM ocean_pay_users WHERE LOWER(username) = LOWER($1)',
      [usernameToken]
    );

    if (userRows.length === 0) return res.status(404).json({ message: 'Usuario bancario no encontrado' });

    const userId = userRows[0].id;
    const userData = userRows[0];

    // 1. Asegurar que el usuario tenga al menos una tarjeta vinculada
    const { rows: existingCards } = await pool.query('SELECT id FROM ocean_pay_cards WHERE user_id = $1', [userId]);
    if (existingCards.length === 0) {
      const { cardNumber, cvv, expiryDate } = generateCardDetails ? generateCardDetails() : { cardNumber: '4000' + Math.random().toString().slice(2, 14), cvv: '123', expiryDate: '12/28' };
      await pool.query(
        'INSERT INTO ocean_pay_cards (user_id, card_number, cvv, expiry_date, is_primary, card_name) VALUES ($1, $2, $3, $4, true, $5)',
        [userId, cardNumber, cvv, expiryDate, 'Tarjeta Principal']
      );
    } else {
      // Asegurar que al menos una sea primaria
      await pool.query(`
        UPDATE ocean_pay_cards SET is_primary = true 
        WHERE id = (SELECT MIN(id) FROM ocean_pay_cards WHERE user_id = $1)
        AND NOT EXISTS (SELECT 1 FROM ocean_pay_cards WHERE user_id = $1 AND is_primary = true)
      `, [userId]);
    }

    // 2. SincronizaciÃƒÂ³n robusta de saldos legacy (Cruce por Nombre de Usuario)
    await pool.query(`
      INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount)
      SELECT c.id, 'ecorebits', MAX(uc.amount)
      FROM ocean_pay_cards c
      JOIN ocean_pay_users opu ON c.user_id = opu.id
      JOIN users u ON LOWER(u.username) = LOWER(opu.username)
      JOIN user_currency uc ON uc.user_id = u.id AND uc.currency_type = 'ecocorebits'
      WHERE opu.id = $1 AND c.is_primary = true AND uc.amount > 0
      GROUP BY c.id
      ON CONFLICT (card_id, currency_type) DO UPDATE SET amount = EXCLUDED.amount WHERE ocean_pay_card_balances.amount = 0
    `, [userId]).catch((e) => { console.error('Migration error:', e.message); });

    // Obtener tarjetas y sus balances (NUEVO SISTEMA)
    const { rows: cardRows } = await pool.query(
      `SELECT id, card_number, cvv, expiry_date, is_active, is_primary, card_name
       FROM ocean_pay_cards WHERE user_id = $1`,
      [userId]
    );

    const cards = await Promise.all(cardRows.map(async (card) => {
      const { rows: balRows } = await pool.query(
        'SELECT currency_type, amount FROM ocean_pay_card_balances WHERE card_id = $1',
        [card.id]
      );
      const balances = {};
      balRows.forEach(b => balances[b.currency_type] = parseFloat(b.amount));
      return { ...card, balances };
    }));

    // CALCULAR BALANCE TOTAL (Sumatoria de todas las tarjetas para vista global en EcoConsole)
    const totalEcorebits = cards.reduce((sum, card) => sum + parseFloat(card.balances?.ecorebits || 0), 0);
    const primaryCard = cards.find(c => c.is_primary) || cards[0];

    res.json({
      success: true,
      debug: {
        cardCount: cards.length,
        primaryCardId: primaryCard?.id || null,
        totalBalance: totalEcorebits
      },
      user: {
        id: userData.id,
        username: userData.username,
        cards: cards,
        ecorebits: {
          balance: parseFloat(totalEcorebits || 0)
        }
      }
    });

  } catch (error) {
    console.error('Error in /api/ecorebits/user:', error);
    res.status(500).json({
      success: false,
      message: 'Error del servidor',
      details: error.message
    });
  }
});

// Add this middleware for token authentication
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.STUDIO_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Add this endpoint to handle limit extensions
app.post('/api/extend-limit', async (req, res) => {
  try {
    const { option } = req.body;
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'No autorizado' });
    }

    // Verify token and get user
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    // Asegurar que userId sea un nÃƒÂºmero (el id de ocean_pay_users es INTEGER)
    const rawId = (decoded.id || decoded.uid) || decoded.userId || decoded.id || decoded.user?.id;
    const userId = parseInt(rawId);

    if (!userId || isNaN(userId)) {
      console.error('Token decodificado:', decoded);
      return res.status(401).json({ error: 'Token invÃƒÂ¡lido: falta userId. Campos disponibles: ' + Object.keys(decoded).join(', ') });
    }

    // Verificar que el usuario existe - Buscar en ambas tablas
    let userCheck = await pool.query(
      'SELECT id FROM users WHERE id = $1',
      [userId]
    );

    if (userCheck.rows.length === 0) {
      userCheck = await pool.query(
        'SELECT id FROM ocean_pay_users WHERE id = $1',
        [userId]
      );
    }

    if (userCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    let result = {};
    const now = new Date();

    if (option === 'ecocorebits') {
      // Obtener saldo de EcoCoreBits desde user_currency
      const { rows: ecorebitsRows } = await pool.query(
        `SELECT amount FROM user_currency 
                 WHERE user_id = $1 AND currency_type = 'ecocorebits' FOR UPDATE`,
        [userId]
      );

      const currentBalance = ecorebitsRows[0]?.amount || 0;

      // Check if user has enough EcoCoreBits
      if (currentBalance < 100) {
        return res.status(400).json({
          error: 'No tienes suficientes EcoCoreBits'
        });
      }

      // Deduct EcoCoreBits (actualizar o crear en user_currency)
      const newBalance = currentBalance - 100;
      await pool.query(
        `INSERT INTO user_currency (user_id, currency_type, amount)
                 VALUES ($1, 'ecocorebits', $2)
                 ON CONFLICT (user_id, currency_type)
                 DO UPDATE SET amount = EXCLUDED.amount`,
        [userId, newBalance]
      );

      // Incrementar command limit en el estado local (se guarda en localStorage)
      result = {
        success: true,
        newLimit: null,
        ecocorebits: newBalance
      };

    } else if (option === 'ecocorebits_large') {
      // Super Boost: 350 ECB -> +50 comandos
      const { rows: ecorebitsRows } = await pool.query(
        `SELECT amount FROM user_currency 
                 WHERE user_id = $1 AND currency_type = 'ecocorebits' FOR UPDATE`,
        [userId]
      );

      const currentBalance = ecorebitsRows[0]?.amount || 0;
      if (currentBalance < 350) {
        return res.status(400).json({ error: 'No tienes suficientes EcoCoreBits' });
      }

      const newBalance = currentBalance - 350;
      await pool.query(
        `INSERT INTO user_currency (user_id, currency_type, amount)
                 VALUES ($1, 'ecocorebits', $2)
                 ON CONFLICT (user_id, currency_type)
                 DO UPDATE SET amount = EXCLUDED.amount`,
        [userId, newBalance]
      );

      result = {
        success: true,
        newBalance: newBalance,
        ecocorebits: newBalance
      };

    } else if (option === 'credits') {
      // Obtener crÃƒÂ©ditos desde ecocore_credits
      const { rows: creditsRows } = await pool.query(
        'SELECT credits FROM ecocore_credits WHERE user_id = $1 FOR UPDATE',
        [userId]
      );

      let currentCredits = 0;
      if (creditsRows.length === 0) {
        // Crear registro si no existe
        await pool.query(
          'INSERT INTO ecocore_credits (user_id, credits) VALUES ($1, 0)',
          [userId]
        );
      } else {
        currentCredits = creditsRows[0].credits || 0;
      }

      // Check if user has enough credits
      if (currentCredits < 1) {
        return res.status(400).json({
          error: 'No tienes suficientes crÃƒÂ©ditos'
        });
      }

      // Deduct credits
      const newCredits = currentCredits - 1;
      await pool.query(
        'UPDATE ecocore_credits SET credits = $1, updated_at = NOW() WHERE user_id = $2',
        [newCredits, userId]
      );

      result = {
        success: true,
        newLimit: null, // Se calcularÃƒÂ¡ en el frontend
        credits: newCredits
      };

    } else {
      return res.status(400).json({ error: 'OpciÃƒÂ³n no vÃƒÂ¡lida' });
    }

    // Log the transaction (asegurar que userId es string)
    await pool.query(
      `INSERT INTO command_limit_extensions 
             (user_id, extension_type, commands_added, cost, extended_at)
             VALUES ($1, $2, $3, $4, $5)`,
      [
        Number(userId),
        option,
        option === 'ecocorebits' ? 10 : (option === 'ecocorebits_large' ? 50 : 5),
        option === 'ecocorebits' ? 100 : (option === 'ecocorebits_large' ? 350 : 1),
        now
      ]
    );

    res.json(result);

  } catch (error) {
    console.error('Error extending command limit:', error);

    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
    }

    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'SesiÃƒÂ³n expirada' });
    }

    res.status(500).json({
      error: 'Error al procesar la solicitud',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/* ---------- ADMIN: listar usuarios ---------- */
app.get('/admin/users', async (req, res) => {
  const secret = req.headers['x-admin-secret'];
  if (secret !== (process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret')) {
    return res.status(401).json({ error: 'No autorizado' });
  }

  try {
    const { rows } = await pool.query(`
      SELECT id, username, created_at
      FROM users_nat
      ORDER BY created_at DESC
    `);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// === FUNCIONES DE REVISIÃƒâ€œN ===
async function ensureDatabase() {
  try {
    // Intentar conectar a la base de datos
    await pool.query("SELECT 1");
    console.log("Ã¢Å“â€¦ ConexiÃƒÂ³n a la base de datos OK");
  } catch (err) {
    console.error("Ã¢ÂÅ’ La base de datos no existe o no se puede conectar:", err.message);
    process.exit(1); // Terminar servidor si falla
  }
}

async function ensureTables() {
  const tableQueries = [
    // Ã°Å¸â€â€˜ TABLA FALTANTE 1: updates_ecoconsole (Ahora deberÃƒÂ­a crearse)
    `CREATE TABLE IF NOT EXISTS updates_ecoconsole (
      id SERIAL PRIMARY KEY,
      version TEXT NOT NULL,
      news TEXT,
      date TIMESTAMP NOT NULL DEFAULT NOW()
    );`,
    // Otras tablas de actualizaciones/sugerencias
    `CREATE TABLE IF NOT EXISTS updates (
      id SERIAL PRIMARY KEY,
      version TEXT NOT NULL,
      news TEXT,
      date TIMESTAMP NOT NULL DEFAULT NOW()
    );`,
    `CREATE TABLE IF NOT EXISTS suggestions (
      id SERIAL PRIMARY KEY,
      userId TEXT NOT NULL,
      text TEXT NOT NULL,
      date TIMESTAMP NOT NULL DEFAULT NOW()
    );`,
    `CREATE TABLE IF NOT EXISTS events (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      keyword TEXT NOT NULL,
      musicURL TEXT,
      startAt TIMESTAMP NOT NULL,
      rewardBits INTEGER DEFAULT 100,
      created TIMESTAMP NOT NULL DEFAULT NOW(),
      finished BOOLEAN DEFAULT FALSE
    );
    
    -- BLOQUE DE USUARIOS PRINCIPALES (INTEGER Y TEXT)
    CREATE TABLE IF NOT EXISTS users_nat ( 
        id SERIAL PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY, 
      username VARCHAR(100) UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS ocean_pay_users (
      id            SERIAL PRIMARY KEY,
      username      VARCHAR(60) UNIQUE NOT NULL,
      pwd_hash      TEXT NOT NULL,
      aquabux       INTEGER DEFAULT 0,
      appbux        INTEGER DEFAULT 0,
      created_at    TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS oceanic_ethernet_users (
      id            SERIAL PRIMARY KEY,
      username      VARCHAR(60) UNIQUE NOT NULL,
      pwd_hash      TEXT NOT NULL,
      created_at    TIMESTAMP DEFAULT NOW()
    );
    
    -- ocean_pay_metadata: Se define con user_id para instalaciones nuevas
    CREATE TABLE IF NOT EXISTS ocean_pay_metadata (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES ocean_pay_users(id) ON DELETE CASCADE, 
        key TEXT NOT NULL, 
        value TEXT NOT NULL,
        CONSTRAINT unique_user_key UNIQUE (user_id, key)
    );

    -- BLOQUE DE ENTIDADES NAT-MARKET (Referencian users_nat)
    CREATE TABLE IF NOT EXISTS products_nat (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users_nat(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        description TEXT,
        price DECIMAL,
        image_url TEXT,
        contact_number TEXT,
        created_at TIMESTAMP DEFAULT now()
    );
    
    CREATE TABLE IF NOT EXISTS user_ratings_nat (
        id SERIAL PRIMARY KEY,
        rated_user_id INTEGER NOT NULL REFERENCES users_nat(id) ON DELETE CASCADE,
        rater_user_id INTEGER NOT NULL REFERENCES users_nat(id) ON DELETE CASCADE,
        rating INT CHECK (rating BETWEEN 1 AND 5),
        product_id INTEGER REFERENCES products_nat(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT now(),
        CONSTRAINT unique_rating UNIQUE (rated_user_id, rater_user_id, product_id)
    );

    CREATE TABLE IF NOT EXISTS messages_nat (
        id SERIAL PRIMARY KEY,
        sender_id INTEGER NOT NULL REFERENCES users_nat(id) ON DELETE CASCADE,
        product_id INTEGER NOT NULL REFERENCES products_nat(id) ON DELETE CASCADE,
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS user_wishlist_nat (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users_nat(id) ON DELETE CASCADE,
        product_id INTEGER NOT NULL REFERENCES products_nat(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT NOW(),
        CONSTRAINT unique_wishlist_item UNIQUE (user_id, product_id)
    );

    CREATE TABLE IF NOT EXISTS user_favorites_nat (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users_nat(id) ON DELETE CASCADE,
        product_id INTEGER NOT NULL REFERENCES products_nat(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT NOW(),
        CONSTRAINT unique_favorite_item UNIQUE (user_id, product_id)
    );
    
    -- BLOQUE DE OTRAS ENTIDADES (Referencian users - TEXT ID y oceanic_ethernet_users)
    CREATE TABLE IF NOT EXISTS oceanic_ethernet_txs (
      id            SERIAL PRIMARY KEY,
      user_id       INTEGER NOT NULL REFERENCES oceanic_ethernet_users(id) ON DELETE CASCADE,
      concepto      TEXT NOT NULL,
      monto         NUMERIC(20, 15) NOT NULL,
      origen        VARCHAR(50) DEFAULT 'OceanicEthernet',
      created_at    TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS oceanic_ethernet_user_links (
      id            SERIAL PRIMARY KEY,
      oe_user_id    INTEGER NOT NULL REFERENCES oceanic_ethernet_users(id) ON DELETE CASCADE,
      external_user_id TEXT NOT NULL, 
      external_system VARCHAR(50) NOT NULL,
      created_at    TIMESTAMP DEFAULT NOW(),
      UNIQUE(external_user_id, external_system)
    );

    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      user_id TEXT REFERENCES users(id) ON DELETE CASCADE, 
      name TEXT NOT NULL,
      description TEXT,
      price DECIMAL,
      image_url TEXT,
      contact_number TEXT,
      created_at TIMESTAMP DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS user_ratings (
      id SERIAL PRIMARY KEY,
      rated_user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
      rater_user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
      rating INT CHECK (rating BETWEEN 1 AND 5),
      created_at TIMESTAMP DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      sender_id TEXT REFERENCES users(id) ON DELETE CASCADE,
      product_id INT REFERENCES products(id) ON DELETE CASCADE,
      message TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS product_images (
      id SERIAL PRIMARY KEY,
      product_id INT REFERENCES products(id) ON DELETE CASCADE,
      url TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS companies_nat (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      industry TEXT,
      type TEXT,
      email TEXT,
      phone TEXT,
      address TEXT,
      description TEXT,
      logo_url TEXT,
      source TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS tigertasks_backups (
      user_id TEXT PRIMARY KEY,
      backup_data JSONB NOT NULL,
      updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS command_limit_extensions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES ocean_pay_users(id) ON DELETE CASCADE, 
      extension_type VARCHAR(20) NOT NULL,
      commands_added INTEGER NOT NULL,
      cost INTEGER NOT NULL,
      extended_at TIMESTAMP WITH TIME ZONE NOT NULL,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS notifications_nat (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users_nat(id) ON DELETE CASCADE,
      type VARCHAR(50) NOT NULL DEFAULT 'message',
      message TEXT NOT NULL,
      product_id INTEGER REFERENCES products_nat(id) ON DELETE CASCADE,
      sender_id INTEGER REFERENCES users_nat(id) ON DELETE CASCADE,
      read BOOLEAN DEFAULT false,
      created_at TIMESTAMP DEFAULT NOW()
    );
    
    -- Crear tabla de reportes
    CREATE TABLE IF NOT EXISTS product_reports (
      id SERIAL PRIMARY KEY,
      product_id INTEGER NOT NULL REFERENCES products_nat(id) ON DELETE CASCADE,
      reporter_id INTEGER NOT NULL REFERENCES users_nat(id) ON DELETE CASCADE,
      reason TEXT NOT NULL,
      status VARCHAR(20) DEFAULT 'pending', 
      admin_id INTEGER REFERENCES users_nat(id) ON DELETE SET NULL,
      admin_response TEXT,
      created_at TIMESTAMP DEFAULT NOW(),
      reviewed_at TIMESTAMP
    );
    
    CREATE INDEX IF NOT EXISTS idx_product_reports_status ON product_reports(status);
    CREATE INDEX IF NOT EXISTS idx_product_reports_product ON product_reports(product_id);
    
    -- Crear tabla de vistas ÃƒÂºnicas por usuario y producto
    CREATE TABLE IF NOT EXISTS product_views_unique (
      id SERIAL PRIMARY KEY,
      user_id VARCHAR(255) NOT NULL,
      product_id INTEGER NOT NULL REFERENCES products_nat(id) ON DELETE CASCADE,
      created_at TIMESTAMP DEFAULT NOW(),
      CONSTRAINT unique_user_product_view UNIQUE(user_id, product_id)
    );
    
    -- Crear tabla de seguidores
    CREATE TABLE IF NOT EXISTS user_follows (
      id SERIAL PRIMARY KEY,
      follower_id INTEGER NOT NULL REFERENCES users_nat(id) ON DELETE CASCADE,
      following_id INTEGER NOT NULL REFERENCES users_nat(id) ON DELETE CASCADE,
      created_at TIMESTAMP DEFAULT NOW(),
      CONSTRAINT unique_follow UNIQUE(follower_id, following_id),
      CONSTRAINT no_self_follow CHECK (follower_id != following_id)
    );
    
    -- Crear tabla de suscripciones de Ecoxion
    CREATE TABLE IF NOT EXISTS ecoxion_subscriptions (
      id SERIAL PRIMARY KEY,
      user_id TEXT NOT NULL,
      plan TEXT NOT NULL DEFAULT 'free',
      starts_at TIMESTAMP NOT NULL DEFAULT NOW(),
      ends_at TIMESTAMP NOT NULL,
      active BOOLEAN DEFAULT true,
      created_at TIMESTAMP DEFAULT NOW()
    );
    
    -- Crear ÃƒÂ­ndice para bÃƒÂºsquedas rÃƒÂ¡pidas
    CREATE INDEX IF NOT EXISTS idx_ecoxion_subs_user_active ON ecoxion_subscriptions(user_id, active, ends_at);
    
    -- Tabla de transacciones de Ocean Pay
    CREATE TABLE IF NOT EXISTS ocean_pay_txs (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      concepto TEXT NOT NULL,
      monto NUMERIC(20,2) NOT NULL,
      origen TEXT,
      created_at TIMESTAMP DEFAULT NOW(),
      moneda TEXT
    );
    
    -- Tabla de transacciones de EcoCoreBits
    CREATE TABLE IF NOT EXISTS ecocore_txs (
      id SERIAL PRIMARY KEY,
      user_id TEXT NOT NULL,
      concepto TEXT NOT NULL,
      monto NUMERIC(20,2) NOT NULL,
      origen TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
    
    -- Tabla de productos rechazados (NatMarket)
    CREATE TABLE IF NOT EXISTS products_rejected (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users_nat(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      reason TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
    
    -- Tabla de productos pendientes de moderaciÃƒÂ³n (NatMarket)
    CREATE TABLE IF NOT EXISTS products_pending (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users_nat(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      description TEXT,
      price DECIMAL,
      contact_number TEXT,
      places JSONB,
      methods JSONB,
      created_at TIMESTAMP DEFAULT NOW()
    );
    
    -- Tabla de mensajes pendientes de moderaciÃƒÂ³n (NatMarket)
    CREATE TABLE IF NOT EXISTS messages_pending (
      id SERIAL PRIMARY KEY,
      product_id INTEGER NOT NULL REFERENCES products_nat(id) ON DELETE CASCADE,
      sender_id INTEGER NOT NULL REFERENCES users_nat(id) ON DELETE CASCADE,
      message TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
    
    -- Tabla de mensajes rechazados (NatMarket)
    CREATE TABLE IF NOT EXISTS messages_rejected (
      id SERIAL PRIMARY KEY,
      sender_id INTEGER NOT NULL REFERENCES users_nat(id) ON DELETE CASCADE,
      product_id INTEGER NOT NULL REFERENCES products_nat(id) ON DELETE CASCADE,
      message TEXT NOT NULL,
      reason TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
    
    -- Tabla de lugares recurrentes (NatMarket)
    CREATE TABLE IF NOT EXISTS user_places (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users_nat(id) ON DELETE CASCADE,
      dept TEXT NOT NULL,
      street TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
    
    -- Tabla de mÃƒÂ©todos de envÃƒÂ­o recurrentes (NatMarket)
    CREATE TABLE IF NOT EXISTS user_shipping_methods (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users_nat(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
    
    -- Tablas de relaciÃƒÂ³n producto-lugar y producto-mÃƒÂ©todo (NatMarket)
    CREATE TABLE IF NOT EXISTS product_places (
      product_id INTEGER NOT NULL REFERENCES products_nat(id) ON DELETE CASCADE,
      place_id INTEGER NOT NULL REFERENCES user_places(id) ON DELETE CASCADE,
      PRIMARY KEY (product_id, place_id)
    );
    
    CREATE TABLE IF NOT EXISTS product_shipping_methods (
      product_id INTEGER NOT NULL REFERENCES products_nat(id) ON DELETE CASCADE,
      shipping_method_id INTEGER NOT NULL REFERENCES user_shipping_methods(id) ON DELETE CASCADE,
      PRIMARY KEY (product_id, shipping_method_id)
    );
    
    CREATE INDEX IF NOT EXISTS idx_ocean_pay_txs_user ON ocean_pay_txs(user_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_ecocore_txs_user ON ecocore_txs(user_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_products_rejected_user ON products_rejected(user_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_products_pending_user ON products_pending(user_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_messages_pending_product ON messages_pending(product_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_user_places_user ON user_places(user_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_user_shipping_methods_user ON user_shipping_methods(user_id, created_at DESC);
    `,
  ];

  // 1. Ejecutar la creaciÃƒÂ³n de todas las tablas
  for (const q of tableQueries) {
    try {
      await pool.query(q);
    } catch (error) {
      console.error(`Ã¢ÂÅ’ Error al ejecutar query de creaciÃƒÂ³n de tabla: ${q.substring(0, 50)}...`, error);
      // Lanzamos el error solo si es crÃƒÂ­tico para que las tablas no se creen
      throw error;
    }
  }

  // =========================================================
  // Ã°Å¸â€â€˜ MIGRACIÃƒâ€œN CRÃƒÂTICA ocean_pay_metadata (Paso a paso)
  // =========================================================

  try {
    // 1. Verificar y Agregar columna user_id
    const columnCheck = await pool.query(`
        SELECT 1 
        FROM information_schema.columns 
        WHERE table_name = 'ocean_pay_metadata' AND column_name = 'user_id'
    `);

    if (columnCheck.rows.length === 0) {
      console.log('Ã°Å¸â€â€ž Agregando columna user_id a ocean_pay_metadata...');
      await pool.query(`ALTER TABLE ocean_pay_metadata ADD COLUMN user_id INTEGER`);
      console.log('Ã¢Å“â€¦ Columna user_id agregada.');
    }

    // 2. Verificar y Agregar la llave forÃƒÂ¡nea
    const fkCheck = await pool.query(`
        SELECT 1 
        FROM pg_constraint 
        WHERE conrelid = 'ocean_pay_metadata'::regclass AND conname = 'ocean_pay_metadata_user_id_fkey'
    `);

    if (fkCheck.rows.length === 0) {
      console.log('Ã°Å¸â€â€ž Agregando FK a ocean_pay_metadata...');
      await pool.query(`
            ALTER TABLE ocean_pay_metadata 
            ADD CONSTRAINT ocean_pay_metadata_user_id_fkey 
            FOREIGN KEY (user_id) REFERENCES ocean_pay_users(id) ON DELETE CASCADE
        `);
      console.log('Ã¢Å“â€¦ FK ocean_pay_metadata_user_id_fkey agregada.');
    }

    // 3. Verificar y Agregar la restricciÃƒÂ³n UNIQUE
    const uniqueCheck = await pool.query(`
        SELECT 1 
        FROM pg_constraint 
        WHERE conrelid = 'ocean_pay_metadata'::regclass AND conname = 'unique_user_key'
    `);

    if (uniqueCheck.rows.length === 0) {
      console.log('Ã°Å¸â€â€ž Agregando restricciÃƒÂ³n UNIQUE a ocean_pay_metadata...');
      await pool.query(`
            ALTER TABLE ocean_pay_metadata 
            ADD CONSTRAINT unique_user_key UNIQUE (user_id, key)
        `);
      console.log('Ã¢Å“â€¦ RestricciÃƒÂ³n UNIQUE agregada.');
    }

    console.log('Ã¢Å“â€¦ MigraciÃƒÂ³n de ocean_pay_metadata ejecutada de forma secuencial.');
  } catch (err) {
    console.warn('Ã¢Å¡Â Ã¯Â¸Â Error al ejecutar migraciÃƒÂ³n secuencial de ocean_pay_metadata (puede ser un error menor si ya existe):', err.message);
  }

  // =========================================================
  // Bloque de migraciones restantes (Procedural SQL, ahora mÃƒÂ¡s aislado)
  // =========================================================

  // Agregar columna appbux a ocean_pay_users si no existe
  try {
    await pool.query(`
      DO $$ 
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'ocean_pay_users' AND column_name = 'appbux') THEN
          ALTER TABLE ocean_pay_users ADD COLUMN appbux INTEGER DEFAULT 0;
        END IF;
      END $$;
    `);
    console.log('Ã¢Å“â€¦ MigraciÃƒÂ³n de ocean_pay_users appbux ejecutada.');
  } catch (err) {
    console.warn('Ã¢Å¡Â Ã¯Â¸Â Error al ejecutar migraciÃƒÂ³n de ocean_pay_users appbux:', err.message);
  }

  // Agregar user_unique_id y unique_id_shown a users_nat si no existen
  try {
    await pool.query(`
      DO $$ 
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users_nat' AND column_name = 'user_unique_id') THEN
          ALTER TABLE users_nat ADD COLUMN user_unique_id VARCHAR(100) UNIQUE;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users_nat' AND column_name = 'unique_id_shown') THEN
          ALTER TABLE users_nat ADD COLUMN unique_id_shown BOOLEAN DEFAULT false;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users_nat' AND column_name = 'strikes') THEN
          ALTER TABLE users_nat ADD COLUMN strikes INTEGER DEFAULT 0;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users_nat' AND column_name = 'banned_until') THEN
          ALTER TABLE users_nat ADD COLUMN banned_until TIMESTAMP;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users_nat' AND column_name = 'ban_reason') THEN
          ALTER TABLE users_nat ADD COLUMN ban_reason TEXT;
        END IF;
      END $$;
    `);
    console.log('Ã¢Å“â€¦ MigraciÃƒÂ³n de users_nat columnas ejecutada.');
  } catch (err) {
    console.warn('Ã¢Å¡Â Ã¯Â¸Â Error al ejecutar migraciÃƒÂ³n de users_nat columnas:', err.message);
  }

  // Agregar columnas de stock y vendido a products_nat si no existen
  try {
    await pool.query(`
      DO $$ 
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'products_nat' AND column_name = 'stock') THEN
          ALTER TABLE products_nat ADD COLUMN stock INTEGER DEFAULT 1;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'products_nat' AND column_name = 'sold') THEN
          ALTER TABLE products_nat ADD COLUMN sold BOOLEAN DEFAULT false;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'products_nat' AND column_name = 'buyer_id') THEN
          ALTER TABLE products_nat ADD COLUMN buyer_id INTEGER REFERENCES users_nat(id) ON DELETE SET NULL;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'products_nat' AND column_name = 'published_at') THEN
          ALTER TABLE products_nat ADD COLUMN published_at TIMESTAMP DEFAULT now();
          -- Inicializar published_at con created_at para productos existentes
          UPDATE products_nat SET published_at = created_at WHERE published_at IS NULL;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'products_nat' AND column_name = 'category') THEN
          ALTER TABLE products_nat ADD COLUMN category VARCHAR(100);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'products_nat' AND column_name = 'status') THEN
          ALTER TABLE products_nat ADD COLUMN status VARCHAR(50) DEFAULT 'disponible';
        END IF;
      END $$;
    `);
    console.log('Ã¢Å“â€¦ MigraciÃƒÂ³n de products_nat columnas ejecutada.');
  } catch (err) {
    console.warn('Ã¢Å¡Â Ã¯Â¸Â Error al ejecutar migraciÃƒÂ³n de products_nat columnas:', err.message);
  }

  // MigraciÃƒÂ³n: Si la tabla command_limit_extensions existe con user_id TEXT, cambiarla a INTEGER (Ocean Pay Sync)
  try {
    const checkColumn = await pool.query(`
      SELECT data_type 
      FROM information_schema.columns 
      WHERE table_name = 'command_limit_extensions' 
      AND column_name = 'user_id'
    `);

    if (checkColumn.rows.length > 0 && checkColumn.rows[0].data_type === 'text') {
      console.log('Ã°Å¸â€â€ž Migrando command_limit_extensions: cambiando user_id de TEXT a INTEGER (Ocean Pay Sync)...');

      await pool.query(`
        ALTER TABLE command_limit_extensions 
        DROP CONSTRAINT IF EXISTS command_limit_extensions_user_id_fkey
      `).catch(() => { });

      await pool.query(`
        ALTER TABLE command_limit_extensions 
        ALTER COLUMN user_id TYPE INTEGER USING user_id::INTEGER
      `);

      await pool.query(`
        ALTER TABLE command_limit_extensions 
        ADD CONSTRAINT command_limit_extensions_user_id_fkey 
        FOREIGN KEY (user_id) REFERENCES ocean_pay_users(id) ON DELETE CASCADE
      `);

      console.log('Ã¢Å“â€¦ MigraciÃƒÂ³n completada: user_id ahora es INTEGER y apunta a ocean_pay_users');
    }
  } catch (err) {
    if (!err.message.includes('relation "command_limit_extensions" does not exist')) {
      console.warn('Ã¢Å¡Â Ã¯Â¸Â Error en migraciÃƒÂ³n de command_limit_extensions:', err.message);
    }
  }

  console.log("Ã¢Å“â€¦ Todas las tablas existen o fueron creadas");
}

function handleNatError(res, err, place = '') {
  console.error(`[NAT-MARKET ${place}]`, err?.message || err);

  // Detectar si el error es porque el usuario no existe (Foreign Key Violation)
  if (err?.code === '23503') {
    const detail = err.detail || '';
    // Si el error menciona user_id, sender_id, follower_id, etc. no presente en users_nat
    if (detail.includes('users_nat') || detail.includes('user_id') || detail.includes('sender_id')) {
      return res.status(401).json({
        error: 'Tu sesiÃƒÂ³n ha expirado o el usuario no existe. Por favor inicia sesiÃƒÂ³n nuevamente.',
        code: 'USER_NOT_FOUND'
      });
    }
  }

  res.status(500).json({ error: err?.message || String(err) });
}


// Add credits table to the database
await pool.query(`
  CREATE TABLE IF NOT EXISTS ecocore_credits (
    user_id TEXT PRIMARY KEY,
    credits INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
  )
`);

// Get user credits
app.get('/ecocore/credits/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const { rows } = await pool.query(
      'SELECT credits FROM ecocore_credits WHERE user_id = $1',
      [userId]
    );

    if (rows.length === 0) {
      // Initialize with 0 credits if user not found
      await pool.query(
        'INSERT INTO ecocore_credits (user_id, credits) VALUES ($1, 0) RETURNING credits',
        [userId]
      );
      return res.json({ credits: 0 });
    }

    res.json({ credits: rows[0].credits });
  } catch (error) {
    console.error('Error fetching credits:', error);
    res.status(500).json({ error: 'Failed to fetch credits' });
  }
});

// Update user credits
app.post('/ecocore/credits/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const { amount, operation = 'set' } = req.body; // operation can be 'set', 'add', or 'subtract'

    if (typeof amount !== 'number') {
      return res.status(400).json({ error: 'Invalid amount' });
    }

    let query = '';
    let params = [userId];

    if (operation === 'add') {
      query = `
        INSERT INTO ecocore_credits (user_id, credits)
        VALUES ($1, $2)
        ON CONFLICT (user_id)
        DO UPDATE SET credits = ecocore_credits.credits + EXCLUDED.credits, updated_at = NOW()
        RETURNING credits
      `;
      params.push(amount);
    } else if (operation === 'subtract') {
      // First check if user has enough credits
      const { rows } = await pool.query(
        'SELECT credits FROM ecocore_credits WHERE user_id = $1',
        [userId]
      );

      if (rows.length === 0 || rows[0].credits < amount) {
        return res.status(400).json({ error: 'Insufficient credits' });
      }

      query = `
        UPDATE ecocore_credits 
        SET credits = credits - $2, updated_at = NOW()
        WHERE user_id = $1
        RETURNING credits
      `;
      params.push(amount);
    } else {
      // Default to set operation
      query = `
        INSERT INTO ecocore_credits (user_id, credits)
        VALUES ($1, $2)
        ON CONFLICT (user_id)
        DO UPDATE SET credits = EXCLUDED.credits, updated_at = NOW()
        RETURNING credits
      `;
      params.push(amount);
    }

    const { rows } = await pool.query(query, params);
    res.json({ credits: rows[0].credits });
  } catch (error) {
    console.error('Error updating credits:', error);
    res.status(500).json({ error: 'Failed to update credits' });
  }
});

// Get user credits by user ID
app.get('/api/credits/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    const { rows } = await pool.query(
      'SELECT credits FROM ecocore_credits WHERE user_id = $1',
      [userId]
    );
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado o sin crÃƒÂ©ditos.' });
    }
    res.json({ credits: rows[0].credits });
  } catch (error) {
    console.error('Error fetching credits:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});


// Add credits table to the database
await pool.query(`
  CREATE TABLE IF NOT EXISTS ecocore_credits (
    user_id TEXT PRIMARY KEY,
    credits INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
  )
`);

// Get user credits
app.get('/ecocore/credits/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const { rows } = await pool.query(
      'SELECT credits FROM ecocore_credits WHERE user_id = $1',
      [userId]
    );

    if (rows.length === 0) {
      // Initialize with 0 credits if user not found
      await pool.query(
        'INSERT INTO ecocore_credits (user_id, credits) VALUES ($1, 0) RETURNING credits',
        [userId]
      );
      return res.json({ credits: 0 });
    }

    res.json({ credits: rows[0].credits });
  } catch (error) {
    console.error('Error fetching credits:', error);
    res.status(500).json({ error: 'Failed to fetch credits' });
  }
});

// Update user credits
app.post('/ecocore/credits/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const { amount, operation = 'set' } = req.body; // operation can be 'set', 'add', or 'subtract'

    if (typeof amount !== 'number') {
      return res.status(400).json({ error: 'Invalid amount' });
    }

    let query = '';
    let params = [userId];

    if (operation === 'add') {
      query = `
        INSERT INTO ecocore_credits (user_id, credits)
        VALUES ($1, $2)
        ON CONFLICT (user_id)
        DO UPDATE SET credits = ecocore_credits.credits + EXCLUDED.credits, updated_at = NOW()
        RETURNING credits
      `;
      params.push(amount);
    } else if (operation === 'subtract') {
      // First check if user has enough credits
      const { rows } = await pool.query(
        'SELECT credits FROM ecocore_credits WHERE user_id = $1',
        [userId]
      );

      if (rows.length === 0 || rows[0].credits < amount) {
        return res.status(400).json({ error: 'Insufficient credits' });
      }

      query = `
        UPDATE ecocore_credits 
        SET credits = credits - $2, updated_at = NOW()
        WHERE user_id = $1
        RETURNING credits
      `;
      params.push(amount);
    } else {
      // Default to set operation
      query = `
        INSERT INTO ecocore_credits (user_id, credits)
        VALUES ($1, $2)
        ON CONFLICT (user_id)
        DO UPDATE SET credits = EXCLUDED.credits, updated_at = NOW()
        RETURNING credits
      `;
      params.push(amount);
    }

    const { rows } = await pool.query(query, params);
    res.json({ credits: rows[0].credits });
  } catch (error) {
    console.error('Error updating credits:', error);
    res.status(500).json({ error: 'Failed to update credits' });
  }
});

app.post('/api/ecocore/bypass-key-system', authenticateToken, async (req, res) => {
  const userId = (req.user.id || req.user.uid); // CORRECCIÃƒâ€œN: El token guarda el ID como 'uid'
  const BYPASS_COST = 5000; // Costo para el bypass

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1. Bloquear la fila del usuario y verificar si ya tiene el bypass
    const { rows: userRows } = await client.query(
      'SELECT key_system_bypassed FROM users WHERE id = $1 FOR UPDATE',
      [userId]
    );

    if (userRows.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado en el sistema.' });
    }

    // 2. Obtener y bloquear el saldo de EcoCoreBits del usuario
    const { rows: currencyRows } = await client.query(
      `SELECT amount FROM user_currency WHERE user_id = $1 AND currency_type = 'ecocorebits' FOR UPDATE`,
      [userId]
    );
    const balance = currencyRows[0]?.amount || 0;

    if (userRows[0].key_system_bypassed) {
      return res.status(400).json({ error: 'Ya tienes el bypass activo.' });
    }

    // 3. Verificar saldo
    if (balance < BYPASS_COST) {
      return res.status(400).json({ error: `Saldo insuficiente. Necesitas ${BYPASS_COST} EcoCoreBits.` });
    }

    // 4. Deducir costo y registrar transacciÃƒÂ³n
    const newBalance = balance - BYPASS_COST;
    await client.query(
      `INSERT INTO user_currency (user_id, currency_type, amount) VALUES ($1, 'ecocorebits', $2)
             ON CONFLICT (user_id, currency_type) DO UPDATE SET amount = $2`,
      [userId, newBalance]
    );
    await client.query(
      'INSERT INTO ecocore_txs (user_id, concepto, monto, origen) VALUES ($1, $2, $3, $4)',
      [userId, 'Bypass del Key System', -BYPASS_COST, 'EcoConsole']
    );

    // 5. Marcar el bypass como activo para el usuario
    await client.query('UPDATE users SET key_system_bypassed = TRUE WHERE id = $1', [userId]);

    await client.query('COMMIT');
    res.json({ success: true, message: 'Ã‚Â¡Trato aceptado! El Key System ha sido desactivado permanentemente.', newBalance });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Error en /api/ecocore/bypass-key-system:', error);
    res.status(500).json({ error: 'Error interno del servidor al procesar el trato.' });
  } finally {
    client.release();
  }
});

/* ===== TIGER TASKS BACKUP ===== */

// Guardar/Actualizar backup de un usuario
app.post('/api/tigertasks/backup', async (req, res) => {
  const { userId, listsData, notesData } = req.body;
  if (!userId || !listsData) {
    return res.status(400).json({ error: 'Faltan userId o listsData' });
  }

  try {
    const payload = {
      version: 2,
      saved_at: new Date().toISOString(),
      lists: Array.isArray(listsData) ? listsData : [],
      notes: Array.isArray(notesData) ? notesData : []
    };
    await pool.query(
      `INSERT INTO tigertasks_backups (user_id, backup_data, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (user_id) DO UPDATE SET
         backup_data = EXCLUDED.backup_data,
         updated_at = NOW()`,
      [userId, JSON.stringify(payload)]
    );
    res.json({ success: true, message: 'Copia de seguridad guardada.' });
  } catch (err) {
    console.error('Error en /api/tigertasks/backup:', err);
    res.status(500).json({ error: 'Error al guardar la copia de seguridad.' });
  }
});

// Restaurar backup de un usuario
app.get('/api/tigertasks/backup/:userId', async (req, res) => {
  const { userId } = req.params;
  const { rows } = await pool.query('SELECT backup_data FROM tigertasks_backups WHERE user_id = $1', [userId]);
  const data = rows[0]?.backup_data || null;
  if (!data) return res.json(null);

  // Compatibilidad con backups legacy (array de listas directo)
  if (Array.isArray(data)) {
    return res.json(data);
  }

  // Backup versionado (listas + notas)
  return res.json({
    version: Number(data.version || 2),
    saved_at: data.saved_at || null,
    lists: Array.isArray(data.lists) ? data.lists : [],
    notes: Array.isArray(data.notes) ? data.notes : []
  });
});

/* ===== SUSCRIPCIONES ECOXION ===== */

const ECOXION_PROJECT_ID = 'Ecoxion';
const ECOXION_CURRENCY = 'ecoxionums';
const ECOXION_PLAN_CATALOG = {
  plus: { id: 'plus', label: 'Plus', price: 420, intervalDays: 30 },
  pro: { id: 'pro', label: 'Pro', price: 750, intervalDays: 30 },
  ultra: { id: 'ultra', label: 'Ultra', price: 1250, intervalDays: 30 }
};

const ECOXION_PLAN_CONFIG_DEFAULT = {
  planAdvantages: {
    free: {
      'eco-luck': ['Tabla base de probabilidades.', 'Costo por tirada: 25 ??.'],
      'eco-generator': ['1 reclamo cada 20h.', 'Bono de racha estï¿½ndar.'],
      'clicky-coin': ['Lï¿½mite diario estï¿½ndar (50 clics).'],
      'eco-stock': ['Acceso al mercado base.'],
      'quick-surveys': ['Encuestas normales sin prioridad.'],
      'smart-notes': ['Funciones base de ediciï¿½n y guardado local.'],
      'ecoxion-workspace': ['Panel base: checklist, recordatorios y scratchpad en dashboard.', 'Sin acceso de segundo plano.']
    },
    plus: {
      'eco-luck': ['Suerte aumentada: sube chance de x3/x10.', 'Pï¿½rdida total reducida frente al plan base.'],
      'eco-generator': ['Eficiencia de generaciï¿½n mejorada.', 'Mejor rendimiento en rachas intermedias.'],
      'clicky-coin': ['Mejor respuesta visual y recompensas consistentes.'],
      'eco-stock': ['Panel de movimiento con lectura mï¿½s rï¿½pida.'],
      'quick-surveys': ['Acceso a mï¿½s encuestas activas por ciclo.'],
      'smart-notes': ['Capas de organizaciï¿½n adicionales.'],
      'ecoxion-workspace': ['Mayor capacidad de metas y recordatorios.', 'Autosave mï¿½s consistente en sesiones largas.']
    },
    pro: {
      'eco-luck': ['Suerte premium: mejora clara de premios altos.', 'Mayor estabilidad en resultados no negativos.'],
      'eco-generator': ['Multiplicador de productividad avanzado.', 'Bonos de racha reforzados.'],
      'clicky-coin': ['Optimizaciï¿½n de flujo en sesiones largas.'],
      'eco-stock': ['Mejoras de seï¿½ales y lectura de tendencia.'],
      'quick-surveys': ['Prioridad de tareas con mejor recompensa media.'],
      'smart-notes': ['Herramientas avanzadas de estructura y foco.'],
      'ecoxion-workspace': ['Modo segundo plano activo con botï¿½n global.', 'Modal rï¿½pido: checklist, recordatorios y scratchpad desde cualquier pestaï¿½a.']
    },
    ultra: {
      'eco-luck': ['Suerte Ultra Nova: mï¿½xima probabilidad de x3/x10.', 'Mitigaciï¿½n alta de tiradas fallidas.'],
      'eco-generator': ['Rendimiento mï¿½ximo y consolidaciï¿½n de rachas.', 'Mejor estabilidad en ciclos largos.'],
      'clicky-coin': ['Flujo experto + mejor consistencia de sesiï¿½n.'],
      'eco-stock': ['Lectura avanzada con ejecuciï¿½n de alto nivel.'],
      'quick-surveys': ['Canal prioritario de encuestas premium.'],
      'smart-notes': ['Suite completa de productividad premium.'],
      'ecoxion-workspace': ['Segundo plano siempre activo con acceso instantï¿½neo.', 'Modal global con resumen live y recarga automï¿½tica de datos.']
    }
  },
  fortuneOdds: {
    free: { tier0: 50, tier15: 30, tier3: 17, tier10: 3 },
    plus: { tier0: 47, tier15: 31, tier3: 18, tier10: 4 },
    pro: { tier0: 43, tier15: 32, tier3: 20, tier10: 5 },
    ultra: { tier0: 38, tier15: 32, tier3: 23, tier10: 7 }
  }
};

function sanitizeEcoxionPlanAdvantages(input) {
  const source = input && typeof input === 'object' ? input : {};
  const out = {};
  for (const planId of ['free', 'plus', 'pro', 'ultra']) {
    const rawPlan = source[planId] && typeof source[planId] === 'object' ? source[planId] : {};
    out[planId] = {};
    for (const [extKey, rawBenefits] of Object.entries(rawPlan)) {
      if (!extKey) continue;
      const benefits = Array.isArray(rawBenefits)
        ? rawBenefits.map((x) => String(x || '').trim()).filter(Boolean).slice(0, 20)
        : [];
      out[planId][String(extKey).trim()] = benefits;
    }
  }
  return out;
}

function sanitizeEcoxionFortuneOdds(input) {
  const defaults = ECOXION_PLAN_CONFIG_DEFAULT.fortuneOdds;
  const source = input && typeof input === 'object' ? input : {};
  const out = {};
  for (const planId of ['free', 'plus', 'pro', 'ultra']) {
    const row = source[planId] && typeof source[planId] === 'object' ? source[planId] : {};
    const tier0 = Number(row.tier0 ?? defaults[planId].tier0);
    const tier15 = Number(row.tier15 ?? defaults[planId].tier15);
    const tier3 = Number(row.tier3 ?? defaults[planId].tier3);
    const tier10 = Number(row.tier10 ?? defaults[planId].tier10);
    const values = [tier0, tier15, tier3, tier10].map((n) => (Number.isFinite(n) && n >= 0 ? n : 0));
    const total = values.reduce((acc, n) => acc + n, 0);
    if (total <= 0) {
      out[planId] = { ...defaults[planId] };
      continue;
    }
    const scaled = values.map((n) => Math.round((n / total) * 100));
    const diff = 100 - scaled.reduce((acc, n) => acc + n, 0);
    scaled[0] += diff;
    out[planId] = { tier0: scaled[0], tier15: scaled[1], tier3: scaled[2], tier10: scaled[3] };
  }
  return out;
}

function sanitizeEcoxionPlanConfig(input) {
  const source = input && typeof input === 'object' ? input : {};
  return {
    planAdvantages: sanitizeEcoxionPlanAdvantages(source.planAdvantages || ECOXION_PLAN_CONFIG_DEFAULT.planAdvantages),
    fortuneOdds: sanitizeEcoxionFortuneOdds(source.fortuneOdds || ECOXION_PLAN_CONFIG_DEFAULT.fortuneOdds)
  };
}

async function ensureEcoxionPlanConfigTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ecoxion_plan_configs (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      config JSONB NOT NULL,
      updated_at TIMESTAMP DEFAULT NOW()
    )
  `);
}

async function getEcoxionPlanConfig() {
  await ensureEcoxionPlanConfigTable();
  const { rows } = await pool.query('SELECT config FROM ecoxion_plan_configs WHERE id = 1 LIMIT 1');
  if (!rows.length) {
    const initial = sanitizeEcoxionPlanConfig(ECOXION_PLAN_CONFIG_DEFAULT);
    await pool.query(
      'INSERT INTO ecoxion_plan_configs (id, config, updated_at) VALUES (1, $1::jsonb, NOW()) ON CONFLICT (id) DO NOTHING',
      [JSON.stringify(initial)]
    );
    return initial;
  }
  return sanitizeEcoxionPlanConfig(rows[0].config || {});
}

function normalizeEcoxionPlanId(planId) {
  const key = String(planId || '').trim().toLowerCase();
  if (key.includes('ultra') || key.includes('nexus') || key.includes('elite')) return 'ultra';
  if (key.includes('pro')) return 'pro';
  if (key.includes('plus') || key.includes('starter')) return 'plus';
  return '';
}

function getEcoxionPlanDefinition(planId) {
  const normalized = normalizeEcoxionPlanId(planId);
  return ECOXION_PLAN_CATALOG[normalized] || null;
}

const ECOXION_ECLIPSER_TYPE_META = {
  solar_total: { label: 'Eclipse Solar Total', reward: 180 },
  solar_partial: { label: 'Eclipse Solar Parcial', reward: 120 },
  lunar_total: { label: 'Eclipse Lunar Total', reward: 150 },
  lunar_partial: { label: 'Eclipse Lunar Parcial', reward: 95 },
  annular: { label: 'Eclipse Anular', reward: 160 }
};

function normalizeEclipserType(value) {
  const key = String(value || '').trim().toLowerCase();
  if (ECOXION_ECLIPSER_TYPE_META[key]) return key;
  if (key.includes('solar') && key.includes('total')) return 'solar_total';
  if (key.includes('solar')) return 'solar_partial';
  if (key.includes('lunar') && key.includes('total')) return 'lunar_total';
  if (key.includes('lunar')) return 'lunar_partial';
  if (key.includes('anular') || key.includes('annular')) return 'annular';
  return 'solar_partial';
}

function toIsoDate(value, fallbackMs = 0) {
  const d = value ? new Date(value) : new Date(Date.now() + fallbackMs);
  if (!Number.isFinite(d.getTime())) return null;
  return d;
}

function buildEclipseCode(prefix = 'ECL') {
  const rnd = Math.random().toString(36).slice(2, 8).toUpperCase();
  return `${prefix}-${Date.now()}-${rnd}`;
}

async function ensureEcoxionEclipserTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ecoxion_eclipses (
      id SERIAL PRIMARY KEY,
      eclipse_code TEXT UNIQUE NOT NULL,
      eclipse_type TEXT NOT NULL,
      eclipse_kind TEXT NOT NULL DEFAULT 'admin',
      title TEXT NOT NULL,
      starts_at TIMESTAMP NOT NULL,
      ends_at TIMESTAMP NOT NULL,
      reward_amount INTEGER NOT NULL DEFAULT 0,
      reward_currency TEXT NOT NULL DEFAULT 'ecoxionums',
      created_by INTEGER,
      created_by_name TEXT,
      metadata JSONB DEFAULT '{}'::jsonb,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ecoxion_eclipse_participations (
      id SERIAL PRIMARY KEY,
      eclipse_id INTEGER NOT NULL REFERENCES ecoxion_eclipses(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL,
      watched_seconds INTEGER NOT NULL DEFAULT 0,
      reward_amount INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW(),
      UNIQUE(eclipse_id, user_id)
    )
  `);
}

function mapEclipseRow(row, now = Date.now()) {
  const starts = new Date(row.starts_at).getTime();
  const ends = new Date(row.ends_at).getTime();
  const status = now < starts ? 'upcoming' : (now > ends ? 'ended' : 'active');
  return {
    id: Number(row.id),
    eclipseCode: row.eclipse_code,
    eclipseType: row.eclipse_type,
    eclipseKind: row.eclipse_kind,
    title: row.title,
    startsAt: row.starts_at,
    endsAt: row.ends_at,
    rewardAmount: Number(row.reward_amount || 0),
    rewardCurrency: row.reward_currency || ECOXION_CURRENCY,
    createdBy: row.created_by || null,
    createdByName: row.created_by_name || '',
    metadata: row.metadata || {},
    status
  };
}

async function getPrimaryCardForUser(client, userId, forUpdate = true) {
  const lockSql = forUpdate ? 'FOR UPDATE' : '';
  const { rows } = await client.query(
    `SELECT id, balances
     FROM ocean_pay_cards
     WHERE user_id = $1 AND COALESCE(is_active, true) = true
     ORDER BY is_primary DESC, id ASC
     LIMIT 1
     ${lockSql}`,
    [userId]
  );
  return rows[0] || null;
}

async function ensurePrimaryCardForUser(client, userId, forUpdate = true) {
  let card = await getPrimaryCardForUser(client, userId, forUpdate);
  if (card) return card;

  const { cardNumber, cvv, expiryDate } = generateCardDetails();
  const { rows } = await client.query(
    `INSERT INTO ocean_pay_cards (user_id, card_number, cvv, expiry_date, is_primary, card_name)
     VALUES ($1, $2, $3, $4, true, $5)
     RETURNING id, balances`,
    [userId, cardNumber, cvv, expiryDate, 'Tarjeta Principal']
  );

  card = rows[0] || null;
  return card;
}

async function getUserIdByCardId(client, cardId) {
  const { rows } = await client.query(
    'SELECT user_id FROM ocean_pay_cards WHERE id = $1 LIMIT 1',
    [cardId]
  );
  return rows[0]?.user_id ? Number(rows[0].user_id) : 0;
}

async function ensureUserWalletRow(client, userId) {
  await client.query(
    `INSERT INTO ${USER_WALLET_TABLE} (user_id, balances)
     VALUES ($1, '{}'::jsonb)
     ON CONFLICT (user_id) DO NOTHING`,
    [userId]
  );
}

async function getUserWalletBalances(client, userId, forUpdate = false) {
  await ensureUserWalletRow(client, userId);
  const lockSql = forUpdate ? 'FOR UPDATE' : '';
  const { rows } = await client.query(
    `SELECT balances FROM ${USER_WALLET_TABLE} WHERE user_id = $1 ${lockSql}`,
    [userId]
  );
  return (rows[0]?.balances && typeof rows[0].balances === 'object') ? rows[0].balances : {};
}

async function getUnifiedCardCurrencyBalance(client, cardId, currency, forUpdate = true) {
  const curr = String(currency || '').trim().toLowerCase();
  const userId = await getUserIdByCardId(client, cardId);
  if (!userId) return 0;
  const balances = await getUserWalletBalances(client, userId, forUpdate);
  const amount = Number(balances[curr] || 0);
  return Number.isFinite(amount) ? amount : 0;
}

async function setUnifiedCardCurrencyBalance(client, { userId, cardId, currency, newBalance }) {
  const curr = String(currency || '').trim().toLowerCase();
  const safeBalance = Math.max(0, Number(newBalance || 0));
  const resolvedUserId = Number(userId || await getUserIdByCardId(client, cardId) || 0);
  if (!resolvedUserId) return;

  await ensureUserWalletRow(client, resolvedUserId);
  await client.query(
    `UPDATE ${USER_WALLET_TABLE}
     SET balances = jsonb_set(COALESCE(balances, '{}'::jsonb), ARRAY[$1]::text[], to_jsonb($2::numeric), true),
         updated_at = NOW()
     WHERE user_id = $3`,
    [curr, safeBalance, resolvedUserId]
  );

  // Mirror de compatibilidad para endpoints legacy que siguen leyendo tarjeta.
  await client.query(
    `UPDATE ocean_pay_cards
     SET balances = jsonb_set(
       COALESCE(balances, '{}'::jsonb),
       ARRAY[$1]::text[],
       to_jsonb($2::numeric),
       true
     )
     WHERE id = $3`,
    [curr, safeBalance, cardId]
  ).catch(() => {});

  await client.query(
    `INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount)
     VALUES ($1, $2, $3)
     ON CONFLICT (card_id, currency_type) DO UPDATE SET amount = EXCLUDED.amount`,
    [cardId, curr, safeBalance]
  ).catch(() => {});

  await client.query(
    `INSERT INTO user_currency (user_id, currency_type, amount)
     VALUES ($1, $2, $3)
     ON CONFLICT (user_id, currency_type) DO UPDATE SET amount = EXCLUDED.amount, updated_at = NOW()`,
    [resolvedUserId, curr, safeBalance]
  ).catch(() => {});

  if (curr === ECOXION_CURRENCY) {
    await client.query(
      `UPDATE ocean_pay_users SET ecoxionums = $1 WHERE id = $2`,
      [safeBalance, resolvedUserId]
    ).catch(() => {});
  } else if (curr === 'aquabux' || curr === 'appbux') {
    await client.query(
      `UPDATE ocean_pay_users SET ${curr} = $1 WHERE id = $2`,
      [safeBalance, resolvedUserId]
    );
  }
}

async function insertEcoxionSubscription(client, { userId, cardId, planDef, now }) {
  const columns = await getWtSubscriptionColumnSet();
  const values = [];
  const params = [];
  const colList = [];

  const add = (col, val) => {
    if (!columns.has(col)) return;
    colList.push(col);
    params.push(val);
    values.push(`$${params.length}`);
  };

  add('user_id', userId);
  add('card_id', cardId);
  add('project_id', ECOXION_PROJECT_ID);
  add('plan_name', `Ecoxion ${planDef.label}`);
  add('sub_name', `Ecoxion ${planDef.label}`);
  add('price', planDef.price);
  add('currency', ECOXION_CURRENCY);
  add('status', 'active');
  add('start_date', now);

  const nextPayment = new Date(now.getTime() + planDef.intervalDays * 24 * 60 * 60 * 1000);
  add('end_date', nextPayment);
  add('interval_days', planDef.intervalDays);
  add('next_payment', nextPayment);
  add('auto_renew', true);

  if (!colList.length) throw new Error('No se pudo crear la suscripcion: esquema incompleto');

  const { rows } = await client.query(
    `INSERT INTO ocean_pay_subscriptions (${colList.join(', ')}) VALUES (${values.join(', ')}) RETURNING *`,
    params
  );

  return rows[0] || null;
}

async function closeActiveEcoxionSubscriptions(client, userId) {
  const columns = await getWtSubscriptionColumnSet();
  const setClauses = [];
  if (columns.has('status')) setClauses.push(`status = 'cancelled'`);
  if (columns.has('end_date')) setClauses.push(`end_date = NOW()`);
  if (columns.has('next_payment')) setClauses.push(`next_payment = NOW()`);
  if (!setClauses.length) return 0;

  const { rowCount } = await client.query(
    `UPDATE ocean_pay_subscriptions
     SET ${setClauses.join(', ')}
     WHERE user_id = $1
       AND LOWER(COALESCE(project_id, '')) = LOWER($2)
       AND (status IS NULL OR LOWER(status) = 'active')`,
    [userId, ECOXION_PROJECT_ID]
  );

  return Number(rowCount || 0);
}

// GET - Obtener suscripcion actual del usuario (ocean_pay_subscriptions + fallback legacy)
app.get('/api/ecoxion/subscription/:userId', async (req, res) => {
  try {
    let tokenUserId = 0;
    const authHeader = String(req.headers.authorization || '');
    if (authHeader.startsWith('Bearer ')) {
      try {
        const token = authHeader.substring(7);
        const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
        tokenUserId = Number(decoded.id || decoded.uid || decoded.sub || 0);
      } catch (_e) {
        tokenUserId = 0;
      }
    }

    let userId = Number(req.params.userId);
    if (!Number.isFinite(userId) || userId <= 0) {
      userId = tokenUserId;
    }
    if (!Number.isFinite(userId) || userId <= 0) {
      return res.status(400).json({ error: 'userId invalido' });
    }

    const columns = await getWtSubscriptionColumnSet();
    const startsExpr = columns.has('start_date')
      ? 'start_date'
      : 'created_at';
    const endsExpr = columns.has('end_date')
      ? 'end_date'
      : (columns.has('next_payment') ? 'next_payment' : 'created_at');
    const renewExpr = columns.has('next_payment')
      ? 'next_payment'
      : (columns.has('end_date') ? 'end_date' : 'created_at');

    const { rows } = await pool.query(
      `SELECT id, plan_name, sub_name, price, currency, status, ${startsExpr} AS starts_at, ${endsExpr} AS ends_at, ${renewExpr} AS renew_at, created_at
       FROM ocean_pay_subscriptions
       WHERE user_id = $1
         AND LOWER(COALESCE(project_id, '')) = LOWER($2)
         AND (status IS NULL OR LOWER(status) = 'active')
       ORDER BY COALESCE(${renewExpr}, ${endsExpr}, created_at) DESC, created_at DESC
       LIMIT 1`,
      [userId, ECOXION_PROJECT_ID]
    );

    const current = rows[0];
    if (!current) {
      const { rows: legacyRows } = await pool.query(
        `SELECT plan, starts_at, ends_at, created_at
         FROM ecoxion_subscriptions
         WHERE user_id = $1 AND active = true
         ORDER BY created_at DESC
         LIMIT 1`,
        [userId]
      );
      if (!legacyRows.length) return res.json(null);

      return res.json({
        plan: normalizeEcoxionPlanId(legacyRows[0].plan) || legacyRows[0].plan || 'pro',
        planName: legacyRows[0].plan || 'Ecoxion Pro',
        price: null,
        currency: ECOXION_CURRENCY,
        startsAt: legacyRows[0].starts_at,
        endsAt: legacyRows[0].ends_at,
        renewAt: legacyRows[0].ends_at,
        status: 'active',
        source: 'legacy'
      });
    }

    const nowTs = Date.now();
    const endsTs = current.ends_at ? new Date(current.ends_at).getTime() : 0;
    const isActive = String(current.status || 'active').toLowerCase() === 'active' && (!endsTs || endsTs > nowTs);
    if (!isActive) return res.json(null);

    const normalizedPlan = normalizeEcoxionPlanId(current.plan_name || current.sub_name || '') || 'pro';
    res.json({
      id: current.id,
      plan: normalizedPlan,
      planName: current.plan_name || current.sub_name || `Ecoxion ${ECOXION_PLAN_CATALOG[normalizedPlan]?.label || 'Pro'}`,
      price: Number(current.price || 0),
      currency: (current.currency || ECOXION_CURRENCY).toLowerCase(),
      startsAt: current.starts_at || current.created_at,
      endsAt: current.ends_at || null,
      renewAt: current.renew_at || current.ends_at || null,
      status: 'active',
      source: 'ocean_pay_subscriptions'
    });
  } catch (err) {
    console.error('Error obteniendo suscripcion Ecoxion:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// GET - Configuracion de planes Ecoxion (ventajas por extension + odds Fortuna)
app.get('/api/ecoxion/plans/config', async (_req, res) => {
  try {
    const config = await getEcoxionPlanConfig();
    return res.json({ success: true, config });
  } catch (err) {
    console.error('Error obteniendo config de planes Ecoxion:', err);
    return res.status(500).json({ error: 'Error interno' });
  }
});

// PUT - Actualizar configuracion de planes Ecoxion (admin)
app.put('/api/ecoxion/plans/config', async (req, res) => {
  if (!requireOwsStoreAdmin(req, res)) return;
  try {
    const current = await getEcoxionPlanConfig();
    const incoming = (req.body && typeof req.body === 'object') ? req.body : {};
    const merged = sanitizeEcoxionPlanConfig({
      planAdvantages: {
        ...(current.planAdvantages || {}),
        ...(incoming.planAdvantages && typeof incoming.planAdvantages === 'object' ? incoming.planAdvantages : {})
      },
      fortuneOdds: {
        ...(current.fortuneOdds || {}),
        ...(incoming.fortuneOdds && typeof incoming.fortuneOdds === 'object' ? incoming.fortuneOdds : {})
      }
    });

    await pool.query(
      `INSERT INTO ecoxion_plan_configs (id, config, updated_at)
       VALUES (1, $1::jsonb, NOW())
       ON CONFLICT (id) DO UPDATE SET
         config = EXCLUDED.config,
         updated_at = NOW()`,
      [JSON.stringify(merged)]
    );

    return res.json({ success: true, config: merged });
  } catch (err) {
    console.error('Error actualizando config de planes Ecoxion:', err);
    return res.status(500).json({ error: 'Error interno' });
  }
});

// GET - Eclipser: prï¿½ximos eclipses + activos
app.get('/api/ecoxion/eclipses/upcoming', async (req, res) => {
  try {
    await ensureEcoxionEclipserTables();
    const now = new Date();
    const userId = Number(req.query?.userId || 0);
    const { rows } = await pool.query(
      `SELECT e.*,
              CASE WHEN p.id IS NULL THEN false ELSE true END AS participated
       FROM ecoxion_eclipses e
       LEFT JOIN ecoxion_eclipse_participations p
              ON p.eclipse_id = e.id
             AND ($2::int > 0 AND p.user_id = $2::int)
       WHERE e.ends_at >= $1
       ORDER BY e.starts_at ASC
       LIMIT 30`,
      [now, userId]
    );
    return res.json({
      success: true,
      events: rows.map((r) => ({ ...mapEclipseRow(r), participated: r.participated === true }))
    });
  } catch (err) {
    console.error('Error en GET /api/ecoxion/eclipses/upcoming:', err);
    return res.status(500).json({ error: 'Error interno' });
  }
});

app.get('/api/ecoxion/eclipses/active', async (_req, res) => {
  try {
    await ensureEcoxionEclipserTables();
    const { rows } = await pool.query(
      `SELECT * FROM ecoxion_eclipses
       WHERE starts_at <= NOW() AND ends_at >= NOW()
       ORDER BY starts_at ASC
       LIMIT 12`
    );
    return res.json({ success: true, events: rows.map((r) => mapEclipseRow(r)) });
  } catch (err) {
    console.error('Error en GET /api/ecoxion/eclipses/active:', err);
    return res.status(500).json({ error: 'Error interno' });
  }
});

// POST - Eclipser admin invoke
app.post('/api/ecoxion/eclipses/admin/invoke', async (req, res) => {
  if (!requireOwsStoreAdmin(req, res)) return;
  try {
    await ensureEcoxionEclipserTables();
    const eclipseType = normalizeEclipserType(req.body?.eclipseType);
    const typeMeta = ECOXION_ECLIPSER_TYPE_META[eclipseType] || ECOXION_ECLIPSER_TYPE_META.solar_partial;
    const startsAtDate = toIsoDate(req.body?.startsAt, 5 * 60 * 1000);
    const endsAtDate = toIsoDate(req.body?.endsAt, 20 * 60 * 1000);
    if (!startsAtDate || !endsAtDate || endsAtDate.getTime() <= startsAtDate.getTime()) {
      return res.status(400).json({ error: 'Fechas invï¿½lidas para el eclipse.' });
    }
    const rewardAmount = Number.isFinite(Number(req.body?.rewardAmount))
      ? Math.max(0, Math.floor(Number(req.body.rewardAmount)))
      : Number(typeMeta.reward || 120);
    const title = String(req.body?.title || typeMeta.label || 'Eclipse Admin').trim().slice(0, 120);
    const eclipseCode = buildEclipseCode('ADM');
    const { rows } = await pool.query(
      `INSERT INTO ecoxion_eclipses
       (eclipse_code, eclipse_type, eclipse_kind, title, starts_at, ends_at, reward_amount, reward_currency, created_by_name, metadata)
       VALUES ($1,$2,'admin',$3,$4,$5,$6,$7,$8,$9::jsonb)
       RETURNING *`,
      [
        eclipseCode,
        eclipseType,
        title || typeMeta.label,
        startsAtDate,
        endsAtDate,
        rewardAmount,
        ECOXION_CURRENCY,
        String(req.body?.createdByName || 'Admin'),
        JSON.stringify({
          source: 'admin',
          announcedType: typeMeta.label
        })
      ]
    );
    return res.json({ success: true, event: mapEclipseRow(rows[0]) });
  } catch (err) {
    console.error('Error en POST /api/ecoxion/eclipses/admin/invoke:', err);
    return res.status(500).json({ error: 'Error interno' });
  }
});

// POST - Eclipser custom (solo Ultra)
app.post('/api/ecoxion/eclipses/custom', async (req, res) => {
  const userId = Number(req.body?.userId || 0);
  const username = String(req.body?.username || 'Usuario').trim().slice(0, 60);
  const planId = normalizeEcoxionPlanId(req.body?.planId || req.body?.plan || '');
  if (!Number.isFinite(userId) || userId <= 0) return res.status(400).json({ error: 'userId invï¿½lido' });
  if (planId !== 'ultra') return res.status(403).json({ error: 'Crear eclipses personalizados requiere plan Ultra.' });
  try {
    await ensureEcoxionEclipserTables();
    const eclipseType = normalizeEclipserType(req.body?.eclipseType);
    const typeMeta = ECOXION_ECLIPSER_TYPE_META[eclipseType] || ECOXION_ECLIPSER_TYPE_META.solar_partial;
    const startsAtDate = toIsoDate(req.body?.startsAt, 2 * 60 * 1000);
    const endsAtDate = toIsoDate(req.body?.endsAt, 12 * 60 * 1000);
    if (!startsAtDate || !endsAtDate || endsAtDate.getTime() <= startsAtDate.getTime()) {
      return res.status(400).json({ error: 'Fechas invï¿½lidas para el eclipse.' });
    }
    const baseReward = Number(typeMeta.reward || 120);
    const reducedReward = Math.max(1, Math.floor(baseReward * 0.1)); // 90% menos
    const customName = String(req.body?.customName || '').trim().slice(0, 80);
    const title = customName ? `Eclipse Personalizado: ${customName}` : `Eclipse Personalizado de ${username}`;
    const eclipseCode = buildEclipseCode('CUS');
    const { rows } = await pool.query(
      `INSERT INTO ecoxion_eclipses
       (eclipse_code, eclipse_type, eclipse_kind, title, starts_at, ends_at, reward_amount, reward_currency, created_by, created_by_name, metadata)
       VALUES ($1,$2,'custom',$3,$4,$5,$6,$7,$8,$9,$10::jsonb)
       RETURNING *`,
      [
        eclipseCode,
        eclipseType,
        title,
        startsAtDate,
        endsAtDate,
        reducedReward,
        ECOXION_CURRENCY,
        userId,
        username,
        JSON.stringify({
          source: 'ultra_custom',
          customName: customName || null,
          baseReward,
          reductionPercent: 90
        })
      ]
    );
    return res.json({ success: true, event: mapEclipseRow(rows[0]) });
  } catch (err) {
    console.error('Error en POST /api/ecoxion/eclipses/custom:', err);
    return res.status(500).json({ error: 'Error interno' });
  }
});

// POST - Eclipser participation + reward
app.post('/api/ecoxion/eclipses/:eclipseId/participate', async (req, res) => {
  const eclipseId = Number(req.params.eclipseId || 0);
  const userId = Number(req.body?.userId || 0);
  const watchedSeconds = Math.max(0, Math.floor(Number(req.body?.watchedSeconds || 0)));
  if (!Number.isFinite(eclipseId) || eclipseId <= 0) return res.status(400).json({ error: 'eclipseId invï¿½lido' });
  if (!Number.isFinite(userId) || userId <= 0) return res.status(400).json({ error: 'userId invï¿½lido' });
  if (watchedSeconds < 6) return res.status(400).json({ error: 'Debes ver el eclipse por al menos 6 segundos.' });
  const client = await pool.connect();
  try {
    await ensureEcoxionEclipserTables();
    await client.query('BEGIN');
    const { rows: eventRows } = await client.query(
      `SELECT * FROM ecoxion_eclipses WHERE id = $1 FOR UPDATE`,
      [eclipseId]
    );
    if (!eventRows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Eclipse no encontrado.' });
    }
    const event = eventRows[0];
    const now = Date.now();
    const starts = new Date(event.starts_at).getTime();
    const ends = new Date(event.ends_at).getTime();
    if (now < starts) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Este eclipse aï¿½n no comenzï¿½.' });
    }
    if (now > ends + 30 * 60 * 1000) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Este eclipse ya finalizï¿½.' });
    }
    const { rows: alreadyRows } = await client.query(
      `SELECT id FROM ecoxion_eclipse_participations WHERE eclipse_id = $1 AND user_id = $2`,
      [eclipseId, userId]
    );
    if (alreadyRows.length) {
      await client.query('ROLLBACK');
      return res.json({ success: true, alreadyClaimed: true, reward: 0 });
    }

    const rewardAmount = Math.max(0, Number(event.reward_amount || 0));
    if (rewardAmount > 0) {
      const primaryCard = await ensurePrimaryCardForUser(client, userId, true);
      if (!primaryCard) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'No se encontrï¿½ tarjeta principal para abonar recompensa.' });
      }
      const currentBalance = await getUnifiedCardCurrencyBalance(client, Number(primaryCard.id), ECOXION_CURRENCY, true);
      await setUnifiedCardCurrencyBalance(client, {
        userId,
        cardId: Number(primaryCard.id),
        currency: ECOXION_CURRENCY,
        newBalance: currentBalance + rewardAmount
      });
      await client.query(
        `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
         VALUES ($1, $2, $3, $4, $5)`,
        [userId, `Recompensa Eclipse (${event.title})`, rewardAmount, 'Ecoxion Eclipser', ECOXION_CURRENCY]
      ).catch(() => null);
    }

    await client.query(
      `INSERT INTO ecoxion_eclipse_participations (eclipse_id, user_id, watched_seconds, reward_amount)
       VALUES ($1, $2, $3, $4)`,
      [eclipseId, userId, watchedSeconds, rewardAmount]
    );
    await client.query('COMMIT');
    return res.json({ success: true, reward: rewardAmount, currency: ECOXION_CURRENCY });
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch (_) {}
    console.error('Error en POST /api/ecoxion/eclipses/:eclipseId/participate:', err);
    return res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

// POST - Suscribirse a un plan de Ecoxion
app.post('/api/ecoxion/subscribe', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  let tokenUserId = null;
  try {
    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    tokenUserId = Number(decoded.id || decoded.uid || decoded.sub);
  } catch (_e) {
    return res.status(401).json({ error: 'Token invalido' });
  }

  const requestedUserId = Number(req.body?.userId || 0) || tokenUserId;
  if (!Number.isFinite(requestedUserId) || requestedUserId <= 0 || requestedUserId !== tokenUserId) {
    return res.status(403).json({ error: 'Usuario no autorizado para esta operacion' });
  }

  const rawPlan =
    req.body?.plan ??
    req.body?.planId ??
    req.body?.plan_id ??
    req.body?.plan_name ??
    req.body?.subName ??
    req.body?.tier ??
    req.body?.id;
  const planDef = getEcoxionPlanDefinition(rawPlan);
  if (!planDef) {
    return res.status(400).json({ error: 'Plan no valido. Usa plus, pro o ultra.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const primaryCard = await ensurePrimaryCardForUser(client, requestedUserId, true);
    if (!primaryCard) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'No tienes una tarjeta Ocean Pay activa.' });
    }

    const currentBalance = await getUnifiedCardCurrencyBalance(client, Number(primaryCard.id), ECOXION_CURRENCY, true);
    if (currentBalance < planDef.price) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        error: `Saldo insuficiente. Necesitas ${planDef.price} Ecoxionums para Ecoxion ${planDef.label}.`,
        currentBalance
      });
    }

    const newBalance = currentBalance - planDef.price;
    await setUnifiedCardCurrencyBalance(client, {
      userId: requestedUserId,
      cardId: Number(primaryCard.id),
      currency: ECOXION_CURRENCY,
      newBalance
    });

    await closeActiveEcoxionSubscriptions(client, requestedUserId);

    const now = new Date();
    const createdSub = await insertEcoxionSubscription(client, {
      userId: requestedUserId,
      cardId: Number(primaryCard.id),
      planDef,
      now
    });

    await client.query(
      `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
       VALUES ($1, $2, $3, $4, $5)`,
      [requestedUserId, `Suscripcion Ecoxion ${planDef.label}`, -planDef.price, ECOXION_PROJECT_ID, ECOXION_CURRENCY]
    );

    await client.query(
      `INSERT INTO ocean_pay_notifications (user_id, type, title, message)
       VALUES ($1, 'success', $2, $3)`,
      [requestedUserId, 'Suscripcion Ecoxion activada', `Plan Ecoxion ${planDef.label} activo por ${planDef.intervalDays} dias.`]
    ).catch(() => null);

    // Compatibilidad legacy
    await client.query(
      `UPDATE ecoxion_subscriptions SET active = false WHERE user_id = $1 AND active = true`,
      [requestedUserId]
    ).catch(() => null);

    const legacyEndsAt = new Date(now.getTime() + planDef.intervalDays * 24 * 60 * 60 * 1000);
    await client.query(
      `INSERT INTO ecoxion_subscriptions (user_id, plan, starts_at, ends_at, active)
       VALUES ($1, $2, $3, $4, true)`,
      [requestedUserId, planDef.id, now, legacyEndsAt]
    ).catch(() => null);

    await client.query('COMMIT');

    const endsAt = createdSub?.end_date || createdSub?.next_payment || legacyEndsAt;
    res.json({
      success: true,
      newBalance,
      subscription: {
        plan: planDef.id,
        planName: createdSub?.plan_name || `Ecoxion ${planDef.label}`,
        price: planDef.price,
        currency: ECOXION_CURRENCY,
        startsAt: createdSub?.start_date || now,
        endsAt,
        renewAt: createdSub?.next_payment || endsAt
      }
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error al suscribirse Ecoxion:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  } finally {
    client.release();
  }
});

// POST - Cancelar suscripcion Ecoxion
app.post('/api/ecoxion/subscription/cancel', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  let tokenUserId = null;
  try {
    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    tokenUserId = Number(decoded.id || decoded.uid || decoded.sub);
  } catch (_e) {
    return res.status(401).json({ error: 'Token invalido' });
  }

  const requestedUserId = Number(req.body?.userId || 0) || tokenUserId;
  if (!Number.isFinite(requestedUserId) || requestedUserId <= 0 || requestedUserId !== tokenUserId) {
    return res.status(403).json({ error: 'Usuario no autorizado para esta operacion' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const closedMain = await closeActiveEcoxionSubscriptions(client, requestedUserId);
    const legacyResult = await client.query(
      `UPDATE ecoxion_subscriptions
       SET active = false
       WHERE user_id = $1 AND active = true`,
      [requestedUserId]
    ).catch(() => ({ rowCount: 0 }));

    if (!closedMain && !Number(legacyResult?.rowCount || 0)) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'No tienes una suscripcion activa de Ecoxion.' });
    }

    await client.query(
      `INSERT INTO ocean_pay_notifications (user_id, type, title, message)
       VALUES ($1, 'info', $2, $3)`,
      [requestedUserId, 'Suscripcion Ecoxion cancelada', 'Tu suscripcion de Ecoxion quedo cancelada.']
    ).catch(() => null);

    await client.query('COMMIT');
    res.json({
      success: true,
      message: 'Suscripcion cancelada correctamente.'
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error al cancelar suscripcion Ecoxion:', err);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});


/* ===== QUIZ KAHOOT SYSTEM ===== */

/* ===== A WILD QUESTION GAME (AWQG) MULTIPLAYER ===== */
const awqgRooms = new Map(); // code -> room
const awqgSocketToRoom = new Map(); // socketId -> code

function generateAwqgCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

function createAwqgRoom({ hostName = 'Jugador 1' } = {}) {
  let code = generateAwqgCode();
  while (awqgRooms.has(code)) code = generateAwqgCode();
  const room = {
    code,
    createdAt: Date.now(),
    status: 'waiting', // waiting|selecting|playing|finished
    category: null,
    host: { socketId: null, name: hostName },
    guest: null,
    hostSecret: null, // personaje que debe adivinar guest
    guestSecret: null, // personaje que debe adivinar host
    currentTurn: 'host',
    questionsLeftThisTurn: 1,
    extraQuestionFor: null, // host|guest|null
    pendingQuestion: null, // { askedBy, trait, value, text }
    noGuessSwitches: 0,
    finalDuel: {
      active: false,
      hostChoice: null,
      guestChoice: null
    }
  };
  awqgRooms.set(code, room);
  return room;
}

function getAwqgRoomPublic(room) {
  return {
    code: room.code,
    status: room.status,
    category: room.category,
    hasGuest: !!room.guest,
    hostName: room.host?.name || 'Jugador 1',
    guestName: room.guest?.name || null,
    currentTurn: room.currentTurn,
    questionsLeftThisTurn: room.questionsLeftThisTurn,
    hostSecretSelected: !!room.hostSecret,
    guestSecretSelected: !!room.guestSecret
  };
}

function getAwqgRole(room, socketId) {
  if (room.host?.socketId === socketId) return 'host';
  if (room.guest?.socketId === socketId) return 'guest';
  return null;
}

function emitAwqgRoomState(code) {
  const room = awqgRooms.get(code);
  if (!room) return;
  io.to(`awqg-${code}`).emit('awqg:room-state', getAwqgRoomPublic(room));
}

function emitAwqgTurnState(code) {
  const room = awqgRooms.get(code);
  if (!room) return;
  io.to(`awqg-${code}`).emit('awqg:turn-state', {
    currentTurn: room.currentTurn,
    questionsLeftThisTurn: room.questionsLeftThisTurn
  });
}

function startAwqgFinalDuel(room, reason = '') {
  if (!room || room.finalDuel?.active) return;
  room.finalDuel = {
    active: true,
    hostChoice: null,
    guestChoice: null
  };
  io.to(`awqg-${room.code}`).emit('awqg:final-duel-start', {
    reason: reason || 'Fase final activada. Ambos deben elegir su veredicto.'
  });
}

function switchAwqgTurn(room) {
  room.currentTurn = room.currentTurn === 'host' ? 'guest' : 'host';
  room.noGuessSwitches = (room.noGuessSwitches || 0) + 1;
  if (room.extraQuestionFor === room.currentTurn) {
    room.questionsLeftThisTurn = 2;
    room.extraQuestionFor = null;
  } else {
    room.questionsLeftThisTurn = 1;
  }
  room.pendingQuestion = null;
}

// Crear sala AWQG
app.post('/api/awqg/rooms/create', (req, res) => {
  try {
    const hostName = String(req.body?.hostName || 'Jugador 1').slice(0, 40);
    const room = createAwqgRoom({ hostName });
    res.json({ success: true, room: getAwqgRoomPublic(room) });
  } catch (err) {
    console.error('[AWQG] Error creando sala:', err);
    res.status(500).json({ error: 'No se pudo crear la sala' });
  }
});

// Listar salas esperando segundo jugador
app.get('/api/awqg/rooms/waiting', (_req, res) => {
  try {
    const waitingRooms = Array.from(awqgRooms.values())
      .filter((room) => (room.status === 'waiting' || room.status === 'selecting') && !room.guest)
      .sort((a, b) => b.createdAt - a.createdAt)
      .slice(0, 30)
      .map((room) => ({
        code: room.code,
        hostName: room.host?.name || 'Jugador 1',
        createdAt: room.createdAt
      }));
    res.json({ success: true, rooms: waitingRooms });
  } catch (err) {
    console.error('[AWQG] Error listando salas waiting:', err);
    res.status(500).json({ error: 'No se pudo listar salas' });
  }
});

app.get('/api/awqg/rooms/:code', (req, res) => {
  try {
    const code = String(req.params.code || '').toUpperCase();
    const room = awqgRooms.get(code);
    if (!room) return res.status(404).json({ error: 'Sala no encontrada' });
    res.json({ success: true, room: getAwqgRoomPublic(room) });
  } catch (err) {
    console.error('[AWQG] Error obteniendo sala:', err);
    res.status(500).json({ error: 'No se pudo obtener la sala' });
  }
});

// Almacenamiento en memoria para salas activas (se puede migrar a Redis en producciÃƒÂ³n)
const activeRooms = new Map(); // roomPin -> { hostId, quizId, players: [], currentQuestion: 0, scores: {}, state: 'waiting'|'playing'|'results' }
const playerSockets = new Map(); // socketId -> { playerId, roomPin, playerName }

// Inicializar tablas de quizzes
async function ensureQuizTables() {
  const quizQueries = [
    `CREATE TABLE IF NOT EXISTS quizzes (
      id SERIAL PRIMARY KEY,
      user_id TEXT,
      title TEXT NOT NULL,
      description TEXT,
      questions JSONB NOT NULL,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    );`,
    `CREATE TABLE IF NOT EXISTS quiz_sessions (
      id SERIAL PRIMARY KEY,
      quiz_id INTEGER REFERENCES quizzes(id) ON DELETE CASCADE,
      room_pin VARCHAR(6) UNIQUE NOT NULL,
      host_id TEXT,
      state VARCHAR(20) DEFAULT 'waiting',
      current_question INTEGER DEFAULT 0,
      started_at TIMESTAMP,
      ended_at TIMESTAMP,
      created_at TIMESTAMP DEFAULT NOW()
    );`,
    `CREATE TABLE IF NOT EXISTS quiz_players (
      id SERIAL PRIMARY KEY,
      session_id INTEGER REFERENCES quiz_sessions(id) ON DELETE CASCADE,
      player_id TEXT NOT NULL,
      player_name VARCHAR(100) NOT NULL,
      score INTEGER DEFAULT 0,
      answers JSONB DEFAULT '[]',
      joined_at TIMESTAMP DEFAULT NOW(),
      UNIQUE(session_id, player_id)
    );`
  ];

  for (const q of quizQueries) {
    try {
      await pool.query(q);
    } catch (err) {
      console.error('Error creando tabla de quiz:', err.message);
    }
  }
  console.log("Ã¢Å“â€¦ Tablas de quiz inicializadas");
}

// Endpoints de API para quizzes
app.post('/api/quiz/create', async (req, res) => {
  try {
    const { userId, title, description, questions } = req.body;

    if (!title || !questions || !Array.isArray(questions) || questions.length === 0) {
      return res.status(400).json({ error: 'TÃƒÂ­tulo y preguntas son requeridos' });
    }

    const { rows } = await pool.query(
      `INSERT INTO quizzes (user_id, title, description, questions, created_at, updated_at)
       VALUES ($1, $2, $3, $4, NOW(), NOW())
       RETURNING *`,
      [userId || null, title, description || '', JSON.stringify(questions)]
    );

    res.json({ success: true, quiz: rows[0] });
  } catch (err) {
    console.error('Error creando quiz:', err);
    res.status(500).json({ error: 'Error al crear el quiz' });
  }
});

app.get('/api/quiz/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { rows } = await pool.query('SELECT * FROM quizzes WHERE id = $1', [id]);

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Quiz no encontrado' });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error('Error obteniendo quiz:', err);
    res.status(500).json({ error: 'Error al obtener el quiz' });
  }
});

app.get('/api/quiz/user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const { rows } = await pool.query(
      'SELECT * FROM quizzes WHERE user_id = $1 ORDER BY created_at DESC',
      [userId]
    );
    res.json(rows);
  } catch (err) {
    console.error('Error obteniendo quizzes:', err);
    res.status(500).json({ error: 'Error al obtener los quizzes' });
  }
});

app.delete('/api/quiz/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM quizzes WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err) {
    console.error('Error eliminando quiz:', err);
    res.status(500).json({ error: 'Error al eliminar el quiz' });
  }
});

// Crear sala de juego
app.post('/api/quiz/start-session', async (req, res) => {
  try {
    const { quizId, hostId } = req.body;

    if (!quizId) {
      return res.status(400).json({ error: 'Quiz ID es requerido' });
    }

    // Generar PIN ÃƒÂºnico de 6 dÃƒÂ­gitos
    let roomPin;
    let exists = true;
    while (exists) {
      roomPin = Math.floor(100000 + Math.random() * 900000).toString();
      const { rows } = await pool.query('SELECT 1 FROM quiz_sessions WHERE room_pin = $1', [roomPin]);
      exists = rows.length > 0;
    }

    const { rows } = await pool.query(
      `INSERT INTO quiz_sessions (quiz_id, room_pin, host_id, state, created_at)
       VALUES ($1, $2, $3, 'waiting', NOW())
       RETURNING *`,
      [quizId, roomPin, hostId || null]
    );

    // Obtener el quiz
    const { rows: quizRows } = await pool.query('SELECT * FROM quizzes WHERE id = $1', [quizId]);

    if (quizRows.length === 0) {
      return res.status(404).json({ error: 'Quiz no encontrado' });
    }

    // Almacenar en memoria
    const quiz = quizRows[0];
    // Asegurar que las preguntas estÃƒÂ©n parseadas y normalizadas
    let questions = typeof quiz.questions === 'string'
      ? JSON.parse(quiz.questions)
      : quiz.questions;

    // Normalizar correctIndex a nÃƒÂºmeros para todas las preguntas
    questions = questions.map(q => {
      if (q.correctIndex !== undefined && q.correctIndex !== null) {
        if (Array.isArray(q.correctIndex)) {
          q.correctIndex = q.correctIndex.map(idx => typeof idx === 'string' ? parseInt(idx) : idx);
        } else {
          q.correctIndex = typeof q.correctIndex === 'string' ? parseInt(q.correctIndex) : q.correctIndex;
        }
      }
      return q;
    });

    activeRooms.set(roomPin, {
      sessionId: rows[0].id,
      quizId: quizId,
      quiz: { ...quiz, questions },
      hostId: hostId || null,
      players: [],
      currentQuestion: 0,
      scores: {},
      state: 'waiting',
      startTime: null
    });

    res.json({ success: true, roomPin, sessionId: rows[0].id });
  } catch (err) {
    console.error('Error creando sesiÃƒÂ³n:', err);
    res.status(500).json({ error: 'Error al crear la sesiÃƒÂ³n' });
  }
});

app.get('/api/quiz/session/:pin', async (req, res) => {
  try {
    const { pin } = req.params;

    // Primero buscar en memoria
    let room = activeRooms.get(pin);

    // Si no estÃƒÂ¡ en memoria, buscar en BD y recrear en memoria si estÃƒÂ¡ activa
    if (!room) {
      const { rows } = await pool.query(
        `SELECT qs.*, q.title, q.questions 
         FROM quiz_sessions qs 
         JOIN quizzes q ON qs.quiz_id = q.id 
         WHERE qs.room_pin = $1 AND qs.state IN ('waiting', 'playing')`,
        [pin]
      );

      if (rows.length === 0) {
        return res.status(404).json({ error: 'Sala no encontrada' });
      }

      const session = rows[0];
      // Parsear y normalizar preguntas
      let questions = typeof session.questions === 'string'
        ? JSON.parse(session.questions)
        : session.questions;

      // Normalizar correctIndex a nÃƒÂºmeros
      questions = questions.map(q => {
        if (q.correctIndex !== undefined && q.correctIndex !== null) {
          if (Array.isArray(q.correctIndex)) {
            q.correctIndex = q.correctIndex.map(idx => typeof idx === 'string' ? parseInt(idx) : idx);
          } else {
            q.correctIndex = typeof q.correctIndex === 'string' ? parseInt(q.correctIndex) : q.correctIndex;
          }
        }
        return q;
      });

      // Recrear sala en memoria
      room = {
        sessionId: session.id,
        quizId: session.quiz_id,
        quiz: {
          id: session.quiz_id,
          title: session.title,
          questions: questions
        },
        hostId: session.host_id,
        players: [],
        currentQuestion: session.current_question || 0,
        scores: {},
        state: session.state,
        startTime: session.started_at ? new Date(session.started_at).getTime() : null
      };

      // Cargar jugadores desde BD
      const { rows: playerRows } = await pool.query(
        'SELECT player_id, player_name, score FROM quiz_players WHERE session_id = $1',
        [session.id]
      );

      room.players = playerRows.map(p => ({
        id: p.player_id,
        name: p.player_name,
        score: p.score || 0,
        answers: []
      }));

      activeRooms.set(pin, room);
    }

    res.json({
      roomPin: pin,
      quizTitle: room.quiz.title,
      playerCount: room.players.length,
      state: room.state
    });
  } catch (err) {
    console.error('Error obteniendo sesiÃƒÂ³n:', err);
    res.status(500).json({ error: 'Error al obtener la sesiÃƒÂ³n' });
  }
});

// WebSocket para tiempo real
io.on('connection', (socket) => {
  console.log('Usuario conectado:', socket.id);

  // Host se une a una sala
  socket.on('host-join', ({ roomPin, hostId }) => {
    const room = activeRooms.get(roomPin);
    if (!room) {
      socket.emit('error', { message: 'Sala no encontrada' });
      return;
    }

    socket.join(`room-${roomPin}`);
    socket.join(`host-${roomPin}`);

    // Enviar informaciÃƒÂ³n del quiz y jugadores actuales
    socket.emit('host-joined', {
      roomPin,
      quiz: room.quiz,
      players: room.players.map(p => ({ id: p.id, name: p.name, score: p.score }))
    });
  });

  // Jugador se une a una sala
  socket.on('player-join', async ({ roomPin, playerName, playerId }) => {
    const room = activeRooms.get(roomPin);
    if (!room) {
      socket.emit('error', { message: 'Sala no encontrada' });
      return;
    }

    if (room.state !== 'waiting') {
      socket.emit('error', { message: 'La partida ya comenzÃƒÂ³' });
      return;
    }

    const player = {
      id: playerId || socket.id,
      name: playerName,
      socketId: socket.id,
      score: 0,
      answers: []
    };

    room.players.push(player);
    room.scores[player.id] = 0;
    playerSockets.set(socket.id, { playerId: player.id, roomPin, playerName });

    // Guardar jugador en BD
    try {
      await pool.query(
        `INSERT INTO quiz_players (session_id, player_id, player_name, score, answers)
         VALUES ($1, $2, $3, 0, '[]')`,
        [room.sessionId, player.id, playerName]
      );
    } catch (err) {
      console.error('Error guardando jugador:', err);
    }

    socket.join(`room-${roomPin}`);
    socket.join(`players-${roomPin}`);

    // Notificar a todos
    io.to(`room-${roomPin}`).emit('player-joined', {
      players: room.players.map(p => ({ id: p.id, name: p.name, score: p.score }))
    });

    socket.emit('player-joined-success', { playerId: player.id, roomPin: roomPin });
  });

  // Host inicia el juego
  socket.on('start-game', ({ roomPin }) => {
    const room = activeRooms.get(roomPin);
    if (!room) {
      socket.emit('error', { message: 'Sala no encontrada' });
      return;
    }

    room.state = 'playing';
    room.currentQuestion = 0;
    room.startTime = Date.now();

    // Guardar en BD
    pool.query(
      'UPDATE quiz_sessions SET state = $1, started_at = NOW(), current_question = 0 WHERE room_pin = $2',
      ['playing', roomPin]
    ).catch(err => console.error('Error actualizando sesiÃƒÂ³n:', err));

    // Obtener preguntas
    let questions = typeof room.quiz.questions === 'string'
      ? JSON.parse(room.quiz.questions)
      : room.quiz.questions;

    // Normalizar correctIndex a nÃƒÂºmeros si es necesario
    const normalizedQuestions = questions.map(q => {
      if (q.correctIndex !== undefined && q.correctIndex !== null) {
        if (Array.isArray(q.correctIndex)) {
          q.correctIndex = q.correctIndex.map(idx => typeof idx === 'string' ? parseInt(idx) : idx);
        } else {
          q.correctIndex = typeof q.correctIndex === 'string' ? parseInt(q.correctIndex) : q.correctIndex;
        }
      }
      return q;
    });

    // Actualizar el room con las preguntas normalizadas
    room.quiz.questions = normalizedQuestions;

    if (!normalizedQuestions || normalizedQuestions.length === 0) {
      socket.emit('error', { message: 'El quiz no tiene preguntas' });
      return;
    }

    // Enviar primera pregunta
    const firstQuestion = normalizedQuestions[0];
    io.to(`room-${roomPin}`).emit('question-start', {
      questionIndex: 0,
      question: firstQuestion,
      totalQuestions: normalizedQuestions.length
    });
  });

  // Jugador envÃƒÂ­a respuesta
  socket.on('submit-answer', ({ roomPin, playerId, answer, timeTaken }) => {
    console.log('submit-answer recibido:', { roomPin, playerId, answer, socketId: socket.id });
    const room = activeRooms.get(roomPin);
    if (!room) {
      console.log('Sala no encontrada:', roomPin);
      socket.emit('error', { message: 'Sala no encontrada' });
      return;
    }

    if (room.state !== 'playing') {
      console.log('Sala no estÃƒÂ¡ en estado playing:', room.state);
      socket.emit('error', { message: 'El juego no estÃƒÂ¡ en curso' });
      return;
    }

    // Buscar jugador por playerId o socketId
    const player = room.players.find(p => p.id === playerId || p.socketId === socket.id);
    if (!player) {
      console.log('Jugador no encontrado:', { playerId, socketId: socket.id, players: room.players.map(p => ({ id: p.id, socketId: p.socketId })) });
      socket.emit('error', { message: 'Jugador no encontrado en la sala' });
      return;
    }

    // Verificar si el jugador ya respondiÃƒÂ³ esta pregunta
    const alreadyAnswered = player.answers.some(a => a.questionIndex === room.currentQuestion);
    if (alreadyAnswered) {
      console.log('Jugador ya respondiÃƒÂ³ esta pregunta');
      return;
    }

    // Obtener y normalizar preguntas
    let questions = typeof room.quiz.questions === 'string'
      ? JSON.parse(room.quiz.questions)
      : room.quiz.questions;

    // Normalizar correctIndex a nÃƒÂºmeros si es necesario
    const normalizedQuestions = questions.map(q => {
      if (q.correctIndex !== undefined && q.correctIndex !== null) {
        if (Array.isArray(q.correctIndex)) {
          q.correctIndex = q.correctIndex.map(idx => typeof idx === 'string' ? parseInt(idx) : idx);
        } else {
          q.correctIndex = typeof q.correctIndex === 'string' ? parseInt(q.correctIndex) : q.correctIndex;
        }
      }
      return q;
    });

    // Actualizar el room con las preguntas normalizadas
    room.quiz.questions = normalizedQuestions;

    const currentQ = normalizedQuestions[room.currentQuestion];

    let correct = false;
    let points = 0;

    // Calcular puntos segÃƒÂºn el tipo de pregunta
    if (currentQ.type === 'multiple-choice') {
      // correctIndex puede ser un nÃƒÂºmero o un array
      if (Array.isArray(currentQ.correctIndex)) {
        correct = currentQ.correctIndex.includes(parseInt(answer));
      } else {
        correct = parseInt(answer) === currentQ.correctIndex;
      }
    } else if (currentQ.type === 'single-choice') {
      // OpciÃƒÂ³n ÃƒÂºnica: un solo ÃƒÂ­ndice correcto
      correct = parseInt(answer) === currentQ.correctIndex;
    } else if (currentQ.type === 'true-false') {
      // Verdadero/Falso: se compara con correctIndex (0 = Verdadero, 1 = Falso)
      console.log('Validando true-false:', {
        answer,
        answerParsed: parseInt(answer),
        correctIndex: currentQ.correctIndex,
        correctIndexType: typeof currentQ.correctIndex,
        question: currentQ
      });
      correct = parseInt(answer) === currentQ.correctIndex;
      console.log('Resultado validaciÃƒÂ³n true-false:', correct);
    } else if (currentQ.type === 'short-answer') {
      correct = answer.toLowerCase().trim() === currentQ.correctAnswer.toLowerCase().trim();
    } else if (currentQ.type === 'number') {
      const numAnswer = parseFloat(answer);
      const correctNum = typeof currentQ.correctAnswer === 'number' ? currentQ.correctAnswer : parseFloat(currentQ.correctAnswer);
      correct = Math.abs(numAnswer - correctNum) < 0.01; // Permitir pequeÃƒÂ±as diferencias por redondeo
    } else if (currentQ.type === 'date') {
      correct = answer.trim() === currentQ.correctAnswer.trim();
    } else if (currentQ.type === 'fill-blank') {
      correct = answer.toLowerCase().trim() === currentQ.correctAnswer.toLowerCase().trim();
    } else if (currentQ.type === 'slider') {
      const sliderAnswer = parseFloat(answer);
      const correctValue = typeof currentQ.correctAnswer === 'number' ? currentQ.correctAnswer : parseFloat(currentQ.correctAnswer);
      // Permitir pequeÃƒÂ±a tolerancia para valores numÃƒÂ©ricos
      correct = Math.abs(sliderAnswer - correctValue) < 0.01;
    } else if (currentQ.type === 'code') {
      correct = answer.toLowerCase().trim() === currentQ.correctAnswer.toLowerCase().trim();
    }

    if (correct) {
      // Puntos base: 1000, con bonus por velocidad (mÃƒÂ¡ximo 30 segundos)
      const maxTime = currentQ.timeLimit || 30;
      const timeBonus = Math.max(0, Math.floor((maxTime - timeTaken) / maxTime * 500));
      let basePoints = 1000 + timeBonus;

      // Aplicar modificadores
      if (currentQ.modifier === 'x2') {
        basePoints *= 2;
      } else if (currentQ.modifier === 'x3') {
        basePoints *= 3;
      } else if (currentQ.modifier === 'no-points') {
        basePoints = 0;
      } else if (currentQ.modifier === 'time-bonus') {
        basePoints += Math.floor((maxTime - timeTaken) / maxTime * 1000);
      } else if (currentQ.modifier === 'streak') {
        // Bonus por racha de respuestas correctas
        const streak = player.answers.filter(a => a.correct).length;
        basePoints += streak * 100;
      }

      points = basePoints;
      player.score += points;
      room.scores[player.id] = player.score;
    }

    player.answers.push({
      questionIndex: room.currentQuestion,
      answer,
      correct,
      points,
      timeTaken
    });

    // Guardar respuesta en BD (actualizar o insertar si no existe)
    pool.query(
      `INSERT INTO quiz_players (session_id, player_id, player_name, score, answers)
       VALUES ($1, $2, $3, $4, $5::jsonb)
       ON CONFLICT (session_id, player_id) 
       DO UPDATE SET answers = EXCLUDED.answers, score = EXCLUDED.score`,
      [room.sessionId, player.id, player.name, player.score, JSON.stringify(player.answers)]
    ).catch(err => {
      console.error('Error guardando respuesta:', err);
    });

    // Notificar al host sobre respuesta recibida
    console.log('Enviando player-answer al host:', { playerId: player.id, playerName: player.name });
    io.to(`host-${roomPin}`).emit('player-answer', {
      playerId: player.id,
      playerName: player.name,
      answered: true
    });

    socket.emit('answer-received', { correct, points, totalScore: player.score });
    console.log('Respuesta procesada:', { playerName: player.name, correct, points, totalScore: player.score });

    // Enviar leaderboard actualizado a todos los jugadores
    const leaderboard = room.players
      .map(p => ({ id: p.id, name: p.name, score: p.score }))
      .sort((a, b) => b.score - a.score);
    io.to(`room-${roomPin}`).emit('current-leaderboard', { leaderboard });
  });

  // Jugador solicita leaderboard actual
  socket.on('get-current-leaderboard', ({ roomPin }) => {
    const room = activeRooms.get(roomPin);
    if (!room) return;

    const leaderboard = room.players
      .map(p => ({ id: p.id, name: p.name, score: p.score }))
      .sort((a, b) => b.score - a.score);
    socket.emit('current-leaderboard', { leaderboard });
  });

  // Host avanza a siguiente pregunta o muestra resultados finales
  socket.on('next-question', ({ roomPin }) => {
    const room = activeRooms.get(roomPin);
    if (!room) return;

    const questions = typeof room.quiz.questions === 'string'
      ? JSON.parse(room.quiz.questions)
      : room.quiz.questions;

    room.currentQuestion++;

    // Actualizar en BD
    pool.query(
      'UPDATE quiz_sessions SET current_question = $1 WHERE room_pin = $2',
      [room.currentQuestion, roomPin]
    ).catch(err => console.error('Error actualizando pregunta actual:', err));

    if (room.currentQuestion >= questions.length) {
      // Fin del juego - mostrar resultados finales
      room.state = 'results';
      pool.query(
        'UPDATE quiz_sessions SET state = $1, ended_at = NOW() WHERE room_pin = $2',
        ['finished', roomPin]
      ).catch(err => console.error('Error actualizando estado final:', err));

      const leaderboard = room.players
        .map(p => ({ id: p.id, name: p.name, score: p.score }))
        .sort((a, b) => b.score - a.score);

      io.to(`room-${roomPin}`).emit('game-end', { leaderboard });
    } else {
      // Siguiente pregunta
      const question = questions[room.currentQuestion];
      io.to(`room-${roomPin}`).emit('question-start', {
        questionIndex: room.currentQuestion,
        question: question,
        totalQuestions: questions.length
      });
    }
  });

  // Host muestra resultados despuÃƒÂ©s de cada pregunta
  socket.on('show-results', ({ roomPin }) => {
    const room = activeRooms.get(roomPin);
    if (!room) return;

    const questions = typeof room.quiz.questions === 'string'
      ? JSON.parse(room.quiz.questions)
      : room.quiz.questions;
    const currentQ = questions[room.currentQuestion];

    // Calcular estadÃƒÂ­sticas de respuestas
    const answeredPlayers = room.players.filter(p => p.answers.length > room.currentQuestion);
    const stats = {
      total: room.players.length,
      answered: answeredPlayers.length,
      correct: 0
    };

    answeredPlayers.forEach(player => {
      const answer = player.answers[room.currentQuestion];
      if (answer && answer.correct) {
        stats.correct++;
      }
    });

    // Enviar resultados intermedios al host
    io.to(`host-${roomPin}`).emit('question-results', {
      question: currentQ,
      stats: stats,
      leaderboard: room.players
        .map(p => ({ id: p.id, name: p.name, score: p.score }))
        .sort((a, b) => b.score - a.score)
    });
  });

  // =============================
  // AWQG multiplayer socket flow
  // =============================
  socket.on('awqg:host-connect', ({ code, hostName }) => {
    const room = awqgRooms.get(String(code || '').toUpperCase());
    if (!room) {
      socket.emit('awqg:error', { message: 'Sala no encontrada' });
      return;
    }
    room.host.socketId = socket.id;
    if (hostName) room.host.name = String(hostName).slice(0, 40);
    socket.join(`awqg-${room.code}`);
    awqgSocketToRoom.set(socket.id, room.code);
    socket.emit('awqg:host-ready', { room: getAwqgRoomPublic(room) });
    emitAwqgRoomState(room.code);
  });

  socket.on('awqg:join-room', ({ code, guestName }) => {
    const room = awqgRooms.get(String(code || '').toUpperCase());
    if (!room) {
      socket.emit('awqg:error', { message: 'Cï¿½digo invï¿½lido o sala inexistente.' });
      return;
    }
    if (room.guest && room.guest.socketId && room.guest.socketId !== socket.id) {
      socket.emit('awqg:error', { message: 'La sala ya tiene 2 jugadores.' });
      return;
    }
    room.guest = {
      socketId: socket.id,
      name: String(guestName || 'Jugador 2').slice(0, 40)
    };
    if (room.status === 'waiting') room.status = 'selecting';
    socket.join(`awqg-${room.code}`);
    awqgSocketToRoom.set(socket.id, room.code);
    io.to(`awqg-${room.code}`).emit('awqg:guest-joined', {
      room: getAwqgRoomPublic(room)
    });
    emitAwqgRoomState(room.code);
  });

  socket.on('awqg:set-category', ({ code, category }) => {
    const room = awqgRooms.get(String(code || '').toUpperCase());
    if (!room) return;
    const role = getAwqgRole(room, socket.id);
    if (role !== 'host') {
      socket.emit('awqg:error', { message: 'Solo el anfitriï¿½n puede elegir categorï¿½a.' });
      return;
    }
    room.category = String(category || '');
    room.status = 'selecting';
    io.to(`awqg-${room.code}`).emit('awqg:category-selected', { category: room.category });
    emitAwqgRoomState(room.code);
  });

  socket.on('awqg:set-secret', ({ code, secret }) => {
    const room = awqgRooms.get(String(code || '').toUpperCase());
    if (!room) return;
    const role = getAwqgRole(room, socket.id);
    if (!role) return;
    if (!secret || !secret.id || !secret.name || !secret.traits) {
      socket.emit('awqg:error', { message: 'Personaje secreto invï¿½lido.' });
      return;
    }

    const safeSecret = {
      id: String(secret.id),
      name: String(secret.name),
      traits: typeof secret.traits === 'object' && secret.traits ? secret.traits : {}
    };

    if (role === 'host') room.hostSecret = safeSecret;
    if (role === 'guest') room.guestSecret = safeSecret;

    emitAwqgRoomState(room.code);
    io.to(`awqg-${room.code}`).emit('awqg:secret-progress', {
      hostSecretSelected: !!room.hostSecret,
      guestSecretSelected: !!room.guestSecret
    });

    if (room.hostSecret && room.guestSecret && room.category) {
      room.status = 'playing';
      room.currentTurn = 'host';
      room.questionsLeftThisTurn = 1;
      room.extraQuestionFor = null;
      room.pendingQuestion = null;
      room.noGuessSwitches = 0;
      room.finalDuel = { active: false, hostChoice: null, guestChoice: null };
      io.to(`awqg-${room.code}`).emit('awqg:game-started', {
        room: getAwqgRoomPublic(room)
      });
      emitAwqgTurnState(room.code);
    }
  });

  socket.on('awqg:ask-question', ({ code, question }) => {
    const room = awqgRooms.get(String(code || '').toUpperCase());
    if (!room || room.status !== 'playing') return;
    if (room.finalDuel?.active) return;
    const role = getAwqgRole(room, socket.id);
    if (!role) return;
    if (role !== room.currentTurn) {
      socket.emit('awqg:error', { message: 'No es tu turno.' });
      return;
    }
    if (room.questionsLeftThisTurn <= 0) {
      socket.emit('awqg:error', { message: 'No te quedan preguntas en este turno.' });
      return;
    }
    if (!question || !question.trait) {
      socket.emit('awqg:error', { message: 'Pregunta invï¿½lida.' });
      return;
    }

    const targetSecret = role === 'host' ? room.guestSecret : room.hostSecret;
    if (!targetSecret || !targetSecret.traits) {
      socket.emit('awqg:error', { message: 'No se pudo evaluar la pregunta.' });
      return;
    }

    const trait = String(question.trait);
    const value = question.value;
    const traitValue = targetSecret.traits[trait];
    const autoAnswer = traitValue === value;

    room.pendingQuestion = {
      askedBy: role,
      question: {
        text: String(question.text || ''),
        trait,
        value
      },
      answer: autoAnswer
    };

    room.questionsLeftThisTurn -= 1;
    io.to(`awqg-${room.code}`).emit('awqg:question-result', {
      askedBy: role,
      question: room.pendingQuestion.question,
      answer: autoAnswer,
      questionsLeftThisTurn: room.questionsLeftThisTurn
    });

    if (room.questionsLeftThisTurn <= 0) {
      switchAwqgTurn(room);
      io.to(`awqg-${room.code}`).emit('awqg:turn-switched', {
        currentTurn: room.currentTurn,
        questionsLeftThisTurn: room.questionsLeftThisTurn
      });
      if ((room.noGuessSwitches || 0) >= 6) {
        startAwqgFinalDuel(room, 'El duelo se estancï¿½. Se activa la DECISIï¿½N FINAL para ambos jugadores.');
      }
    } else {
      emitAwqgTurnState(room.code);
    }
  });

  socket.on('awqg:skip-turn', ({ code }) => {
    const room = awqgRooms.get(String(code || '').toUpperCase());
    if (!room || room.status !== 'playing') return;
    if (room.finalDuel?.active) return;
    const role = getAwqgRole(room, socket.id);
    if (!role || role !== room.currentTurn) return;
    room.extraQuestionFor = role === 'host' ? 'guest' : 'host';
    switchAwqgTurn(room);
    io.to(`awqg-${room.code}`).emit('awqg:turn-skipped', {
      skippedBy: role,
      currentTurn: room.currentTurn,
      questionsLeftThisTurn: room.questionsLeftThisTurn
    });
    if ((room.noGuessSwitches || 0) >= 6) {
      startAwqgFinalDuel(room, 'Demasiados turnos sin cierre. Se activa la DECISIï¿½N FINAL.');
    }
  });

  socket.on('awqg:end-turn', ({ code }) => {
    const room = awqgRooms.get(String(code || '').toUpperCase());
    if (!room || room.status !== 'playing') return;
    if (room.finalDuel?.active) return;
    const role = getAwqgRole(room, socket.id);
    if (!role || role !== room.currentTurn) return;
    switchAwqgTurn(room);
    io.to(`awqg-${room.code}`).emit('awqg:turn-switched', {
      currentTurn: room.currentTurn,
      questionsLeftThisTurn: room.questionsLeftThisTurn
    });
    if ((room.noGuessSwitches || 0) >= 6) {
      startAwqgFinalDuel(room, 'Demasiados turnos sin cierre. Se activa la DECISIï¿½N FINAL.');
    }
  });

  socket.on('awqg:guess', ({ code, guess }) => {
    const room = awqgRooms.get(String(code || '').toUpperCase());
    if (!room || room.status !== 'playing') return;
    if (room.finalDuel?.active) return;
    const role = getAwqgRole(room, socket.id);
    if (!role || role !== room.currentTurn) return;

    const targetSecret = role === 'host' ? room.guestSecret : room.hostSecret;
    if (!targetSecret) return;
    room.noGuessSwitches = 0;

    const ok = String(guess || '').trim().toLowerCase() === String(targetSecret.name || '').trim().toLowerCase();
    if (ok) {
      room.status = 'finished';
      io.to(`awqg-${room.code}`).emit('awqg:victory', {
        winner: role,
        winnerName: role === 'host' ? room.host?.name : room.guest?.name,
        guessed: guess,
        expected: targetSecret.name
      });
      return;
    }

    switchAwqgTurn(room);
    io.to(`awqg-${room.code}`).emit('awqg:guess-failed', {
      guessedBy: role,
      guessed: guess,
      currentTurn: room.currentTurn,
      questionsLeftThisTurn: room.questionsLeftThisTurn
    });
  });

  socket.on('awqg:request-final-duel', ({ code }) => {
    const room = awqgRooms.get(String(code || '').toUpperCase());
    if (!room || room.status !== 'playing') return;
    const role = getAwqgRole(room, socket.id);
    if (!role) return;
    startAwqgFinalDuel(room, 'Candidatos mï¿½nimos detectados. Inicia el protocolo de DECISIï¿½N FINAL.');
  });

  socket.on('awqg:submit-final-choice', ({ code, choice }) => {
    const room = awqgRooms.get(String(code || '').toUpperCase());
    if (!room || room.status !== 'playing') return;
    if (!room.finalDuel?.active) return;
    const role = getAwqgRole(room, socket.id);
    if (!role) return;
    const normalizedChoice = String(choice || '').trim();
    if (!normalizedChoice) return;

    if (role === 'host') room.finalDuel.hostChoice = normalizedChoice;
    if (role === 'guest') room.finalDuel.guestChoice = normalizedChoice;
    io.to(`awqg-${room.code}`).emit('awqg:final-choice-submitted', { by: role });

    const hostChoice = room.finalDuel.hostChoice;
    const guestChoice = room.finalDuel.guestChoice;
    if (!hostChoice || !guestChoice) return;

    const hostCorrect = hostChoice.toLowerCase() === String(room.guestSecret?.name || '').toLowerCase();
    const guestCorrect = guestChoice.toLowerCase() === String(room.hostSecret?.name || '').toLowerCase();
    let winner = null;
    if (hostCorrect && !guestCorrect) winner = 'host';
    if (guestCorrect && !hostCorrect) winner = 'guest';
    if (winner) room.status = 'finished';

    io.to(`awqg-${room.code}`).emit('awqg:final-reveal', {
      winner,
      hostCorrect,
      guestCorrect,
      hostChoice,
      guestChoice
    });

    room.finalDuel = { active: false, hostChoice: null, guestChoice: null };
  });

  // DesconexiÃƒÂ³n
  socket.on('disconnect', () => {
    const playerData = playerSockets.get(socket.id);
    if (playerData) {
      const room = activeRooms.get(playerData.roomPin);
      if (room) {
        room.players = room.players.filter(p => p.socketId !== socket.id);
        io.to(`room-${playerData.roomPin}`).emit('player-left', {
          players: room.players.map(p => ({ id: p.id, name: p.name, score: p.score }))
        });
      }
      playerSockets.delete(socket.id);
    }

    const awqgCode = awqgSocketToRoom.get(socket.id);
    if (awqgCode) {
      const room = awqgRooms.get(awqgCode);
      if (room) {
        const role = getAwqgRole(room, socket.id);
        if (role === 'host') {
          io.to(`awqg-${awqgCode}`).emit('awqg:host-left', { message: 'El anfitriï¿½n saliï¿½ de la sala.' });
          awqgRooms.delete(awqgCode);
        } else if (role === 'guest') {
          room.guest = null;
          room.guestSecret = null;
          room.status = 'waiting';
          room.currentTurn = 'host';
          room.questionsLeftThisTurn = 1;
          room.extraQuestionFor = null;
          room.pendingQuestion = null;
          room.noGuessSwitches = 0;
          room.finalDuel = { active: false, hostChoice: null, guestChoice: null };
          io.to(`awqg-${awqgCode}`).emit('awqg:guest-left', { message: 'El jugador 2 se desconectï¿½.' });
          emitAwqgRoomState(awqgCode);
        }
      }
      awqgSocketToRoom.delete(socket.id);
    }
  });

  // WildWave: join user room for process updates
  socket.on('ww:join', ({ userId }) => {
    if (userId) socket.join(`ww-user-${userId}`);
  });
  socket.on('ww:leave', ({ userId }) => {
    if (userId) socket.leave(`ww-user-${userId}`);
  });
});

// Servir archivo HTML del quiz
app.get('/quiz', (_req, res) => {
  try {
    const html = fs.readFileSync(join(__dirname, 'Quiz NatCreator', 'index.html'), 'utf-8');
    res.type('html').send(html);
  } catch (e) {
    res.status(404).send('Archivo no encontrado');
  }
});

// ====================
// DeepDive Pro - subscriptions with Ocean Pay charge (WildCredits)
// ====================

// Ensure DeepDive tables (idempotent)
async function ensureDeepDiveTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS subscriptions (
      id SERIAL PRIMARY KEY,
      user_id TEXT NOT NULL,
      plan VARCHAR(50) NOT NULL,
      status VARCHAR(20) NOT NULL,
      starts_at TIMESTAMP WITH TIME ZONE NOT NULL,
      ends_at   TIMESTAMP WITH TIME ZONE NOT NULL,
      payment_method VARCHAR(50),
      payment_amount DECIMAL(10,2),
      created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
      updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
      cancelled_at TIMESTAMP WITH TIME ZONE
    );
    CREATE TABLE IF NOT EXISTS payments (
      id SERIAL PRIMARY KEY,
      user_id TEXT NOT NULL,
      amount DECIMAL(10,2) NOT NULL,
      currency VARCHAR(10) NOT NULL,
      status VARCHAR(20) NOT NULL,
      payment_method VARCHAR(50),
      subscription_plan VARCHAR(50),
      description TEXT,
      error TEXT,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_subscriptions_user_id ON subscriptions(user_id)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_subscriptions_status  ON subscriptions(status)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_payments_user_id ON payments(user_id)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_payments_created_at ON payments(created_at)`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS ux_subscriptions_active_user ON subscriptions(user_id) WHERE status = 'active'`);
}

// Decode an OP token (STUDIO_SECRET) specifically for charging
function getOPUserId(req) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return null;
  const token = auth.substring(7);
  try {
    const d = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    // Ocean Pay tokens carry `uid`
    return d.uid || d.userId || d.id || null;
  } catch {
    return null;
  }
}

// Decode a general app token for subscription record fallback
function getAppUserId(req) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return null;
  const token = auth.substring(7);
  try {
    const d = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    return d.userId || d.uid || d.id || null;
  } catch {
    return null;
  }
}

async function oceanPayHasMonedaColumn() {
  try {
    const { rows } = await pool.query(`
      SELECT column_name FROM information_schema.columns
      WHERE table_name = 'ocean_pay_txs' AND column_name = 'moneda'
    `);
    return rows.length > 0;
  } catch {
    return false;
  }
}

ensureDeepDiveTables().catch(e => console.error('[DeepDive] table init:', e.message));

// GET status
app.get('/deepdive/subscription/status', async (req, res) => {
  const appUid = getAppUserId(req) || getOPUserId(req);
  if (!appUid) return res.status(401).json({ error: 'Token required' });

  try {
    const { rows } = await pool.query(
      `SELECT plan, starts_at, ends_at, status, created_at
         FROM subscriptions
        WHERE user_id = $1 AND status = 'active'
        ORDER BY ends_at DESC LIMIT 1`,
      [String(appUid)]
    );
    if (rows.length) {
      const nowTs = new Date();
      const ends = new Date(rows[0].ends_at);
      const msRemain = ends.getTime() - nowTs.getTime();
      const daysRemaining = Math.ceil(msRemain / (1000 * 60 * 60 * 24));
      const overdue = msRemain <= 0;
      return res.json({
        isActive: !overdue,
        plan: rows[0].plan,
        startsAt: rows[0].starts_at,
        endsAt: rows[0].ends_at,
        nextChargeAt: rows[0].ends_at,
        daysRemaining: overdue ? 0 : daysRemaining,
        overdue,
        createdAt: rows[0].created_at
      });
    }
    return res.json({ isActive: false });
  } catch (err) {
    console.error('[DeepDive] status error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST subscribe: charge OP WildCredits, log tx, upsert subscription
app.post('/deepdive/subscription/subscribe', async (req, res) => {
  // Require Ocean Pay token for charge
  const opUid = getOPUserId(req);
  if (!opUid) {
    return res.status(401).json({ error: 'Please connect your Ocean Pay account (OP token required)' });
  }
  // Use app token if available for subscription record, else fall back to OP uid
  const appUid = getAppUserId(req) || opUid;

  const { plan } = req.body || {};
  if (!plan || (plan !== 'monthly' && plan !== 'weekly')) {
    return res.status(400).json({ error: 'Invalid plan (must be weekly or monthly)' });
  }

  // Pricing: Weekly 15 WC, Monthly 50 WC
  const normalizedAmount = plan === 'weekly' ? 15 : 50;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Lock WC balance
    await client.query(`
      CREATE TABLE IF NOT EXISTS ocean_pay_metadata (
        user_id INTEGER NOT NULL,
        key TEXT NOT NULL,
        value TEXT NOT NULL,
        PRIMARY KEY (user_id, key)
      )
    `);

    const opUserIdInt = parseInt(opUid); // OP ids are integer in ocean_pay_metadata
    if (Number.isNaN(opUserIdInt)) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Invalid Ocean Pay user id' });
    }

    const { rows: wcRows } = await client.query(
      `SELECT value FROM ocean_pay_metadata WHERE user_id = $1 AND key = 'wildcredits' FOR UPDATE`,
      [opUserIdInt]
    );
    const currentWC = parseInt(wcRows[0]?.value || '0');
    if (currentWC < normalizedAmount) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: `Insufficient WildCredits. Need ${normalizedAmount}.` });
    }

    const newWC = currentWC - normalizedAmount;
    await client.query(
      `INSERT INTO ocean_pay_metadata (user_id, key, value)
         VALUES ($1, 'wildcredits', $2)
       ON CONFLICT (user_id, key)
       DO UPDATE SET value = $2`,
      [opUserIdInt, String(newWC)]
    );

    // Ensure OP tx table exists (idempotent)
    await client.query(`
      CREATE TABLE IF NOT EXISTS ocean_pay_txs (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        concepto TEXT NOT NULL,
        monto NUMERIC(20,2) NOT NULL,
        origen TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        moneda TEXT
      )
    `);
    // If table already existed without currency column, add it
    await client.query(`ALTER TABLE ocean_pay_txs ADD COLUMN IF NOT EXISTS moneda TEXT`);

    // Log OP tx (moneda='WC' if column exists)
    const hasMoneda = await oceanPayHasMonedaColumn();
    const concept = `SuscripciÃƒÂ³n Pro (DeepDive) - ${plan === 'weekly' ? 'Semanal' : 'Mensual'}`;
    if (hasMoneda) {
      await client.query(
        `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
         VALUES ($1, $2, $3, $4, 'WC')`,
        [opUserIdInt, concept, -normalizedAmount, 'DeepDive']
      );
    } else {
      await client.query(
        `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen)
         VALUES ($1, $2, $3, $4)`,
        [opUserIdInt, concept, -normalizedAmount, 'DeepDive']
      );
    }

    // Upsert/extend DeepDive subscription for appUid (string)
    const now = new Date();

    const { rows: active } = await client.query(
      `SELECT id, ends_at FROM subscriptions
        WHERE user_id = $1 AND status = 'active'
        ORDER BY ends_at DESC
        LIMIT 1`,
      [String(appUid)]
    );

    let baseDate = now;
    if (active.length) {
      const currentEnd = new Date(active[0].ends_at);
      // extend from current end if still in future, else from now
      if (currentEnd > now) baseDate = currentEnd;
    }

    const endsAt = new Date(baseDate);
    if (plan === 'weekly') {
      endsAt.setDate(endsAt.getDate() + 7);
    } else {
      endsAt.setDate(endsAt.getDate() + 30);
    }

    if (active.length) {
      await client.query(
        `UPDATE subscriptions
           SET plan = $1, status = 'active', starts_at = $2, ends_at = $3,
               updated_at = NOW(), payment_method = $4, payment_amount = $5
         WHERE id = $6`,
        [plan, now, endsAt, 'Ocean Pay (WildCredits)', normalizedAmount, active[0].id]
      );
    } else {
      await client.query(
        `INSERT INTO subscriptions (user_id, plan, status, starts_at, ends_at, payment_method, payment_amount)
         VALUES ($1, $2, 'active', $3, $4, $5, $6)`,
        [String(appUid), plan, now, endsAt, 'Ocean Pay (WildCredits)', normalizedAmount]
      );
    }

    // Payment log
    await client.query(
      `INSERT INTO payments (user_id, amount, currency, status, payment_method, subscription_plan, description)
       VALUES ($1, $2, 'WC', 'completed', $3, $4, 'DeepDive Pro Subscription')`,
      [String(appUid), normalizedAmount, 'Ocean Pay (WildCredits)', plan]
    );

    await client.query('COMMIT');
    res.json({ success: true, plan, endsAt, newWC });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[DeepDive] subscribe charge error:', err);

    // Failure payment log
    try {
      await pool.query(
        `INSERT INTO payments (user_id, amount, currency, status, payment_method, subscription_plan, description, error)
         VALUES ($1, $2, 'WC', 'failed', $3, $4, 'DeepDive Pro Subscription', $5)`,
        [String(getAppUserId(req) || opUid), normalizedAmount, 'Ocean Pay (WildCredits)', plan || 'unknown', err.message]
      );
    } catch { }

    res.status(500).json({ error: 'Failed to process subscription' });
  } finally {
    client.release();
  }
});

// POST cancel
app.post('/deepdive/subscription/cancel', async (req, res) => {
  const appUid = getAppUserId(req) || getOPUserId(req);
  if (!appUid) return res.status(401).json({ error: 'Token required' });

  try {
    const { rowCount } = await pool.query(
      `UPDATE subscriptions
         SET status = 'cancelled', cancelled_at = NOW(), updated_at = NOW()
       WHERE user_id = $1 AND status = 'active'`,
      [String(appUid)]
    );
    if (!rowCount) return res.status(404).json({ error: 'No active subscription found' });
    res.json({ success: true, cancelledAt: new Date().toISOString() });
  } catch (err) {
    console.error('[DeepDive] cancel error:', err);
    res.status(500).json({ error: 'Failed to cancel subscription' });
  }
});

// POST renew: charge according to current plan and extend due date
app.post('/deepdive/subscription/renew', async (req, res) => {
  const opUid = getOPUserId(req);
  if (!opUid) return res.status(401).json({ error: 'Please connect your Ocean Pay account (OP token required)' });
  const appUid = getAppUserId(req) || opUid;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // get active subscription (or most recent)
    const { rows: subs } = await client.query(
      `SELECT id, plan, ends_at FROM subscriptions
       WHERE user_id = $1 AND status='active'
       ORDER BY ends_at DESC LIMIT 1`,
      [String(appUid)]
    );
    if (!subs.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'No subscription found to renew' });
    }

    const plan = subs[0].plan;
    const amount = plan === 'weekly' ? 15 : 50;

    // Ensure metadata table
    await client.query(`
      CREATE TABLE IF NOT EXISTS ocean_pay_metadata (
        user_id INTEGER NOT NULL,
        key TEXT NOT NULL,
        value TEXT NOT NULL,
        PRIMARY KEY (user_id, key)
      )
    `);

    const opUserIdInt = parseInt(opUid);
    const { rows: wcRows } = await client.query(
      `SELECT value FROM ocean_pay_metadata WHERE user_id = $1 AND key = 'wildcredits' FOR UPDATE`,
      [opUserIdInt]
    );
    const currentWC = parseInt(wcRows[0]?.value || '0');
    if (currentWC < amount) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: `Insufficient WildCredits. Need ${amount}.` });
    }

    const newWC = currentWC - amount;
    await client.query(
      `INSERT INTO ocean_pay_metadata (user_id, key, value)
         VALUES ($1, 'wildcredits', $2)
       ON CONFLICT (user_id, key)
       DO UPDATE SET value = $2`,
      [opUserIdInt, String(newWC)]
    );

    // Ensure tx table and moneda column
    await client.query(`
      CREATE TABLE IF NOT EXISTS ocean_pay_txs (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        concepto TEXT NOT NULL,
        monto NUMERIC(20,2) NOT NULL,
        origen TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        moneda TEXT
      )`);
    await client.query(`ALTER TABLE ocean_pay_txs ADD COLUMN IF NOT EXISTS moneda TEXT`);

    const hasMoneda = await oceanPayHasMonedaColumn();
    const concept = `RenovaciÃƒÂ³n Pro (DeepDive) - ${plan === 'weekly' ? 'Semanal' : 'Mensual'}`;
    if (hasMoneda) {
      await client.query(
        `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
         VALUES ($1, $2, $3, $4, 'WC')`,
        [opUserIdInt, concept, -amount, 'DeepDive']
      );
    } else {
      await client.query(
        `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen)
         VALUES ($1, $2, $3, $4)`,
        [opUserIdInt, concept, -amount, 'DeepDive']
      );
    }

    // Extend subscription ends_at
    const now = new Date();
    const currentEnd = new Date(subs[0].ends_at);
    const baseDate = currentEnd > now ? currentEnd : now;
    const newEnd = new Date(baseDate);
    if (plan === 'weekly') newEnd.setDate(newEnd.getDate() + 7); else newEnd.setDate(newEnd.getDate() + 30);

    await client.query(
      `UPDATE subscriptions SET ends_at=$1, updated_at=NOW(), payment_method=$2, payment_amount=$3 WHERE id=$4`,
      [newEnd, 'Ocean Pay (WildCredits)', amount, subs[0].id]
    );

    await client.query(
      `INSERT INTO payments (user_id, amount, currency, status, payment_method, subscription_plan, description)
       VALUES ($1, $2, 'WC', 'completed', $3, $4, 'DeepDive Pro Renewal')`,
      [String(appUid), amount, 'Ocean Pay (WildCredits)', plan]
    );

    await client.query('COMMIT');
    res.json({ success: true, plan, newEndsAt: newEnd, newWC });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[DeepDive] renew error:', err);
    res.status(500).json({ error: 'Failed to renew subscription' });
  } finally {
    client.release();
  }
});

// GET history
app.get('/deepdive/subscription/history', async (req, res) => {
  const appUid = getAppUserId(req) || getOPUserId(req);
  if (!appUid) return res.status(401).json({ error: 'Token required' });

  try {
    const { rows: subscriptions } = await pool.query(
      `SELECT id, plan, status,
              starts_at AS "startsAt",
              ends_at   AS "endsAt",
              created_at AS "createdAt",
              cancelled_at AS "cancelledAt"
         FROM subscriptions
        WHERE user_id = $1
        ORDER BY created_at DESC`,
      [String(appUid)]
    );
    const { rows: payments } = await pool.query(
      `SELECT id, amount, currency, status,
              payment_method AS "paymentMethod",
              subscription_plan AS "subscriptionPlan",
              description, created_at AS "createdAt"
         FROM payments
        WHERE user_id = $1
        ORDER BY created_at DESC`,
      [String(appUid)]
    );
    res.json({ subscriptions, payments });
  } catch (err) {
    console.error('[DeepDive] history error:', err);
    res.status(500).json({ error: 'Failed to fetch subscription history' });
  }
});

// WildWave - mini red social
// Sirve la SPA desde carpeta WildWave
app.get('/wildwave', (_req, res) => {
  res.sendFile(join(__dirname, 'WildWave', 'index.html'));
});

// Compatibilidad legacy con el nombre anterior
app.get('/wildx', (_req, res) => {
  res.redirect(302, '/wildwave');
});

// Compatibilidad de API antigua (/wildx/api/* -> /wildwave/api/*)
app.use('/wildx/api', (req, _res, next) => {
  req.url = `/wildwave/api${req.url}`;
  next();
});
// === WildX Auth helpers ===
async function ensureWildXTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS wildx_users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      display_name TEXT,
      pwd_hash TEXT NOT NULL,
      avatar_url TEXT,
      username_changed_at TIMESTAMP,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query('ALTER TABLE wildx_users ADD COLUMN IF NOT EXISTS avatar_url TEXT');
  await pool.query('ALTER TABLE wildx_users ADD COLUMN IF NOT EXISTS display_name TEXT');
  await pool.query('ALTER TABLE wildx_users ADD COLUMN IF NOT EXISTS username_changed_at TIMESTAMP');
  await pool.query('ALTER TABLE wildx_users ADD COLUMN IF NOT EXISTS bio TEXT');

  // Tabla principal de posts (con soporte para respuestas y likes)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS wildx_posts (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES wildx_users(id) ON DELETE SET NULL,
      username TEXT,
      content TEXT NOT NULL,
      images JSONB NOT NULL DEFAULT '[]'::jsonb,
      created_at TIMESTAMP DEFAULT NOW(),
      parent_id INTEGER REFERENCES wildx_posts(id) ON DELETE CASCADE,
      likes_count INTEGER NOT NULL DEFAULT 0
    )
  `);

  // Asegurar columnas nuevas si la tabla ya existÃƒÂ­a
  await pool.query('ALTER TABLE wildx_posts ADD COLUMN IF NOT EXISTS parent_id INTEGER REFERENCES wildx_posts(id) ON DELETE CASCADE');
  await pool.query("ALTER TABLE wildx_posts ADD COLUMN IF NOT EXISTS likes_count INTEGER NOT NULL DEFAULT 0");

  // Colaboradores por post
  await pool.query(`
    CREATE TABLE IF NOT EXISTS wildx_post_collaborators (
      id SERIAL PRIMARY KEY,
      post_id INTEGER NOT NULL REFERENCES wildx_posts(id) ON DELETE CASCADE,
      collaborator_id INTEGER NOT NULL REFERENCES wildx_users(id) ON DELETE CASCADE,
      requested_by INTEGER NOT NULL REFERENCES wildx_users(id) ON DELETE CASCADE,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT NOW(),
      responded_at TIMESTAMP
    )
  `);
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_wildx_post_collaborators_unique
      ON wildx_post_collaborators(post_id, collaborator_id)
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_wildx_post_collaborators_collab
      ON wildx_post_collaborators(collaborator_id, status)
  `);

  // Tabla de likes por usuario/post
  await pool.query(`
    CREATE TABLE IF NOT EXISTS wildx_likes (
      user_id INTEGER NOT NULL REFERENCES wildx_users(id) ON DELETE CASCADE,
      post_id INTEGER NOT NULL REFERENCES wildx_posts(id) ON DELETE CASCADE,
      created_at TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY (user_id, post_id)
    )
  `);

  // Tabla de verificaciones (blue / gold / black, etc.)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS wildx_verifications (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES wildx_users(id) ON DELETE CASCADE,
      tier TEXT NOT NULL,
      reason TEXT NOT NULL,
      started_at TIMESTAMP NOT NULL DEFAULT NOW(),
      valid_until TIMESTAMP NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query("ALTER TABLE wildx_verifications ADD COLUMN IF NOT EXISTS plan_id TEXT");
  await pool.query("ALTER TABLE wildx_verifications ADD COLUMN IF NOT EXISTS badge_color TEXT");
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_wildx_verifications_user_tier
      ON wildx_verifications(user_id, tier)
  `);

  // Saldo de WildX Tokens (WXT) por usuario
  await pool.query(`
    CREATE TABLE IF NOT EXISTS wildx_balances (
      user_id INTEGER PRIMARY KEY REFERENCES wildx_users(id) ON DELETE CASCADE,
      wxt_balance NUMERIC(20,2) NOT NULL DEFAULT 0
    )
  `);

  // Promociones de posts usando WXT
  await pool.query(`
    CREATE TABLE IF NOT EXISTS wildx_promotions (
      id SERIAL PRIMARY KEY,
      post_id INTEGER NOT NULL REFERENCES wildx_posts(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES wildx_users(id) ON DELETE CASCADE,
      amount_wxt NUMERIC(20,2) NOT NULL,
      created_at TIMESTAMP DEFAULT NOW(),
      last_shown_at TIMESTAMP,
      active BOOLEAN NOT NULL DEFAULT TRUE
    )
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_wildx_promotions_active
      ON wildx_promotions(active, created_at DESC)
  `);

  // Historial de transacciones de WXT (donaciones recibidas)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS wildx_wxt_txs (
      id SERIAL PRIMARY KEY,
      from_user_id INTEGER REFERENCES wildx_users(id) ON DELETE SET NULL,
      to_user_id INTEGER NOT NULL REFERENCES wildx_users(id) ON DELETE CASCADE,
      post_id INTEGER REFERENCES wildx_posts(id) ON DELETE SET NULL,
      amount_wxt NUMERIC(20,2) NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_wildx_wxt_txs_to_user
      ON wildx_wxt_txs(to_user_id, created_at DESC)
  `);

  // Vinculacion de cuenta WildWave con cuenta Ocean Pay
  await pool.query(`
    CREATE TABLE IF NOT EXISTS wildx_oceanpay_links (
      wildx_user_id INTEGER PRIMARY KEY REFERENCES wildx_users(id) ON DELETE CASCADE,
      ocean_pay_user_id INTEGER UNIQUE NOT NULL REFERENCES ocean_pay_users(id) ON DELETE CASCADE,
      linked_at TIMESTAMP NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`
    ALTER TABLE wildx_oceanpay_links
      DROP CONSTRAINT IF EXISTS wildx_oceanpay_links_ocean_pay_user_id_key
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_wildx_oceanpay_links_ocean_pay_user_id
      ON wildx_oceanpay_links(ocean_pay_user_id)
  `);

  // Notificaciones de WildX
  await pool.query(`
    CREATE TABLE IF NOT EXISTS wildx_notifications (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES wildx_users(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      payload TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW(),
      read_at TIMESTAMP
    )
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_wildx_notifications_user
      ON wildx_notifications(user_id, created_at DESC)
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_wildx_notifications_unread
      ON wildx_notifications(user_id, read_at)
  `);

  // Seguidores / seguidos
  await pool.query(`
    CREATE TABLE IF NOT EXISTS wildx_follows (
      follower_id INTEGER NOT NULL REFERENCES wildx_users(id) ON DELETE CASCADE,
      following_id INTEGER NOT NULL REFERENCES wildx_users(id) ON DELETE CASCADE,
      created_at TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY (follower_id, following_id),
      CHECK (follower_id <> following_id)
    )
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_wildx_follows_following
      ON wildx_follows(following_id, created_at DESC)
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_wildx_follows_follower
      ON wildx_follows(follower_id, created_at DESC)
  `);

  // Afiliaciones entre cuentas
  await pool.query(`
    CREATE TABLE IF NOT EXISTS wildx_affiliations (
      user_id INTEGER NOT NULL REFERENCES wildx_users(id) ON DELETE CASCADE,
      affiliate_id INTEGER NOT NULL REFERENCES wildx_users(id) ON DELETE CASCADE,
      created_at TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY (user_id, affiliate_id),
      CHECK (user_id <> affiliate_id)
    )
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_wildx_affiliations_user
      ON wildx_affiliations(user_id, created_at DESC)
  `);

  // ── Polls ──────────────────────────────────────────────────────────────
  await pool.query(`
    CREATE TABLE IF NOT EXISTS wildx_polls (
      id          SERIAL PRIMARY KEY,
      post_id     INTEGER NOT NULL REFERENCES wildx_posts(id) ON DELETE CASCADE,
      question    TEXT NOT NULL,
      options     JSONB NOT NULL DEFAULT '[]'::jsonb,
      ends_at     TIMESTAMP NULL,
      created_at  TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_wildx_polls_post
      ON wildx_polls(post_id)
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS wildx_poll_votes (
      id        SERIAL PRIMARY KEY,
      poll_id   INTEGER NOT NULL REFERENCES wildx_polls(id) ON DELETE CASCADE,
      user_id   INTEGER NOT NULL REFERENCES wildx_users(id) ON DELETE CASCADE,
      option_idx INTEGER NOT NULL,
      voted_at  TIMESTAMP DEFAULT NOW(),
      UNIQUE(poll_id, user_id)
    )
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_wildx_poll_votes_poll
      ON wildx_poll_votes(poll_id)
  `);

  // ── Processes ─────────────────────────────────────────────────────────
  await pool.query(`
    CREATE TABLE IF NOT EXISTS wildx_processes (
      id          SERIAL PRIMARY KEY,
      user_id     INTEGER NOT NULL REFERENCES wildx_users(id) ON DELETE CASCADE,
      title       TEXT NOT NULL,
      description TEXT,
      status      TEXT NOT NULL DEFAULT 'active',
      created_at  TIMESTAMP DEFAULT NOW(),
      updated_at  TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_wildx_processes_user
      ON wildx_processes(user_id, created_at DESC)
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS wildx_process_steps (
      id          SERIAL PRIMARY KEY,
      process_id  INTEGER NOT NULL REFERENCES wildx_processes(id) ON DELETE CASCADE,
      parent_id   INTEGER REFERENCES wildx_process_steps(id) ON DELETE CASCADE,
      title       TEXT NOT NULL,
      done        BOOLEAN NOT NULL DEFAULT FALSE,
      position    INTEGER NOT NULL DEFAULT 0,
      created_at  TIMESTAMP DEFAULT NOW(),
      updated_at  TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_wildx_process_steps_process
      ON wildx_process_steps(process_id, position ASC)
  `);
}

function getWildXUserId(req) {
  const auth = req.headers.authorization;
  if (!auth) return null;
  const [, token] = auth.split(' ');
  if (!token) return null;
  try {
    const payload = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    return payload?.wid || null;
  } catch {
    return null;
  }
}

// Crear una notificacion para un usuario de WildX
async function createWildXNotification(userId, type, payload) {
  if (!userId || !type) return;
  try {
    await ensureWildXTables();
    await pool.query(
      `INSERT INTO wildx_notifications (user_id, type, payload)
       VALUES ($1, $2, $3)`,
      [userId, type, JSON.stringify(payload || {})]
    );
  } catch (err) {
    console.error('Error creando notificacion WildX:', err);
  }
}

const WILDWAVE_TOKEN_CURRENCY = 'wildwavetokens';

const WILDWAVE_VERIFY_PLANS = [
  { id: 'tide', label: 'Tide Verified', tier: 'blue', priceWildCredits: 175, durationDays: 7, maxChars: 700, allowCustomColor: false, badgeColor: 'blue', perks: ['Insignia azul oficial', '700 caracteres por post', 'Prioridad media en soporte'] },
  { id: 'storm', label: 'Storm Creator', tier: 'gold', priceWildCredits: 420, durationDays: 7, maxChars: 1200, allowCustomColor: false, badgeColor: 'crimson', perks: ['Insignia creator avanzada', '1200 caracteres por post', 'Soporte prioritario para creators'] },
  { id: 'aurora', label: 'Aurora Elite', tier: 'elite', priceWildCredits: 780, durationDays: 7, maxChars: 1800, allowCustomColor: true, badgeColor: 'rainbow', perks: ['Color de insignia personalizable', '1800 caracteres por post', 'Prioridad maxima y visibilidad premium'] }
];

const WILDWAVE_VERIFY_PLAN_MAP = new Map(WILDWAVE_VERIFY_PLANS.map((p) => [p.id, p]));
const WILDWAVE_BADGE_COLORS = ['rainbow', 'red', 'crimson', 'magenta', 'violet', 'emerald', 'mint', 'orange', 'silver'];
const WILDWAVE_ADMIN_USERNAME = 'oceanandwildstudios';
const WILDWAVE_ADMIN_DISPLAY_NAME = 'ocean and wild studios';
const WILDWAVE_ADMIN_OCEANPAY_USERNAME = 'oceanandwild';
const WILDWAVE_USERNAME_MIN = 3;
const WILDWAVE_USERNAME_MAX = 20;
const WILDWAVE_USERNAME_COOLDOWN_DAYS = 14;
const WILDWAVE_DISPLAY_NAME_MIN = 2;
const WILDWAVE_DISPLAY_NAME_MAX = 32;
const WILDWAVE_RESERVED_USERNAMES = new Set([
  'admin',
  'administrator',
  'wildx',
  'support',
  'help',
  'oceanandwildstudios',
  'oceanandwild'
]);

function normalizeWildWaveBadgeColor(color) {
  const normalized = String(color || '').trim().toLowerCase();
  return WILDWAVE_BADGE_COLORS.includes(normalized) ? normalized : null;
}

function normalizeWildWaveDisplayName(value) {
  return String(value || '').replace(/\s+/g, ' ').trim();
}

function normalizeWildWaveUsername(value) {
  return String(value || '').trim();
}

function extractWildWaveVideoUrl(value) {
  const text = String(value || '');
  if (!text) return null;
  const urls = text.match(/https?:\/\/[^\s<>"']+/gi) || [];
  for (const rawUrl of urls) {
    const clean = String(rawUrl || '').replace(/[)\],.;!?]+$/, '');
    const lower = clean.toLowerCase();
    if (!clean) continue;
    if (/\.(mp4|webm|mov)(?:$|[?#])/i.test(clean)) return clean;
    if (lower.includes('archive.org/download/') && /\.(mp4|webm|mov)/i.test(lower)) return clean;
    if (lower.includes('res.cloudinary.com') && lower.includes('/video/upload/')) return clean;
  }
  return null;
}

function validateWildWaveUsername(username) {
  if (!username) return 'Usuario requerido';
  if (username.length < WILDWAVE_USERNAME_MIN || username.length > WILDWAVE_USERNAME_MAX) {
    return `El usuario debe tener entre ${WILDWAVE_USERNAME_MIN} y ${WILDWAVE_USERNAME_MAX} caracteres`;
  }
  if (!/^[a-zA-Z0-9._]+$/.test(username)) {
    return 'Solo se permiten letras, numeros, puntos o guiones bajos';
  }
  if (!/^[a-zA-Z]/.test(username)) {
    return 'El usuario debe comenzar con una letra';
  }
  if (/[._]$/.test(username)) {
    return 'El usuario no puede terminar en punto o guion bajo';
  }
  if (/([._]){2,}/.test(username)) {
    return 'No se permiten puntos o guiones bajos seguidos';
  }
  return null;
}

function validateWildWaveDisplayName(displayName) {
  if (!displayName) return null;
  if (displayName.length < WILDWAVE_DISPLAY_NAME_MIN || displayName.length > WILDWAVE_DISPLAY_NAME_MAX) {
    return `El nombre visible debe tener entre ${WILDWAVE_DISPLAY_NAME_MIN} y ${WILDWAVE_DISPLAY_NAME_MAX} caracteres`;
  }
  if (/[<>]/.test(displayName)) {
    return 'El nombre visible contiene caracteres no permitidos';
  }
  const allowed = /^[\p{L}0-9 ._&'ï¿½-]+$/u;
  if (!allowed.test(displayName)) {
    return 'El nombre visible contiene caracteres no permitidos';
  }
  return null;
}

function isReservedWildWaveUsername(username) {
  const normalized = normalizeWildWaveUsername(username).toLowerCase();
  return WILDWAVE_RESERVED_USERNAMES.has(normalized);
}

function isReservedWildWaveDisplayName(displayName) {
  const normalized = normalizeWildWaveDisplayName(displayName).toLowerCase();
  const compact = normalized.replace(/\s+/g, '');
  return normalized === WILDWAVE_ADMIN_DISPLAY_NAME || compact === WILDWAVE_ADMIN_USERNAME;
}

function isWildWaveAdminBySignals(signals) {
  if (!signals) return false;
  const uname = normalizeWildWaveUsername(signals.username).toLowerCase();
  const dname = normalizeWildWaveDisplayName(signals.display_name).toLowerCase();
  const dnameCompact = dname.replace(/\s+/g, '');
  const opUname = normalizeWildWaveUsername(signals.oceanpay_username).toLowerCase();
  return uname === WILDWAVE_ADMIN_USERNAME
    || dname === WILDWAVE_ADMIN_DISPLAY_NAME
    || dnameCompact === WILDWAVE_ADMIN_USERNAME
    || opUname === WILDWAVE_ADMIN_OCEANPAY_USERNAME;
}

function getWildWavePlanById(planId) {
  return WILDWAVE_VERIFY_PLAN_MAP.get(String(planId || '').trim().toLowerCase()) || null;
}

function getWildWaveMaxCharsForTier(tier, planId) {
  if (tier === 'admin') return 100000;
  const plan = getWildWavePlanById(planId);
  if (plan && Number.isFinite(plan.maxChars)) return plan.maxChars;
  if (tier === 'blue') return 700;
  if (tier === 'gold') return 1200;
  if (tier === 'elite') return 1800;
  return 280;
}

function getOceanPayUserIdFromToken(oceanPayToken) {
  if (!oceanPayToken) return null;
  try {
    const decoded = jwt.verify(oceanPayToken, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    const idRaw = decoded?.id || decoded?.uid;
    const num = Number(idRaw);
    return Number.isFinite(num) && num > 0 ? num : null;
  } catch {
    return null;
  }
}

async function getLinkedOceanPayUserId(client, wildxUserId) {
  const { rows } = await client.query('SELECT ocean_pay_user_id FROM wildx_oceanpay_links WHERE wildx_user_id = $1 LIMIT 1', [wildxUserId]);
  return rows.length ? Number(rows[0].ocean_pay_user_id) : null;
}

async function linkWildWaveOceanPayAccount(client, wildxUserId, oceanPayUserId) {
  await client.query(
    'INSERT INTO wildx_oceanpay_links (wildx_user_id, ocean_pay_user_id, linked_at, updated_at) VALUES ($1, $2, NOW(), NOW()) ON CONFLICT (wildx_user_id) DO UPDATE SET ocean_pay_user_id = EXCLUDED.ocean_pay_user_id, updated_at = NOW()',
    [wildxUserId, oceanPayUserId]
  );
}

async function getPrimaryOceanPayCard(client, oceanPayUserId) {
  const { rows } = await client.query('SELECT id, balances FROM ocean_pay_cards WHERE user_id = $1 AND is_primary = true LIMIT 1', [oceanPayUserId]);
  return rows[0] || null;
}

async function setOceanPayCardCurrencyBalance(client, cardId, currencyType, amount) {
  await client.query('INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount) VALUES ($1, $2, $3) ON CONFLICT (card_id, currency_type) DO UPDATE SET amount = EXCLUDED.amount', [cardId, currencyType, amount]);
  const { rows: cardRows } = await client.query('SELECT balances FROM ocean_pay_cards WHERE id = $1', [cardId]);
  const balances = cardRows[0]?.balances || {};
  balances[currencyType] = Number(amount) || 0;
  await client.query('UPDATE ocean_pay_cards SET balances = $1 WHERE id = $2', [balances, cardId]);
}

async function getOceanPayCurrencyBalance(client, cardId, currencyType) {
  const { rows } = await client.query('SELECT amount FROM ocean_pay_card_balances WHERE card_id = $1 AND currency_type = $2 LIMIT 1', [cardId, currencyType]);
  return rows.length ? Number(rows[0].amount || 0) : 0;
}

async function syncWildWaveTokensForUser(client, wildxUserId) {
  const linkedOpUserId = await getLinkedOceanPayUserId(client, wildxUserId);
  if (!linkedOpUserId) return { synced: false, balance: null };
  const { rows: balRows } = await client.query('SELECT wxt_balance FROM wildx_balances WHERE user_id = $1 LIMIT 1', [wildxUserId]);
  const localBalance = balRows.length ? Number(balRows[0].wxt_balance || 0) : 0;
  const primaryCard = await getPrimaryOceanPayCard(client, linkedOpUserId);
  if (!primaryCard) return { synced: false, balance: localBalance };
  await setOceanPayCardCurrencyBalance(client, primaryCard.id, WILDWAVE_TOKEN_CURRENCY, localBalance);
  return { synced: true, balance: localBalance };
}

function buildWildWaveVerificationResponse(row) {
  if (!row) return null;
  return { tier: row.tier, plan_id: row.plan_id || null, badge_color: row.badge_color || null, reason: row.reason, started_at: row.started_at, valid_until: row.valid_until };
}


// Asegurar columnas extra en wildx_posts (estado, programaciÃƒÂ³n, borrado)
async function ensureWildXExtraColumns() {
  try {
    await pool.query(`
      ALTER TABLE wildx_posts
      ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'published',
      ADD COLUMN IF NOT EXISTS scheduled_at TIMESTAMP NULL,
      ADD COLUMN IF NOT EXISTS images JSONB NOT NULL DEFAULT '[]'::jsonb,
      ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP NULL,
      ADD COLUMN IF NOT EXISTS video_url TEXT NULL
    `);
  } catch (err) {
    // Si la tabla aÃƒÂºn no existe, se crearÃƒÂ¡ en ensureWildXTables
    if (err.code !== '42P01') {
      console.warn('No se pudieron asegurar columnas extra de WildX:', err.message);
    }
  }
}

// Tabla de reportes de posts WildX
async function ensureWildXReportsTable() {
  await ensureWildXTables();
  await pool.query(`
    CREATE TABLE IF NOT EXISTS wildx_post_reports (
      id SERIAL PRIMARY KEY,
      post_id INTEGER NOT NULL REFERENCES wildx_posts(id) ON DELETE CASCADE,
      reporter_id INTEGER NOT NULL REFERENCES wildx_users(id) ON DELETE CASCADE,
      reason TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT NOW(),
      reviewed_at TIMESTAMP,
      admin_id INTEGER REFERENCES wildx_users(id),
      admin_response TEXT
    )
  `);
}

// Registro de usuario WildX
app.post('/wildwave/api/register', async (req, res) => {
  try {
    await ensureWildXTables();
    const { username, password, displayName, display_name } = req.body || {};
    const uname = normalizeWildWaveUsername(username);
    const pwd = String(password || '');
    const displayNameRaw = display_name ?? displayName;
    const dname = normalizeWildWaveDisplayName(displayNameRaw || '');
    if (!uname || !pwd) return res.status(400).json({ error: 'Usuario y contraseÃƒÂ±a requeridos' });
    const unameError = validateWildWaveUsername(uname);
    if (unameError) return res.status(400).json({ error: unameError });
    if (isReservedWildWaveUsername(uname)) {
      return res.status(400).json({ error: 'Ese usuario estÃƒÂ¡ reservado' });
    }
    const dnameError = validateWildWaveDisplayName(dname);
    if (dnameError) return res.status(400).json({ error: dnameError });
    if (dname && isReservedWildWaveDisplayName(dname)) {
      return res.status(400).json({ error: 'Ese nombre visible estÃ¡ reservado' });
    }

    const { rows: existing } = await pool.query(
      'SELECT 1 FROM wildx_users WHERE LOWER(username) = LOWER($1) LIMIT 1',
      [uname]
    );
    if (existing.length) {
      return res.status(409).json({ error: 'Ese usuario ya existe' });
    }

    const hash = await bcrypt.hash(pwd, 10);
    const finalDisplayName = dname || uname;
    const { rows } = await pool.query(
      'INSERT INTO wildx_users (username, display_name, pwd_hash) VALUES ($1,$2,$3) RETURNING id, username, display_name, avatar_url, created_at, bio',
      [uname, finalDisplayName, hash]
    );
    const userRow = rows[0];

    const token = jwt.sign({ wid: userRow.id, un: userRow.username }, process.env.STUDIO_SECRET, { expiresIn: '7d' });
    const user = { id: userRow.id, username: userRow.username, display_name: userRow.display_name || userRow.username, avatar_url: userRow.avatar_url || null, created_at: userRow.created_at, bio: userRow.bio || null, posts_count: 0 };
    res.json({ token, user });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Ese usuario ya existe' });
    }
    console.error('Error en POST /wildwave/api/register:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Login WildX
app.post('/wildwave/api/login', async (req, res) => {
  try {
    await ensureWildXTables();
    const { username, password } = req.body || {};
    const uname = (username || '').toString().trim();
    const pwd = (password || '').toString();
    if (!uname || !pwd) return res.status(400).json({ error: 'Usuario y contraseÃƒÂ±a requeridos' });

    const { rows } = await pool.query('SELECT id, username, display_name, pwd_hash, avatar_url, created_at, bio FROM wildx_users WHERE username=$1', [uname]);
    if (!rows.length) return res.status(401).json({ error: 'Credenciales incorrectas' });
    const ok = await bcrypt.compare(pwd, rows[0].pwd_hash);
    if (!ok) return res.status(401).json({ error: 'Credenciales incorrectas' });

    const { rows: countRows } = await pool.query(
      'SELECT COUNT(*)::int AS posts_count FROM wildx_posts WHERE user_id=$1',
      [rows[0].id]
    );
    const postsCount = countRows[0]?.posts_count || 0;

    const token = jwt.sign({ wid: rows[0].id, un: rows[0].username }, process.env.STUDIO_SECRET, { expiresIn: '7d' });
    const user = {
      id: rows[0].id,
      username: rows[0].username,
      display_name: rows[0].display_name || rows[0].username,
      avatar_url: rows[0].avatar_url || null,
      created_at: rows[0].created_at,
      bio: rows[0].bio || null,
      posts_count: postsCount
    };
    res.json({ token, user });
  } catch (err) {
    console.error('Error en POST /wildwave/api/login:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Datos del usuario actual WildX (incluye stats bÃƒÂ¡sicas + verificaciÃƒÂ³n)
app.get('/wildwave/api/me', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Token requerido' });
    const { rows } = await pool.query(
      `SELECT u.id,
              u.username,
              u.display_name,
              u.username_changed_at,
              u.avatar_url,
              u.bio,
              u.created_at,
              COALESCE(p.posts_count, 0) AS posts_count,
              COALESCE(f.followers_count, 0) AS followers_count,
              COALESCE(fg.following_count, 0) AS following_count,
              v.tier          AS verify_tier,
              v.plan_id       AS verify_plan_id,
              v.badge_color   AS verify_badge_color,
              v.reason        AS verify_reason,
              v.started_at    AS verify_started_at,
              v.valid_until   AS verify_valid_until
         FROM wildx_users u
         LEFT JOIN (
           SELECT user_id, COUNT(*)::int AS posts_count
             FROM wildx_posts
            GROUP BY user_id
         ) p ON p.user_id = u.id
         LEFT JOIN (
           SELECT following_id, COUNT(*)::int AS followers_count
             FROM wildx_follows
            GROUP BY following_id
         ) f ON f.following_id = u.id
         LEFT JOIN (
           SELECT follower_id, COUNT(*)::int AS following_count
             FROM wildx_follows
            GROUP BY follower_id
         ) fg ON fg.follower_id = u.id
         LEFT JOIN LATERAL (
           SELECT tier, plan_id, badge_color, reason, started_at, valid_until
             FROM wildx_verifications
            WHERE user_id = u.id
              AND valid_until > NOW()
            ORDER BY started_at ASC
            LIMIT 1
         ) v ON TRUE
        WHERE u.id = $1`,
      [wid]
    );
    if (!rows.length) return res.status(404).json({ error: 'Usuario no encontrado' });

    const user = rows[0];
    user.display_name = user.display_name || user.username;
    user.max_post_chars = getWildWaveMaxCharsForTier(user.verify_tier, user.verify_plan_id);

    const { rows: affRows } = await pool.query(
      `SELECT a.affiliate_id AS id, u.username, u.display_name, u.avatar_url
         FROM wildx_affiliations a
         JOIN wildx_users u ON u.id = a.affiliate_id
        WHERE a.user_id = $1
        ORDER BY a.created_at DESC`,
      [wid]
    );
    user.affiliations = affRows || [];

    if (await isWildXAdmin(wid)) {
      // Cuenta admin con verificaciÃƒÂ³n especial dorada+roja
      user.verify_tier = 'admin';
      user.verify_plan_id = 'admin_studio';
      user.verify_badge_color = 'crimson';
      user.verify_reason = user.verify_reason || 'Desarrollador de Juegos - +50 Proyectos aumentando en cantidad poco a poco.';
      user.verify_started_at = user.verify_started_at || user.created_at;
      const far = new Date();
      far.setFullYear(far.getFullYear() + 100);
      user.verify_valid_until = far;
      user.max_post_chars = getWildWaveMaxCharsForTier(user.verify_tier, user.verify_plan_id);
    }

    res.json(user);
  } catch (err) {
    console.error('Error en GET /wildwave/api/me:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Subir foto de perfil WildWave
app.post('/wildwave/api/profile/avatar', wildwaveAvatarUpload.single('avatar'), async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Token requerido' });
    if (!req.file) return res.status(400).json({ error: 'Imagen requerida' });
    const url = req.file.path || req.file.secure_url;
    if (!url) return res.status(500).json({ error: 'No se pudo guardar la imagen' });

    await pool.query('UPDATE wildx_users SET avatar_url = $1 WHERE id = $2', [url, wid]);
    res.json({ success: true, avatar_url: url });
  } catch (err) {
    console.error('Error en POST /wildwave/api/profile/avatar:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Quitar foto de perfil WildWave
app.delete('/wildwave/api/profile/avatar', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Token requerido' });
    await pool.query('UPDATE wildx_users SET avatar_url = NULL WHERE id = $1', [wid]);
    res.json({ success: true });
  } catch (err) {
    console.error('Error en DELETE /wildwave/api/profile/avatar:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Subir media de post WildWave
app.post('/wildwave/api/posts/media', wildwavePostUpload.array('images', 6), async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesiÃ³n en WildWave' });
    const files = Array.isArray(req.files) ? req.files : (req.file ? [req.file] : []);
    if (!files.length) return res.status(400).json({ error: 'Imagen requerida' });
    const urls = files.map((file) => file.path || file.secure_url || file.url).filter(Boolean);
    if (!urls.length) return res.status(500).json({ error: 'No se pudo guardar la imagen' });
    res.json({ success: true, urls });
  } catch (err) {
    console.error('Error en POST /wildwave/api/posts/media:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// WildWave — subir video de post (Cloudinary)
app.post('/wildwave/api/posts/video', wildwaveVideoUpload.single('video'), async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesión en WildWave' });
    const file = req.file;
    if (!file) return res.status(400).json({ error: 'Video requerido' });
    const url = file.path || file.secure_url || file.url;
    if (!url) return res.status(500).json({ error: 'No se pudo guardar el video' });
    res.json({ success: true, url });
  } catch (err) {
    console.error('Error en POST /wildwave/api/posts/video:', err);
    res.status(500).json({ error: 'Error interno al subir video' });
  }
});

// Actualizar nombre de visualizador
app.patch('/wildwave/api/profile/display-name', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Token requerido' });

    const displayNameRaw = req.body?.displayName ?? req.body?.display_name;
    const dname = normalizeWildWaveDisplayName(displayNameRaw || '');
    const dnameError = validateWildWaveDisplayName(dname);
    if (dnameError) return res.status(400).json({ error: dnameError });

    const { rows } = await pool.query(
      'SELECT id, username, display_name, avatar_url, created_at FROM wildx_users WHERE id = $1',
      [wid]
    );
    if (!rows.length) return res.status(404).json({ error: 'Usuario no encontrado' });

    if (dname && isReservedWildWaveDisplayName(dname)) {
      const signals = await getWildXAdminSignals(wid);
      if (!isWildWaveAdminBySignals(signals)) {
        return res.status(403).json({ error: 'Ese nombre visible estÃƒÂ¡ reservado' });
      }
    }

    await pool.query('UPDATE wildx_users SET display_name = $1 WHERE id = $2', [dname || null, wid]);

    const userRow = rows[0];
    const user = {
      id: userRow.id,
      username: userRow.username,
      display_name: dname || userRow.username,
      avatar_url: userRow.avatar_url || null,
      created_at: userRow.created_at
    };
    res.json({ success: true, user });
  } catch (err) {
    console.error('Error en PATCH /wildwave/api/profile/display-name:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Actualizar nombre de usuario (handle)
app.patch('/wildwave/api/profile/username', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Token requerido' });

    const uname = normalizeWildWaveUsername(req.body?.username);
    const unameError = validateWildWaveUsername(uname);
    if (unameError) return res.status(400).json({ error: unameError });

    const { rows } = await pool.query(
      'SELECT id, username, display_name, avatar_url, created_at, username_changed_at FROM wildx_users WHERE id = $1',
      [wid]
    );
    if (!rows.length) return res.status(404).json({ error: 'Usuario no encontrado' });
    const current = rows[0];

    if (normalizeWildWaveUsername(current.username).toLowerCase() === normalizeWildWaveUsername(uname).toLowerCase()) {
      return res.status(400).json({ error: 'El usuario ya es el mismo' });
    }

    const isAdmin = await isWildXAdmin(wid);
    if (!isAdmin && isReservedWildWaveUsername(uname)) {
      return res.status(403).json({ error: 'Ese usuario estÃƒÂ¡ reservado' });
    }

    if (!isAdmin && current.username_changed_at) {
      const last = new Date(current.username_changed_at);
      if (!Number.isNaN(last.getTime())) {
        const diffDays = (Date.now() - last.getTime()) / (1000 * 60 * 60 * 24);
        if (diffDays < WILDWAVE_USERNAME_COOLDOWN_DAYS) {
          const remaining = Math.max(1, Math.ceil(WILDWAVE_USERNAME_COOLDOWN_DAYS - diffDays));
          return res.status(429).json({ error: `Solo puedes cambiar tu usuario cada ${WILDWAVE_USERNAME_COOLDOWN_DAYS} dÃƒÂ­as. Vuelve a intentarlo en ${remaining} dÃƒÂ­as.` });
        }
      }
    }

    const { rows: existing } = await pool.query(
      'SELECT id FROM wildx_users WHERE LOWER(username) = LOWER($1) AND id <> $2 LIMIT 1',
      [uname, wid]
    );
    if (existing.length) {
      return res.status(409).json({ error: 'Ese usuario ya existe' });
    }

    const displayFallback = current.display_name || current.username;
    const shouldSyncDisplayName = !isAdmin
      && normalizeWildWaveDisplayName(displayFallback).toLowerCase() === normalizeWildWaveDisplayName(current.username).toLowerCase();
    const nextDisplayName = shouldSyncDisplayName ? uname : displayFallback;

    await pool.query(
      'UPDATE wildx_users SET username = $1, display_name = $2, username_changed_at = NOW() WHERE id = $3',
      [uname, nextDisplayName, wid]
    );
    await pool.query('UPDATE wildx_posts SET username = $1 WHERE user_id = $2', [uname, wid]);

    const { rows: countRows } = await pool.query(
      'SELECT COUNT(*)::int AS posts_count FROM wildx_posts WHERE user_id = $1',
      [wid]
    );
    const postsCount = countRows[0]?.posts_count || 0;

    const user = {
      id: current.id,
      username: uname,
      display_name: nextDisplayName || uname,
      avatar_url: current.avatar_url || null,
      created_at: current.created_at,
      posts_count: postsCount
    };
    const token = jwt.sign({ wid: current.id, un: uname }, process.env.STUDIO_SECRET, { expiresIn: '7d' });
    res.json({ success: true, user, token });
  } catch (err) {
    console.error('Error en PATCH /wildwave/api/profile/username:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Actualizar descripción (bio)
app.patch('/wildwave/api/profile/bio', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Token requerido' });
    const raw = String(req.body?.bio || '').trim();
    if (raw.length > 160) return res.status(400).json({ error: 'La descripción no puede superar 160 caracteres.' });
    if (/[<>]/.test(raw)) return res.status(400).json({ error: 'La descripción contiene caracteres inválidos.' });
    await pool.query('UPDATE wildx_users SET bio = $1 WHERE id = $2', [raw, wid]);
    res.json({ success: true, bio: raw });
  } catch (err) {
    console.error('Error en PATCH /wildwave/api/profile/bio:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Obtener perfil público
app.get('/wildwave/api/profile/:username([a-zA-Z0-9._]+)', async (req, res) => {
  try {
    await ensureWildXTables();
    await ensureWildXExtraColumns();
    const uname = normalizeWildWaveUsername(req.params.username);
    if (!uname) return res.status(400).json({ error: 'Usuario requerido' });
    const viewerId = getWildXUserId(req);

    const { rows } = await pool.query(
      `SELECT u.id,
              u.username,
              u.display_name,
              u.avatar_url,
              u.created_at,
              u.bio,
              COALESCE(p.posts_count, 0) AS posts_count,
              COALESCE(p.original_count, 0) AS original_count,
              COALESCE(p.replies_count, 0) AS replies_count,
              COALESCE(p.likes_received, 0) AS likes_received,
              p.last_post AS last_post,
              COALESCE(f.followers_count, 0) AS followers_count,
              COALESCE(fg.following_count, 0) AS following_count,
              v.tier        AS verify_tier,
              v.plan_id     AS verify_plan_id,
              v.badge_color AS verify_badge_color,
              v.reason      AS verify_reason,
              v.started_at  AS verify_started_at,
              v.valid_until AS verify_valid_until,
              bal.wxt_balance AS wxt_balance,
              CASE
                WHEN $2::int IS NULL THEN FALSE
                WHEN EXISTS (
                  SELECT 1 FROM wildx_follows wf WHERE wf.follower_id = $2 AND wf.following_id = u.id
                ) THEN TRUE
                ELSE FALSE
              END AS is_following
         FROM wildx_users u
         LEFT JOIN LATERAL (
           SELECT COUNT(*)::int AS posts_count,
                  COUNT(*) FILTER (WHERE parent_id IS NULL)::int AS original_count,
                  COUNT(*) FILTER (WHERE parent_id IS NOT NULL)::int AS replies_count,
                  COALESCE(SUM(likes_count), 0)::int AS likes_received,
                  MAX(created_at) AS last_post
             FROM wildx_posts
            WHERE user_id = u.id AND deleted_at IS NULL
         ) p ON TRUE
         LEFT JOIN (
           SELECT following_id, COUNT(*)::int AS followers_count
             FROM wildx_follows
            GROUP BY following_id
         ) f ON f.following_id = u.id
         LEFT JOIN (
           SELECT follower_id, COUNT(*)::int AS following_count
             FROM wildx_follows
            GROUP BY follower_id
         ) fg ON fg.follower_id = u.id
         LEFT JOIN LATERAL (
           SELECT tier, plan_id, badge_color, reason, started_at, valid_until
             FROM wildx_verifications
            WHERE user_id = u.id
              AND valid_until > NOW()
            ORDER BY started_at ASC
            LIMIT 1
         ) v ON TRUE
         LEFT JOIN wildx_balances bal ON bal.user_id = u.id
        WHERE LOWER(u.username) = LOWER($1)
        LIMIT 1`,
      [uname, viewerId || null]
    );
    if (!rows.length) return res.status(404).json({ error: 'Usuario no encontrado' });
    const user = rows[0];
    user.display_name = user.display_name || user.username;

    if (await isWildXAdmin(user.id)) {
      user.verify_tier = 'admin';
      user.verify_plan_id = 'admin_studio';
      user.verify_badge_color = 'crimson';
      user.verify_reason = user.verify_reason || 'Desarrollador de Juegos - +50 Proyectos aumentando en cantidad poco a poco.';
      user.verify_started_at = user.verify_started_at || user.created_at;
      const far = new Date();
      far.setFullYear(far.getFullYear() + 100);
      user.verify_valid_until = far;
    }

    user.max_post_chars = getWildWaveMaxCharsForTier(user.verify_tier, user.verify_plan_id);

    const { rows: affRows } = await pool.query(
      `SELECT a.affiliate_id AS id, u.username, u.display_name, u.avatar_url
         FROM wildx_affiliations a
         JOIN wildx_users u ON u.id = a.affiliate_id
        WHERE a.user_id = $1
        ORDER BY a.created_at DESC`,
      [user.id]
    );
    user.affiliations = affRows || [];

    // Notify profile owner of visit (only if viewer is different user)
    if (viewerId && viewerId !== user.id) {
      try {
        const { rows: viewerRows } = await pool.query(
          'SELECT username FROM wildx_users WHERE id = $1',
          [viewerId]
        );
        if (viewerRows.length) {
          createWildXNotification(user.id, 'profile_visit', {
            from_username: viewerRows[0].username
          }).catch(() => {});
        }
      } catch (_) {}
    }
    res.json(user);
  } catch (err) {
    console.error('Error en GET /wildwave/api/profile/:username:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Seguir / dejar de seguir
app.post('/wildwave/api/follow/:username', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Token requerido' });
    const uname = normalizeWildWaveUsername(req.params.username);
    if (!uname) return res.status(400).json({ error: 'Usuario requerido' });

    const { rows: targetRows } = await pool.query(
      'SELECT id FROM wildx_users WHERE LOWER(username) = LOWER($1) LIMIT 1',
      [uname]
    );
    if (!targetRows.length) return res.status(404).json({ error: 'Usuario no encontrado' });
    const targetId = targetRows[0].id;
    if (Number(targetId) === Number(wid)) return res.status(400).json({ error: 'No puedes seguirte a ti mismo.' });

    await pool.query(
      'INSERT INTO wildx_follows (follower_id, following_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [wid, targetId]
    );
    const { rows: countRows } = await pool.query(
      `SELECT
         (SELECT COUNT(*)::int FROM wildx_follows WHERE following_id = $1) AS followers_count,
         (SELECT COUNT(*)::int FROM wildx_follows WHERE follower_id = $1) AS following_count`,
      [targetId]
    );
    res.json({
      success: true,
      following: true,
      followers_count: countRows[0]?.followers_count || 0,
      following_count: countRows[0]?.following_count || 0
    });
  } catch (err) {
    console.error('Error en POST /wildwave/api/follow/:username:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

app.delete('/wildwave/api/follow/:username', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Token requerido' });
    const uname = normalizeWildWaveUsername(req.params.username);
    if (!uname) return res.status(400).json({ error: 'Usuario requerido' });

    const { rows: targetRows } = await pool.query(
      'SELECT id FROM wildx_users WHERE LOWER(username) = LOWER($1) LIMIT 1',
      [uname]
    );
    if (!targetRows.length) return res.status(404).json({ error: 'Usuario no encontrado' });
    const targetId = targetRows[0].id;
    if (Number(targetId) === Number(wid)) return res.status(400).json({ error: 'No puedes dejar de seguirte a ti mismo.' });

    await pool.query('DELETE FROM wildx_follows WHERE follower_id = $1 AND following_id = $2', [wid, targetId]);
    const { rows: countRows } = await pool.query(
      `SELECT
         (SELECT COUNT(*)::int FROM wildx_follows WHERE following_id = $1) AS followers_count,
         (SELECT COUNT(*)::int FROM wildx_follows WHERE follower_id = $1) AS following_count`,
      [targetId]
    );
    res.json({
      success: true,
      following: false,
      followers_count: countRows[0]?.followers_count || 0,
      following_count: countRows[0]?.following_count || 0
    });
  } catch (err) {
    console.error('Error en DELETE /wildwave/api/follow/:username:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Guardar afiliaciones del usuario actual
app.post('/wildwave/api/affiliations', async (req, res) => {
  const client = await pool.connect();
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) {
      client.release();
      return res.status(401).json({ error: 'Token requerido' });
    }
    const rawList = req.body?.usernames || req.body?.affiliations || [];
    const list = Array.isArray(rawList)
      ? rawList.map((val) => normalizeWildWaveUsername(val)).filter(Boolean)
      : [];
    const unique = Array.from(new Set(list.map((u) => u.toLowerCase())));
    if (!unique.length) {
      await client.query('BEGIN');
      await client.query('DELETE FROM wildx_affiliations WHERE user_id = $1', [wid]);
      await client.query('COMMIT');
      return res.json({ success: true, affiliations: [] });
    }

    const { rows: targetRows } = await client.query(
      'SELECT id, username, display_name, avatar_url FROM wildx_users WHERE LOWER(username) = ANY($1)',
      [unique]
    );

    await client.query('BEGIN');
    await client.query('DELETE FROM wildx_affiliations WHERE user_id = $1', [wid]);
    for (const row of targetRows) {
      if (Number(row.id) === Number(wid)) continue;
      await client.query(
        'INSERT INTO wildx_affiliations (user_id, affiliate_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
        [wid, row.id]
      );
    }
    await client.query('COMMIT');

    const affiliations = targetRows
      .filter((row) => Number(row.id) !== Number(wid))
      .map((row) => ({
        id: row.id,
        username: row.username,
        display_name: row.display_name,
        avatar_url: row.avatar_url
      }));

    res.json({ success: true, affiliations });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error en POST /wildwave/api/affiliations:', err);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

// SelecciÃƒÂ³n de post promocionado (uno a la vez)
async function selectPromotedPost() {
  await ensureWildXTables();
  // Buscar promociones activas
  const { rows: promos } = await pool.query(
    `SELECT id, post_id, user_id, amount_wxt, created_at, last_shown_at
       FROM wildx_promotions
      WHERE active = TRUE`
  );
  if (!promos.length) return null;

  const now = new Date();
  const fourHoursMs = 4 * 60 * 60 * 1000;

  const due = [];
  const others = [];
  for (const p of promos) {
    const last = p.last_shown_at ? new Date(p.last_shown_at) : null;
    if (!last || now.getTime() - last.getTime() >= fourHoursMs) {
      due.push(p);
    } else {
      others.push(p);
    }
  }

  let chosen = null;
  if (due.length) {
    // 70% probabilidad tomar de las pendientes, 30% de cualquiera
    const roll = Math.random();
    if (roll < 0.7) {
      chosen = due[Math.floor(Math.random() * due.length)];
    } else {
      const poolAll = promos;
      chosen = poolAll[Math.floor(Math.random() * poolAll.length)];
    }
  } else {
    // Sin nuevas, elegir cualquiera (se mantiene el Ã¢â‚¬Å“mismoÃ¢â‚¬Â en muchos casos)
    chosen = promos[Math.floor(Math.random() * promos.length)];
  }

  if (!chosen) return null;

  await pool.query(
    'UPDATE wildx_promotions SET last_shown_at = NOW() WHERE id = $1',
    [chosen.id]
  );

  const { rows: posts } = await pool.query(
    `SELECT p.id,
            p.user_id,
            COALESCE(u.username, p.username) AS username,
            COALESCE(u.display_name, u.username, p.username) AS display_name,
            p.content,
            p.images,
            p.video_url,
            p.created_at,
            p.parent_id,
            p.likes_count,
            u.avatar_url,
            CASE
              WHEN LOWER(COALESCE(u.username, p.username, '')) = $2 THEN 'admin'
              WHEN LOWER(REGEXP_REPLACE(COALESCE(u.display_name, ''), '\\s+', ' ', 'g')) = $3 THEN 'admin'
              WHEN LOWER(REGEXP_REPLACE(COALESCE(u.display_name, ''), '\\s+', '', 'g')) = $2 THEN 'admin'
              WHEN LOWER(COALESCE(op.username, '')) = $4 THEN 'admin'
              ELSE v.tier
            END AS verify_tier,
            CASE
              WHEN LOWER(COALESCE(u.username, p.username, '')) = $2 THEN 'crimson'
              WHEN LOWER(REGEXP_REPLACE(COALESCE(u.display_name, ''), '\\s+', ' ', 'g')) = $3 THEN 'crimson'
              WHEN LOWER(REGEXP_REPLACE(COALESCE(u.display_name, ''), '\\s+', '', 'g')) = $2 THEN 'crimson'
              WHEN LOWER(COALESCE(op.username, '')) = $4 THEN 'crimson'
              ELSE v.badge_color
            END AS verify_badge_color,
            collab.collaborators AS collaborators
       FROM wildx_posts p
       LEFT JOIN wildx_users u ON u.id = p.user_id
       LEFT JOIN wildx_oceanpay_links wol ON wol.wildx_user_id = p.user_id
       LEFT JOIN ocean_pay_users op ON op.id = wol.ocean_pay_user_id
       LEFT JOIN LATERAL (
         SELECT tier, badge_color
           FROM wildx_verifications
          WHERE user_id = p.user_id
            AND valid_until > NOW()
          ORDER BY started_at ASC
          LIMIT 1
       ) v ON TRUE
       LEFT JOIN LATERAL (
         SELECT COALESCE(
           json_agg(
             json_build_object(
               'id', cu.id,
               'username', cu.username,
               'display_name', COALESCE(cu.display_name, cu.username),
               'avatar_url', cu.avatar_url
             ) ORDER BY cu.username
           ),
           '[]'::json
         ) AS collaborators
           FROM wildx_post_collaborators pc
           JOIN wildx_users cu ON cu.id = pc.collaborator_id
          WHERE pc.post_id = p.id
            AND pc.status = 'accepted'
       ) collab ON TRUE
      WHERE p.id = $1`,
    [chosen.post_id, WILDWAVE_ADMIN_USERNAME, WILDWAVE_ADMIN_DISPLAY_NAME, WILDWAVE_ADMIN_OCEANPAY_USERNAME]
  );

  if (!posts.length) return null;

  return {
    promotion_id: chosen.id,
    amount_wxt: Number(chosen.amount_wxt),
    post: posts[0]
  };
}


// ── Poll helper: enrich posts with poll data ─────────────────────────────
async function enrichPostsWithPolls(posts, currentUserId) {
  if (!posts || !posts.length) return posts;
  const postIds = posts.map(p => p.id).filter(Boolean);
  if (!postIds.length) return posts;
  try {
    // Get polls for these posts
    const { rows: polls } = await pool.query(
      `SELECT pl.id, pl.post_id, pl.question, pl.options, pl.ends_at,
              pv.option_idx AS my_vote,
              (SELECT json_agg(json_build_object('option_idx', v.option_idx, 'count', v.cnt))
                 FROM (SELECT option_idx, COUNT(*)::int AS cnt
                         FROM wildx_poll_votes WHERE poll_id = pl.id
                        GROUP BY option_idx) v) AS vote_counts,
              (SELECT COUNT(*)::int FROM wildx_poll_votes WHERE poll_id = pl.id) AS total_votes
         FROM wildx_polls pl
         LEFT JOIN wildx_poll_votes pv
           ON pv.poll_id = pl.id AND pv.user_id = $2
        WHERE pl.post_id = ANY($1)`,
      [postIds, currentUserId || 0]
    );
    const pollMap = {};
    for (const p of polls) pollMap[p.post_id] = p;
    return posts.map(post => {
      const poll = pollMap[post.id];
      if (!poll) return post;
      const voteCounts = poll.vote_counts || [];
      const options = (Array.isArray(poll.options) ? poll.options : []).map((opt, idx) => ({
        idx,
        text: opt,
        votes: (voteCounts.find(v => v.option_idx === idx) || {}).count || 0
      }));
      return {
        ...post,
        poll: {
          id: poll.id,
          question: poll.question,
          options,
          ends_at: poll.ends_at,
          total_votes: poll.total_votes || 0,
          my_vote: poll.my_vote != null ? poll.my_vote : null
        }
      };
    });
  } catch (e) {
    console.error('enrichPostsWithPolls error:', e.message);
    return posts; // fail gracefully
  }
}


// ── Processes helper ─────────────────────────────────────────────────────
async function emitProcessUpdate(userId, eventType, payload) {
  // Notify the owner
  io.to(`ww-user-${userId}`).emit('ww:process-update', { type: eventType, ...payload });
  // Notify followers so they see live updates on the owner's profile
  try {
    const { rows } = await pool.query(
      'SELECT follower_id FROM wildx_follows WHERE following_id = $1',
      [userId]
    );
    for (const r of rows) {
      io.to(`ww-user-${r.follower_id}`).emit('ww:process-update', { type: eventType, userId, ...payload });
    }
  } catch (_) {}
}

async function getProcessWithSteps(processId) {
  const { rows: procs } = await pool.query(
    'SELECT id, user_id, title, description, status, created_at, updated_at FROM wildx_processes WHERE id = $1',
    [processId]
  );
  if (!procs.length) return null;
  const proc = procs[0];
  const { rows: steps } = await pool.query(
    `SELECT id, parent_id, title, done, position, created_at, updated_at
       FROM wildx_process_steps
      WHERE process_id = $1
      ORDER BY position ASC, id ASC`,
    [processId]
  );
  proc.steps = steps;
  // Counts: total steps (no parent), completed
  const topLevel = steps.filter(s => !s.parent_id);
  proc.total_steps     = topLevel.length;
  proc.completed_steps = topLevel.filter(s => s.done).length;
  return proc;
}

// API de posts WildX (Explorar = todos los posts publicados)
app.get('/wildwave/api/posts', async (req, res) => {
  try {
    await ensureWildXTables();
    await ensureWildXExtraColumns();
    const wid = getWildXUserId(req) || 0;
    const postsPromise = pool.query(
      `SELECT p.id,
              p.user_id,
              COALESCE(u.username, p.username) AS username,
              COALESCE(u.display_name, u.username, p.username) AS display_name,
              p.content,
              p.images,
              p.video_url,
              p.created_at,
              p.parent_id,
              p.likes_count,
              u.avatar_url,
              (l.user_id IS NOT NULL) AS liked,
              CASE
                WHEN LOWER(COALESCE(u.username, p.username, '')) = $2 THEN 'admin'
                WHEN LOWER(REGEXP_REPLACE(COALESCE(u.display_name, ''), '\\s+', ' ', 'g')) = $3 THEN 'admin'
              WHEN LOWER(REGEXP_REPLACE(COALESCE(u.display_name, ''), '\\s+', '', 'g')) = $2 THEN 'admin'
                WHEN LOWER(COALESCE(op.username, '')) = $4 THEN 'admin'
                ELSE v.tier
              END AS verify_tier,
              CASE
                WHEN LOWER(COALESCE(u.username, p.username, '')) = $2 THEN 'crimson'
                WHEN LOWER(REGEXP_REPLACE(COALESCE(u.display_name, ''), '\\s+', ' ', 'g')) = $3 THEN 'crimson'
              WHEN LOWER(REGEXP_REPLACE(COALESCE(u.display_name, ''), '\\s+', '', 'g')) = $2 THEN 'crimson'
                WHEN LOWER(COALESCE(op.username, '')) = $4 THEN 'crimson'
                ELSE v.badge_color
              END AS verify_badge_color,
            collab.collaborators AS collaborators
         FROM wildx_posts p
         LEFT JOIN wildx_users u ON u.id = p.user_id
         LEFT JOIN wildx_oceanpay_links wol ON wol.wildx_user_id = p.user_id
         LEFT JOIN ocean_pay_users op ON op.id = wol.ocean_pay_user_id
         LEFT JOIN wildx_likes l
           ON l.post_id = p.id AND l.user_id = $1
         LEFT JOIN LATERAL (
           SELECT tier, badge_color
           FROM wildx_verifications
            WHERE user_id = p.user_id
              AND valid_until > NOW()
            ORDER BY started_at ASC
            LIMIT 1
         ) v ON TRUE
       LEFT JOIN LATERAL (
         SELECT COALESCE(
           json_agg(
             json_build_object(
               'id', cu.id,
               'username', cu.username,
               'display_name', COALESCE(cu.display_name, cu.username),
               'avatar_url', cu.avatar_url
             ) ORDER BY cu.username
           ),
           '[]'::json
         ) AS collaborators
           FROM wildx_post_collaborators pc
           JOIN wildx_users cu ON cu.id = pc.collaborator_id
          WHERE pc.post_id = p.id
            AND pc.status = 'accepted'
       ) collab ON TRUE
        WHERE p.status = 'published' AND p.deleted_at IS NULL
        ORDER BY p.created_at DESC
        LIMIT 100`,
      [wid, WILDWAVE_ADMIN_USERNAME, WILDWAVE_ADMIN_DISPLAY_NAME, WILDWAVE_ADMIN_OCEANPAY_USERNAME]
    );

    const [postsResult, promoted] = await Promise.all([
      postsPromise,
      selectPromotedPost().catch(() => null)
    ]);

    const enrichedPosts = await enrichPostsWithPolls(postsResult.rows, wid);
    res.json({
      posts: enrichedPosts,
      promoted
    });
  } catch (err) {
    console.error('Error en GET /wildwave/api/posts:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Posts propios (Perfil, solo publicados)
app.get('/wildwave/api/my-posts', async (req, res) => {
  try {
    await ensureWildXTables();
    await ensureWildXExtraColumns();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Token requerido' });
    const { rows } = await pool.query(
      `SELECT p.id,
              p.user_id,
              COALESCE(u.username, p.username) AS username,
              COALESCE(u.display_name, u.username, p.username) AS display_name,
              p.content,
              p.images,
              p.video_url,
              p.created_at,
              p.parent_id,
              p.likes_count,
              u.avatar_url,
              (l.user_id IS NOT NULL) AS liked,
              CASE
                WHEN LOWER(COALESCE(u.username, p.username, '')) = $2 THEN 'admin'
                WHEN LOWER(REGEXP_REPLACE(COALESCE(u.display_name, ''), '\\s+', ' ', 'g')) = $3 THEN 'admin'
              WHEN LOWER(REGEXP_REPLACE(COALESCE(u.display_name, ''), '\\s+', '', 'g')) = $2 THEN 'admin'
                WHEN LOWER(COALESCE(op.username, '')) = $4 THEN 'admin'
                ELSE v.tier
              END AS verify_tier,
              CASE
                WHEN LOWER(COALESCE(u.username, p.username, '')) = $2 THEN 'crimson'
                WHEN LOWER(REGEXP_REPLACE(COALESCE(u.display_name, ''), '\\s+', ' ', 'g')) = $3 THEN 'crimson'
              WHEN LOWER(REGEXP_REPLACE(COALESCE(u.display_name, ''), '\\s+', '', 'g')) = $2 THEN 'crimson'
                WHEN LOWER(COALESCE(op.username, '')) = $4 THEN 'crimson'
                ELSE v.badge_color
              END AS verify_badge_color,
            collab.collaborators AS collaborators
         FROM wildx_posts p
         LEFT JOIN wildx_users u ON u.id = p.user_id
         LEFT JOIN wildx_oceanpay_links wol ON wol.wildx_user_id = p.user_id
         LEFT JOIN ocean_pay_users op ON op.id = wol.ocean_pay_user_id
         LEFT JOIN wildx_likes l
           ON l.post_id = p.id AND l.user_id = $1
         LEFT JOIN LATERAL (
           SELECT tier, badge_color
           FROM wildx_verifications
            WHERE user_id = p.user_id
              AND valid_until > NOW()
            ORDER BY started_at ASC
            LIMIT 1
         ) v ON TRUE
         LEFT JOIN LATERAL (
           SELECT COALESCE(
             json_agg(
               json_build_object(
                 'id', cu.id,
                 'username', cu.username,
                 'display_name', COALESCE(cu.display_name, cu.username),
                 'avatar_url', cu.avatar_url
               ) ORDER BY cu.username
             ),
             '[]'::json
           ) AS collaborators
             FROM wildx_post_collaborators pc
             JOIN wildx_users cu ON cu.id = pc.collaborator_id
            WHERE pc.post_id = p.id
              AND pc.status = 'accepted'
         ) collab ON TRUE
        WHERE p.status = 'published' AND p.deleted_at IS NULL
          AND (p.user_id = $1 OR EXISTS (
            SELECT 1 FROM wildx_post_collaborators pc2
             WHERE pc2.post_id = p.id
               AND pc2.collaborator_id = $1
               AND pc2.status = 'accepted'
          ))
        ORDER BY p.created_at DESC
        LIMIT 100`,
      [wid, WILDWAVE_ADMIN_USERNAME, WILDWAVE_ADMIN_DISPLAY_NAME, WILDWAVE_ADMIN_OCEANPAY_USERNAME]
    );
    const enrichedMyPosts = await enrichPostsWithPolls(rows, wid);
    res.json(enrichedMyPosts);
  } catch (err) {
    console.error('Error en GET /wildwave/api/my-posts:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// SuscripciÃƒÂ³n a verificaciÃƒÂ³n azul usando WildCredits via Ocean Pay
// Planes de verificacion WildWave (3 niveles)
app.get('/wildwave/api/verify/plans', (_req, res) => {
  res.json({
    plans: WILDWAVE_VERIFY_PLANS,
    badgeColors: WILDWAVE_BADGE_COLORS
  });
});

// Vincular cuenta WildWave con Ocean Pay y sincronizar WildWave Tokens
app.post('/wildwave/api/oceanpay/link', async (req, res) => {
  const client = await pool.connect();
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesion en WildWave' });

    const oceanPayToken = req.body?.oceanPayToken;
    const opUserId = getOceanPayUserIdFromToken(oceanPayToken);
    if (!opUserId) return res.status(401).json({ error: 'Token de Ocean Pay invalido' });

    await client.query('BEGIN');

    const { rows: opRows } = await client.query('SELECT id FROM ocean_pay_users WHERE id = $1 LIMIT 1', [opUserId]);
    if (!opRows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Cuenta de Ocean Pay no encontrada' });
    }

    await linkWildWaveOceanPayAccount(client, wid, opUserId);

    await client.query(
      'INSERT INTO wildx_balances (user_id, wxt_balance) VALUES ($1, 0) ON CONFLICT (user_id) DO NOTHING',
      [wid]
    );

    const { rows: localRows } = await client.query('SELECT wxt_balance FROM wildx_balances WHERE user_id = $1 FOR UPDATE', [wid]);
    const localBalance = localRows.length ? Number(localRows[0].wxt_balance || 0) : 0;

    const primaryCard = await getPrimaryOceanPayCard(client, opUserId);
    if (!primaryCard) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'No tienes una tarjeta principal activa en Ocean Pay' });
    }

    const oceanPayBalance = await getOceanPayCurrencyBalance(client, primaryCard.id, WILDWAVE_TOKEN_CURRENCY);
    const mergedBalance = Math.max(localBalance, oceanPayBalance, 0);

    await client.query(
      'INSERT INTO wildx_balances (user_id, wxt_balance) VALUES ($1, $2) ON CONFLICT (user_id) DO UPDATE SET wxt_balance = EXCLUDED.wxt_balance',
      [wid, mergedBalance]
    );
    await setOceanPayCardCurrencyBalance(client, primaryCard.id, WILDWAVE_TOKEN_CURRENCY, mergedBalance);

    await client.query('COMMIT');
    res.json({ success: true, linked: true, wxt: mergedBalance, oceanPayUserId: opUserId });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error en POST /wildwave/api/oceanpay/link:', err);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

// Suscripcion a planes de verificacion WildWave
app.post('/wildwave/api/verify/subscribe', async (req, res) => {
  const client = await pool.connect();
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesion en WildWave' });

    const { planId, reason, badgeColor, oceanPayToken, opUsername, opPassword } = req.body || {};
    const plan = getWildWavePlanById(planId);
    if (!plan) return res.status(400).json({ error: 'Plan no valido' });

    const r = String(reason || '').trim();
    if (r.length < 5) return res.status(400).json({ error: 'Debes explicar el motivo de la verificacion' });

    let opUserId = getOceanPayUserIdFromToken(oceanPayToken);
    if (!opUserId && opUsername && opPassword) {
      const uname = String(opUsername || '').trim();
      const pwd = String(opPassword || '');
      const { rows: opRows } = await pool.query('SELECT id, pwd_hash FROM ocean_pay_users WHERE username = $1 LIMIT 1', [uname]);
      if (!opRows.length) return res.status(401).json({ error: 'Credenciales de Ocean Pay incorrectas' });
      const ok = await bcrypt.compare(pwd, opRows[0].pwd_hash || '');
      if (!ok) return res.status(401).json({ error: 'Credenciales de Ocean Pay incorrectas' });
      opUserId = Number(opRows[0].id);
    }
    if (!opUserId) return res.status(401).json({ error: 'Debes conectar Ocean Pay para activar un plan' });

    const selectedColor = plan.allowCustomColor ? (normalizeWildWaveBadgeColor(badgeColor) || plan.badgeColor) : plan.badgeColor;

    await client.query('BEGIN');

    await linkWildWaveOceanPayAccount(client, wid, opUserId);

    const primaryCard = await getPrimaryOceanPayCard(client, opUserId);
    if (!primaryCard) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'No tienes una tarjeta principal activa en Ocean Pay' });
    }

    const currentWildCredits = await getOceanPayCurrencyBalance(client, primaryCard.id, 'wildcredits');
    if (currentWildCredits < Number(plan.priceWildCredits || 0)) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Saldo insuficiente de WildCredits' });
    }

    const remainingWildCredits = currentWildCredits - Number(plan.priceWildCredits || 0);
    await setOceanPayCardCurrencyBalance(client, primaryCard.id, 'wildcredits', remainingWildCredits);

    await client.query(
      "INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda) VALUES ($1, $2, $3, $4, 'WC')",
      [opUserId, `Plan ${plan.label} de WildWave`, -Number(plan.priceWildCredits || 0), 'WildWave']
    ).catch(async () => {
      await client.query(
        'INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen) VALUES ($1, $2, $3, $4)',
        [opUserId, `Plan ${plan.label} de WildWave`, -Number(plan.priceWildCredits || 0), 'WildWave']
      );
    });

    await client.query(
      "UPDATE wildx_verifications SET valid_until = NOW() WHERE user_id = $1 AND tier <> 'admin' AND valid_until > NOW()",
      [wid]
    );

    const { rows: verRows } = await client.query(
      "INSERT INTO wildx_verifications (user_id, tier, plan_id, badge_color, reason, started_at, valid_until) VALUES ($1, $2, $3, $4, $5, NOW(), NOW() + ($6::text || ' days')::interval) RETURNING tier, plan_id, badge_color, reason, started_at, valid_until",
      [wid, plan.tier, plan.id, selectedColor, r, String(plan.durationDays || 7)]
    );

    await client.query('COMMIT');
    res.json({
      success: true,
      plan,
      remainingWildcredits: remainingWildCredits,
      verification: buildWildWaveVerificationResponse(verRows[0])
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error en POST /wildwave/api/verify/subscribe:', err);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});


app.post('/wildwave/api/verify/blue/subscribe', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesiÃƒÂ³n en WildX' });

    const { reason, oceanPayToken } = req.body || {};
    const r = (reason || '').toString().trim();
    if (!r || r.length < 5) {
      return res.status(400).json({ error: 'Explica brevemente el motivo de tu verificaciÃƒÂ³n' });
    }
    if (!oceanPayToken) {
      return res.status(400).json({ error: 'Token de Ocean Pay requerido' });
    }

    // Validar token de Ocean Pay y obtener user_id de ocean_pay_users
    let opUserId;
    try {
      const decoded = jwt.verify(oceanPayToken, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
      opUserId = parseInt((decoded.id || decoded.uid)) || (decoded.id || decoded.uid);
    } catch (e) {
      return res.status(401).json({ error: 'Token de Ocean Pay invÃƒÂ¡lido' });
    }

    const DAILY_PRICE = 25; // WildCredits por dÃƒÂ­a de verificaciÃƒÂ³n azul

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Asegurar tabla de metadata
      await client.query(`
        CREATE TABLE IF NOT EXISTS ocean_pay_metadata (
          user_id INTEGER NOT NULL,
          key TEXT NOT NULL,
          value TEXT NOT NULL,
          PRIMARY KEY (user_id, key)
        )
      `);

      // Leer y bloquear saldo actual de WildCredits
      const { rows: metaRows } = await client.query(
        `SELECT value FROM ocean_pay_metadata
          WHERE user_id = $1 AND key = 'wildcredits'
          FOR UPDATE`,
        [opUserId]
      );

      const currentBalance = metaRows.length > 0 ? parseInt(metaRows[0].value || '0') : 0;
      if (Number.isNaN(currentBalance) || currentBalance < DAILY_PRICE) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Saldo insuficiente de WildCredits' });
      }
      const newBalance = currentBalance - DAILY_PRICE;

      if (metaRows.length) {
        await client.query(
          `UPDATE ocean_pay_metadata
              SET value = $2
            WHERE user_id = $1 AND key = 'wildcredits'`,
          [opUserId, newBalance.toString()]
        );
      } else {
        await client.query(
          `INSERT INTO ocean_pay_metadata (user_id, key, value)
           VALUES ($1, 'wildcredits', $2)`,
          [opUserId, newBalance.toString()]
        );
      }

      // Registrar transacciÃƒÂ³n en Ocean Pay
      await client.query(
        `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
         VALUES ($1, $2, $3, $4, 'WC')`,
        [opUserId, 'SuscripciÃƒÂ³n diaria WildX Blue', -DAILY_PRICE, 'WildX']
      ).catch(async () => {
        await client.query(
          `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen)
           VALUES ($1, $2, $3, $4)`,
          [opUserId, 'SuscripciÃƒÂ³n diaria WildX Blue', -DAILY_PRICE, 'WildX']
        );
      });

      // Crear o extender verificaciÃƒÂ³n azul del usuario de WildX
      const { rows: existing } = await client.query(
        `SELECT id FROM wildx_verifications
          WHERE user_id = $1 AND tier = 'blue'
          FOR UPDATE`,
        [wid]
      );

      let verificationRow;
      if (existing.length) {
        const { rows: upd } = await client.query(
          `UPDATE wildx_verifications
              SET reason = $2,
                  plan_id = 'tide',
                  badge_color = 'blue',
                  valid_until = (CASE WHEN valid_until > NOW() THEN valid_until ELSE NOW() END) + INTERVAL '1 day'
            WHERE user_id = $1 AND tier = 'blue'
            RETURNING id, tier, plan_id, badge_color, reason, started_at, valid_until`,
          [wid, r]
        );
        verificationRow = upd[0];
      } else {
        const { rows: ins } = await client.query(
          `INSERT INTO wildx_verifications (user_id, tier, plan_id, badge_color, reason, started_at, valid_until)
           VALUES ($1, 'blue', 'tide', 'blue', $2, NOW(), NOW() + INTERVAL '1 day')
           RETURNING id, tier, plan_id, badge_color, reason, started_at, valid_until`,
          [wid, r]
        );
        verificationRow = ins[0];
      }

      await client.query('COMMIT');
      res.json({
        success: true,
        remainingWildcredits: newBalance,
        verification: buildWildWaveVerificationResponse(verificationRow)
      });
    } catch (err) {
      await client.query('ROLLBACK');
      console.error('Error en POST /wildwave/api/verify/blue/subscribe:', err);
      res.status(500).json({ error: 'Error interno' });
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('Error en POST /wildwave/api/verify/blue/subscribe:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Helper: detectar admin de WildWave
async function getWildXAdminSignals(userId) {
  const { rows } = await pool.query(
    `SELECT u.username, u.display_name, op.username AS oceanpay_username
       FROM wildx_users u
       LEFT JOIN wildx_oceanpay_links l ON l.wildx_user_id = u.id
       LEFT JOIN ocean_pay_users op ON op.id = l.ocean_pay_user_id
      WHERE u.id = $1`,
    [userId]
  );
  return rows[0] || null;
}

async function isWildXAdmin(userId) {
  const signals = await getWildXAdminSignals(userId);
  return isWildWaveAdminBySignals(signals);
}

// SuscripciÃƒÂ³n a verificaciÃƒÂ³n azul usando credenciales de Ocean Pay (WildCredits)
app.post('/wildwave/api/verify/blue/subscribe-credentials', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesiÃƒÂ³n en WildX' });

    const { reason, opUsername, opPassword } = req.body || {};
    const r = (reason || '').toString().trim();
    if (!r || r.length < 5) {
      return res.status(400).json({ error: 'Explica brevemente el motivo de tu verificaciÃƒÂ³n' });
    }

    const uname = (opUsername || '').toString().trim();
    const pwd = (opPassword || '').toString();
    if (!uname || !pwd) {
      return res.status(400).json({ error: 'Usuario y contraseÃƒÂ±a de Ocean Pay requeridos' });
    }

    // Validar credenciales de Ocean Pay directamente contra ocean_pay_users
    const { rows: opRows } = await pool.query(
      'SELECT id, pwd_hash FROM ocean_pay_users WHERE username = $1',
      [uname]
    );
    if (!opRows.length) {
      return res.status(401).json({ error: 'Credenciales de Ocean Pay incorrectas' });
    }
    const ok = await bcrypt.compare(pwd, opRows[0].pwd_hash);
    if (!ok) {
      return res.status(401).json({ error: 'Credenciales de Ocean Pay incorrectas' });
    }
    const opUserId = opRows[0].id;

    const DAILY_PRICE = 25; // WildCredits por dÃƒÂ­a de verificaciÃƒÂ³n azul

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Asegurar tabla de metadata
      await client.query(`
        CREATE TABLE IF NOT EXISTS ocean_pay_metadata (
          user_id INTEGER NOT NULL,
          key TEXT NOT NULL,
          value TEXT NOT NULL,
          PRIMARY KEY (user_id, key)
        )
      `);

      // Leer y bloquear saldo actual de WildCredits
      const { rows: metaRows } = await client.query(
        `SELECT value FROM ocean_pay_metadata
          WHERE user_id = $1 AND key = 'wildcredits'
          FOR UPDATE`,
        [opUserId]
      );

      const currentBalance = metaRows.length > 0 ? parseInt(metaRows[0].value || '0') : 0;
      if (Number.isNaN(currentBalance) || currentBalance < DAILY_PRICE) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Saldo insuficiente de WildCredits' });
      }
      const newBalance = currentBalance - DAILY_PRICE;

      if (metaRows.length) {
        await client.query(
          `UPDATE ocean_pay_metadata
              SET value = $2
            WHERE user_id = $1 AND key = 'wildcredits'`,
          [opUserId, newBalance.toString()]
        );
      } else {
        await client.query(
          `INSERT INTO ocean_pay_metadata (user_id, key, value)
           VALUES ($1, 'wildcredits', $2)`,
          [opUserId, newBalance.toString()]
        );
      }

      // Registrar transacciÃƒÂ³n en Ocean Pay (aparece en Historial de Transacciones)
      await client.query(
        `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
         VALUES ($1, $2, $3, $4, 'WC')`,
        [opUserId, 'SuscripciÃƒÂ³n diaria WildX Blue', -DAILY_PRICE, 'WildX']
      ).catch(async () => {
        await client.query(
          `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen)
           VALUES ($1, $2, $3, $4)`,
          [opUserId, 'SuscripciÃƒÂ³n diaria WildX Blue', -DAILY_PRICE, 'WildX']
        );
      });

      // Crear o extender verificaciÃƒÂ³n azul del usuario de WildX
      const { rows: existing } = await client.query(
        `SELECT id FROM wildx_verifications
          WHERE user_id = $1 AND tier = 'blue'
          FOR UPDATE`,
        [wid]
      );

      let verificationRow;
      if (existing.length) {
        const { rows: upd } = await client.query(
          `UPDATE wildx_verifications
              SET reason = $2,
                  plan_id = 'tide',
                  badge_color = 'blue',
                  valid_until = (CASE WHEN valid_until > NOW() THEN valid_until ELSE NOW() END) + INTERVAL '1 day'
            WHERE user_id = $1 AND tier = 'blue'
            RETURNING id, tier, plan_id, badge_color, reason, started_at, valid_until`,
          [wid, r]
        );
        verificationRow = upd[0];
      } else {
        const { rows: ins } = await client.query(
          `INSERT INTO wildx_verifications (user_id, tier, plan_id, badge_color, reason, started_at, valid_until)
           VALUES ($1, 'blue', 'tide', 'blue', $2, NOW(), NOW() + INTERVAL '1 day')
           RETURNING id, tier, plan_id, badge_color, reason, started_at, valid_until`,
          [wid, r]
        );
        verificationRow = ins[0];
      }

      await client.query('COMMIT');
      res.json({
        success: true,
        remainingWildcredits: newBalance,
        verification: buildWildWaveVerificationResponse(verificationRow)
      });
    } catch (err) {
      await client.query('ROLLBACK');
      console.error('Error en POST /wildwave/api/verify/blue/subscribe-credentials:', err);
      res.status(500).json({ error: 'Error interno' });
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('Error en POST /wildwave/api/verify/blue/subscribe-credentials:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Obtener saldo de WildX Tokens (WXT)
app.get('/wildwave/api/balance', async (req, res) => {
  const client = await pool.connect();
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesi??n en WildX' });

    await client.query('BEGIN');

    await client.query(
      'INSERT INTO wildx_balances (user_id, wxt_balance) VALUES ($1, 0) ON CONFLICT (user_id) DO NOTHING',
      [wid]
    );

    const linkedOpUserId = await getLinkedOceanPayUserId(client, wid);
    let finalBalance = 0;

    if (linkedOpUserId) {
      const primaryCard = await getPrimaryOceanPayCard(client, linkedOpUserId);
      if (primaryCard) {
        const opBalance = await getOceanPayCurrencyBalance(client, primaryCard.id, WILDWAVE_TOKEN_CURRENCY);
        finalBalance = Number(opBalance || 0);
        await client.query(
          'UPDATE wildx_balances SET wxt_balance = $2 WHERE user_id = $1',
          [wid, finalBalance]
        );
      } else {
        const { rows } = await client.query('SELECT wxt_balance FROM wildx_balances WHERE user_id = $1', [wid]);
        finalBalance = rows.length ? Number(rows[0].wxt_balance || 0) : 0;
      }
    } else {
      const { rows } = await client.query('SELECT wxt_balance FROM wildx_balances WHERE user_id = $1', [wid]);
      finalBalance = rows.length ? Number(rows[0].wxt_balance || 0) : 0;
    }

    await client.query('COMMIT');
    res.json({ wxt: finalBalance, linkedOceanPay: !!linkedOpUserId });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error en GET /wildwave/api/balance:', err);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

// Resumen de propinas (WXT y equivalente en WildCredits)
app.get('/wildwave/api/profile/tips-summary', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesiÃƒÂ³n en WildX' });

    // Asegurar columna created_at para poder calcular "este mes" (si ya existe, no pasa nada)
    try {
      await pool.query(
        "ALTER TABLE wildx_wxt_txs ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW()"
      );
    } catch {
      // ignorar errores de ALTER TABLE, usamos lo que haya
    }

    let rows;
    try {
      const result = await pool.query(
        `SELECT
           COALESCE(SUM(amount_wxt), 0) AS total_wxt,
           COALESCE(SUM(CASE WHEN created_at >= date_trunc('month', NOW()) THEN amount_wxt ELSE 0 END), 0) AS month_wxt
         FROM wildx_wxt_txs
         WHERE to_user_id = $1`,
        [wid]
      );
      rows = result.rows;
    } catch (e) {
      if (e.code === '42P01') {
        // Tabla aÃƒÂºn no existe: simplemente devolver ceros
        rows = [{ total_wxt: 0, month_wxt: 0 }];
      } else {
        throw e;
      }
    }

    const totalWxt = Number(rows[0]?.total_wxt || 0);
    const monthWxt = Number(rows[0]?.month_wxt || 0);
    const totalWc = totalWxt / WXT_PER_WC;
    const monthWc = monthWxt / WXT_PER_WC;

    res.json({
      totalWxt,
      totalWc,
      monthWxt,
      monthWc
    });
  } catch (err) {
    console.error('Error en GET /wildwave/api/profile/tips-summary:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Constante de conversiÃƒÂ³n WildCredits Ã¢â€ â€™ WXT (reducciÃƒÂ³n para que cueste mÃƒÂ¡s promocionar)
const WXT_PER_WC = 0.2; // 1 WXT por cada 5 WildCredits

// Endpoint de test para acreditar WXT (solo Admin)
app.post('/wildwave/api/wxt/grant', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesiÃƒÂ³n en WildX' });
    if (!(await isWildXAdmin(wid))) {
      return res.status(403).json({ error: 'Solo el administrador puede otorgar WXT de prueba.' });
    }
    const { userId, amount } = req.body || {};
    const targetId = userId ? parseInt(userId, 10) : wid;
    const amt = Number(amount) || 0;
    if (!targetId || amt <= 0) {
      return res.status(400).json({ error: 'ParÃƒÂ¡metros invÃƒÂ¡lidos' });
    }
    await pool.query(
      `INSERT INTO wildx_balances (user_id, wxt_balance)
         VALUES ($1, $2)
       ON CONFLICT (user_id)
       DO UPDATE SET wxt_balance = wildx_balances.wxt_balance + EXCLUDED.wxt_balance`,
      [targetId, amt]
    );
    await syncWildWaveTokensForUser(pool, targetId).catch(() => {});
    res.json({ success: true });
  } catch (err) {
    console.error('Error en POST /wildwave/api/wxt/grant:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Donar WildCredits a un post (se convierten a WXT para el autor)
app.post('/wildwave/api/posts/:id/donate', async (req, res) => {
  const client = await pool.connect();
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) {
      client.release();
      return res.status(401).json({ error: 'Inicia sesiÃƒÂ³n en WildX' });
    }

    const postId = parseInt(req.params.id, 10);
    if (!postId) {
      client.release();
      return res.status(400).json({ error: 'Post invÃƒÂ¡lido' });
    }

    const { amount, oceanPayToken } = req.body || {};
    const wcAmount = parseInt(amount, 10);
    if (!Number.isFinite(wcAmount) || wcAmount <= 0) {
      client.release();
      return res.status(400).json({ error: 'Cantidad de WildCredits invÃƒÂ¡lida' });
    }
    if (!oceanPayToken) {
      client.release();
      return res.status(400).json({ error: 'Token de Ocean Pay requerido' });
    }

    // Verificar post y autor
    const { rows: postRows } = await client.query(
      'SELECT user_id, username FROM wildx_posts WHERE id = $1',
      [postId]
    );
    if (!postRows.length) {
      client.release();
      return res.status(404).json({ error: 'Post no encontrado' });
    }
    const toUserId = Number(postRows[0].user_id);
    const toUsername = postRows[0].username || 'usuario';
    if (!toUserId || toUserId === Number(wid)) {
      client.release();
      return res.status(400).json({ error: 'No puedes donarte a ti mismo.' });
    }

    // Validar token de Ocean Pay
    let opUserId;
    try {
      const decoded = jwt.verify(oceanPayToken, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
      opUserId = parseInt((decoded.id || decoded.uid)) || (decoded.id || decoded.uid);
    } catch (e) {
      client.release();
      return res.status(401).json({ error: 'Token de Ocean Pay invÃƒÂ¡lido' });
    }

    await client.query('BEGIN');

    // Asegurar tabla de metadata
    await client.query(`
      CREATE TABLE IF NOT EXISTS ocean_pay_metadata (
        user_id INTEGER NOT NULL,
        key TEXT NOT NULL,
        value TEXT NOT NULL,
        PRIMARY KEY (user_id, key)
      )
    `);

    // Leer y bloquear saldo actual de WildCredits
    const { rows: metaRows } = await client.query(
      `SELECT value FROM ocean_pay_metadata
        WHERE user_id = $1 AND key = 'wildcredits'
        FOR UPDATE`,
      [opUserId]
    );

    const currentBalance = metaRows.length > 0 ? parseInt(metaRows[0].value || '0') : 0;
    if (Number.isNaN(currentBalance) || currentBalance < wcAmount) {
      await client.query('ROLLBACK');
      client.release();
      return res.status(400).json({ error: 'Saldo insuficiente de WildCredits' });
    }
    const newBalance = currentBalance - wcAmount;

    if (metaRows.length) {
      await client.query(
        `UPDATE ocean_pay_metadata
            SET value = $2
          WHERE user_id = $1 AND key = 'wildcredits'`,
        [opUserId, newBalance.toString()]
      );
    } else {
      await client.query(
        `INSERT INTO ocean_pay_metadata (user_id, key, value)
         VALUES ($1, 'wildcredits', $2)`,
        [opUserId, newBalance.toString()]
      );
    }

    // Registrar transacciÃƒÂ³n en Ocean Pay (historial)
    await client.query(
      `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
       VALUES ($1, $2, $3, $4, 'WC')`,
      [opUserId, `DonaciÃƒÂ³n a @${toUsername} en WildX (convertido a WXT)`, -wcAmount, 'WildX']
    ).catch(async () => {
      await client.query(
        `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen)
         VALUES ($1, $2, $3, $4)`,
        [opUserId, `DonaciÃƒÂ³n a @${toUsername} en WildX (convertido a WXT)`, -wcAmount, 'WildX']
      );
    });

    // Convertir WC a WXT para el autor del post
    const amountWxt = wcAmount * WXT_PER_WC;
    await client.query(
      `INSERT INTO wildx_balances (user_id, wxt_balance)
         VALUES ($1, $2)
       ON CONFLICT (user_id)
       DO UPDATE SET wxt_balance = wildx_balances.wxt_balance + EXCLUDED.wxt_balance`,
      [toUserId, amountWxt]
    );
    await syncWildWaveTokensForUser(client, toUserId).catch(() => {});

    // Registrar en historial de WXT
    await client.query(
      `INSERT INTO wildx_wxt_txs (from_user_id, to_user_id, post_id, amount_wxt)
       VALUES ($1, $2, $3, $4)`,
      [wid, toUserId, postId, amountWxt]
    );

    await client.query('COMMIT');
    client.release();

    // NotificaciÃƒÂ³n para el receptor (fuera de la transacciÃƒÂ³n principal)
    createWildXNotification(toUserId, 'donation', {
      fromUserId: wid,
      postId,
      amountWxt,
      amountWC: wcAmount
    }).catch(() => { });

    res.json({ success: true, donated: wcAmount, amountWxt });
  } catch (err) {
    await client.query('ROLLBACK');
    client.release();
    console.error('Error en POST /wildwave/api/posts/:id/donate:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Promocionar un post usando WXT
app.post('/wildwave/api/posts/:id/promote', async (req, res) => {
  const client = await pool.connect();
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) {
      client.release();
      return res.status(401).json({ error: 'Inicia sesiÃƒÂ³n en WildX' });
    }
    const postId = parseInt(req.params.id, 10);
    if (!postId) {
      client.release();
      return res.status(400).json({ error: 'Post invÃƒÂ¡lido' });
    }
    const cost = Number(req.body?.cost || 10); // costo bÃƒÂ¡sico 10 WXT
    if (cost <= 0) {
      client.release();
      return res.status(400).json({ error: 'Costo invÃƒÂ¡lido' });
    }

    await client.query('BEGIN');

    // Verificar que el post sea del usuario
    const { rows: posts } = await client.query(
      'SELECT user_id FROM wildx_posts WHERE id = $1',
      [postId]
    );
    if (!posts.length || Number(posts[0].user_id) !== Number(wid)) {
      await client.query('ROLLBACK');
      client.release();
      return res.status(403).json({ error: 'Solo puedes promocionar tus propios posts.' });
    }

    // Asegurar saldo
    const { rows: balRows } = await client.query(
      `SELECT wxt_balance FROM wildx_balances WHERE user_id = $1 FOR UPDATE`,
      [wid]
    );
    const current = balRows.length ? Number(balRows[0].wxt_balance) : 0;
    if (current < cost) {
      await client.query('ROLLBACK');
      client.release();
      return res.status(400).json({ error: 'Saldo WXT insuficiente para promocionar.' });
    }

    const newBal = current - cost;
    await client.query(
      `INSERT INTO wildx_balances (user_id, wxt_balance)
         VALUES ($1, $2)
       ON CONFLICT (user_id)
       DO UPDATE SET wxt_balance = EXCLUDED.wxt_balance`,
      [wid, newBal]
    );
    await syncWildWaveTokensForUser(client, wid).catch(() => {});

    // Crear o actualizar promociÃƒÂ³n
    const { rows: existing } = await client.query(
      'SELECT id, amount_wxt FROM wildx_promotions WHERE post_id = $1 AND user_id = $2 AND active = TRUE FOR UPDATE',
      [postId, wid]
    );
    if (existing.length) {
      await client.query(
        `UPDATE wildx_promotions
            SET amount_wxt = amount_wxt + $3,
                created_at = NOW()
          WHERE id = $1`,
        [existing[0].id, wid, cost]
      );
    } else {
      await client.query(
        `INSERT INTO wildx_promotions (post_id, user_id, amount_wxt)
         VALUES ($1, $2, $3)`,
        [postId, wid, cost]
      );
    }

    await client.query('COMMIT');
    client.release();

    // NotificaciÃƒÂ³n para el propio usuario indicando que la promociÃƒÂ³n fue registrada
    createWildXNotification(wid, 'promotion', {
      postId,
      amount: cost
    }).catch(() => { });

    res.json({ success: true, remainingWxt: newBal });
  } catch (err) {
    await client.query('ROLLBACK');
    client.release();
    console.error('Error en POST /wildwave/api/posts/:id/promote:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Solicitud de verificaciÃƒÂ³n dorada (empresas)
app.post('/wildwave/api/verify/gold/request', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesiÃƒÂ³n en WildX' });
    if (!(await isWildXAdmin(wid))) {
      return res.status(403).json({ error: 'La verificaciÃƒÂ³n dorada solo puede ser otorgada por el administrador.' });
    }
    return res.status(400).json({ error: 'Las solicitudes de verificaciÃƒÂ³n dorada estÃƒÂ¡n desactivadas. Usa el panel admin.' });

    const { companyName, reason } = req.body || {};
    const r = (reason || '').toString().trim();
    const company = (companyName || '').toString().trim();
    if (!r || r.length < 10) {
      return res.status(400).json({ error: 'Explica mejor por quÃƒÂ© tu empresa merece verificaciÃƒÂ³n dorada.' });
    }

    await pool.query(`
      CREATE TABLE IF NOT EXISTS wildx_gold_requests (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES wildx_users(id) ON DELETE CASCADE,
        company_name TEXT,
        reason TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT NOW(),
        reviewed_at TIMESTAMP,
        reviewer_id INTEGER REFERENCES wildx_users(id),
        reviewer_note TEXT
      )
    `);

    const { rows: existing } = await pool.query(
      "SELECT id FROM wildx_gold_requests WHERE user_id=$1 AND status = 'pending' LIMIT 1",
      [wid]
    );
    if (existing.length) {
      return res.status(400).json({ error: 'Ya tienes una solicitud de verificaciÃƒÂ³n dorada pendiente.' });
    }

    const { rows } = await pool.query(
      'INSERT INTO wildx_gold_requests (user_id, company_name, reason) VALUES ($1,$2,$3) RETURNING id, status, created_at',
      [wid, company || null, r]
    );
    res.json({ success: true, request: rows[0] });
  } catch (err) {
    console.error('Error en POST /wildwave/api/verify/gold/request:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Listado de solicitudes de verificaciÃƒÂ³n dorada (Admin)
app.get('/wildwave/api/verify/gold/requests', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid || !(await isWildXAdmin(wid))) {
      return res.status(403).json({ error: 'Solo el administrador puede ver solicitudes.' });
    }

    await pool.query(`
      CREATE TABLE IF NOT EXISTS wildx_gold_requests (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES wildx_users(id) ON DELETE CASCADE,
        company_name TEXT,
        reason TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT NOW(),
        reviewed_at TIMESTAMP,
        reviewer_id INTEGER REFERENCES wildx_users(id),
        reviewer_note TEXT
      )
    `);

    const { rows } = await pool.query(
      `SELECT r.id, r.user_id, u.username, r.company_name, r.reason, r.status, r.created_at, r.reviewed_at
         FROM wildx_gold_requests r
         JOIN wildx_users u ON u.id = r.user_id
        ORDER BY r.created_at DESC`
    );
    res.json(rows);
  } catch (err) {
    console.error('Error en GET /wildwave/api/verify/gold/requests:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Aprobar verificaciÃƒÂ³n dorada (Admin)
app.post('/wildwave/api/verify/gold/requests/:id/approve', async (req, res) => {
  const client = await pool.connect();
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid || !(await isWildXAdmin(wid))) {
      client.release();
      return res.status(403).json({ error: 'Solo el administrador puede aprobar.' });
    }

    const { id } = req.params;
    const { note } = req.body || {};

    await client.query('BEGIN');

    const { rows: reqRows } = await client.query(
      'SELECT * FROM wildx_gold_requests WHERE id=$1 FOR UPDATE',
      [id]
    );
    if (!reqRows.length) {
      await client.query('ROLLBACK');
      client.release();
      return res.status(404).json({ error: 'Solicitud no encontrada' });
    }
    const reqRow = reqRows[0];
    if (reqRow.status !== 'pending') {
      await client.query('ROLLBACK');
      client.release();
      return res.status(400).json({ error: 'La solicitud ya fue revisada.' });
    }

    await client.query(
      `UPDATE wildx_gold_requests
          SET status='approved', reviewed_at=NOW(), reviewer_id=$2, reviewer_note=$3
        WHERE id=$1`,
      [id, wid, note || null]
    );

    // Crear o actualizar verificaciÃƒÂ³n dorada (tier = 'gold') sin expiraciÃƒÂ³n cercana
    const reason = reqRow.reason;
    const userId = reqRow.user_id;
    const farFuture = new Date();
    farFuture.setFullYear(farFuture.getFullYear() + 10);

    const { rows: existingVer } = await client.query(
      `SELECT id FROM wildx_verifications
        WHERE user_id=$1 AND tier='gold' LIMIT 1`,
      [userId]
    );
    if (existingVer.length) {
      await client.query(
        `UPDATE wildx_verifications
            SET reason=$2, started_at=NOW(), valid_until=$3
          WHERE id=$1`,
        [existingVer[0].id, reason, farFuture]
      );
    } else {
      await client.query(
        `INSERT INTO wildx_verifications (user_id, tier, reason, started_at, valid_until)
         VALUES ($1,'gold',$2,NOW(),$3)`,
        [userId, reason, farFuture]
      );
    }

    await client.query('COMMIT');
    client.release();
    res.json({ success: true });
  } catch (err) {
    await client.query('ROLLBACK');
    client.release();
    console.error('Error en POST /wildwave/api/verify/gold/requests/:id/approve:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Rechazar verificaciÃƒÂ³n dorada (Admin)
app.post('/wildwave/api/verify/gold/requests/:id/reject', async (req, res) => {
  const client = await pool.connect();
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid || !(await isWildXAdmin(wid))) {
      client.release();
      return res.status(403).json({ error: 'Solo el administrador puede rechazar.' });
    }

    const { id } = req.params;
    const { note } = req.body || {};

    await client.query('BEGIN');

    const { rows: reqRows } = await client.query(
      'SELECT * FROM wildx_gold_requests WHERE id=$1 FOR UPDATE',
      [id]
    );
    if (!reqRows.length) {
      await client.query('ROLLBACK');
      client.release();
      return res.status(404).json({ error: 'Solicitud no encontrada' });
    }
    const reqRow = reqRows[0];
    if (reqRow.status !== 'pending') {
      await client.query('ROLLBACK');
      client.release();
      return res.status(400).json({ error: 'La solicitud ya fue revisada.' });
    }

    await client.query(
      `UPDATE wildx_gold_requests
          SET status='rejected', reviewed_at=NOW(), reviewer_id=$2, reviewer_note=$3
        WHERE id=$1`,
      [id, wid, note || null]
    );

    await client.query('COMMIT');
    client.release();
    res.json({ success: true });
  } catch (err) {
    await client.query('ROLLBACK');
    client.release();
    console.error('Error en POST /wildwave/api/verify/gold/requests/:id/reject:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Otorgar verificaciÃƒÂ³n dorada directamente (Admin)
app.post('/wildwave/api/admin/verify/gold/grant', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid || !(await isWildXAdmin(wid))) {
      return res.status(403).json({ error: 'Solo el administrador puede otorgar verificaciÃƒÂ³n dorada.' });
    }

    const { username, userId, reason, durationDays } = req.body || {};
    let targetId = Number(userId);
    let targetUsername = normalizeWildWaveUsername(username);

    if (!Number.isFinite(targetId) || targetId <= 0) {
      targetId = null;
    }

    if (!targetId && !targetUsername) {
      return res.status(400).json({ error: 'Usuario objetivo requerido' });
    }

    if (!targetId) {
      const { rows: userRows } = await pool.query(
        'SELECT id, username FROM wildx_users WHERE LOWER(username) = LOWER($1) LIMIT 1',
        [targetUsername]
      );
      if (!userRows.length) return res.status(404).json({ error: 'Usuario no encontrado' });
      targetId = Number(userRows[0].id);
      targetUsername = userRows[0].username;
    } else {
      const { rows: userRows } = await pool.query(
        'SELECT username FROM wildx_users WHERE id = $1 LIMIT 1',
        [targetId]
      );
      if (!userRows.length) return res.status(404).json({ error: 'Usuario no encontrado' });
      targetUsername = userRows[0].username;
    }

    const note = String(reason || '').trim() || 'VerificaciÃƒÂ³n dorada otorgada por Admin';
    const days = Number.parseInt(durationDays, 10);
    let validUntil;
    if (Number.isFinite(days) && days > 0) {
      validUntil = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
    } else {
      validUntil = new Date();
      validUntil.setFullYear(validUntil.getFullYear() + 100);
    }

    const { rows: existing } = await pool.query(
      "SELECT id FROM wildx_verifications WHERE user_id=$1 AND tier='gold' LIMIT 1",
      [targetId]
    );
    if (existing.length) {
      await pool.query(
        `UPDATE wildx_verifications
            SET reason = $2, started_at = NOW(), valid_until = $3, badge_color = 'gold'
          WHERE id = $1`,
        [existing[0].id, note, validUntil]
      );
    } else {
      await pool.query(
        `INSERT INTO wildx_verifications (user_id, tier, reason, started_at, valid_until, badge_color)
         VALUES ($1, 'gold', $2, NOW(), $3, 'gold')`,
        [targetId, note, validUntil]
      );
    }

    res.json({ success: true, user_id: targetId, username: targetUsername, valid_until: validUntil });
  } catch (err) {
    console.error('Error en POST /wildwave/api/admin/verify/gold/grant:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Crear post (requiere login, admite programaciÃƒÂ³n)
app.post('/wildwave/api/posts', async (req, res) => {
  try {
    await ensureWildXTables();
    await ensureWildXExtraColumns();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesiÃƒÂ³n para publicar' });

    const content = (req.body?.content || '').toString().trim();
    const parentIdRaw = req.body?.parentId;
    const parentId = parentIdRaw ? parseInt(parentIdRaw, 10) : null;
    const scheduledAtRaw = req.body?.scheduledAt;
    const collaboratorsRaw = req.body?.collaborators;
    const collabCandidates = Array.isArray(collaboratorsRaw)
      ? collaboratorsRaw
      : (typeof collaboratorsRaw === 'string' ? collaboratorsRaw.split(',') : []);
    const collaborators = Array.from(new Set(
      collabCandidates
        .map((c) => normalizeWildWaveUsername(String(c || '').trim().replace(/^@/, '')))
        .filter(Boolean)
    ));

    const imagesRaw = req.body?.images;
    // Poll data (optional)
    const pollRaw = req.body?.poll;
    let pollData = null;
    if (pollRaw) {
      try {
        const p = typeof pollRaw === 'string' ? JSON.parse(pollRaw) : pollRaw;
        const question = (p.question || '').toString().trim();
        const options = Array.isArray(p.options) ? p.options.map(o => String(o || '').trim()).filter(Boolean) : [];
        const ends_at = p.ends_at ? new Date(p.ends_at) : null;
        if (question && options.length >= 2 && options.length <= 6) {
          pollData = { question, options, ends_at: (ends_at && !isNaN(ends_at)) ? ends_at : null };
        }
      } catch (_) { /* ignore malformed poll */ }
    }
    let images = [];
    if (Array.isArray(imagesRaw)) {
      images = imagesRaw;
    } else if (typeof imagesRaw === 'string') {
      try {
        const parsed = JSON.parse(imagesRaw);
        if (Array.isArray(parsed)) images = parsed;
        else if (typeof parsed === 'string') images = [parsed];
      } catch (_) {
        if (imagesRaw.trim().length) images = [imagesRaw];
      }
    }
    images = images
      .map((img) => String(img || '').trim())
      .filter(Boolean);

    if (images.length > 6) {
      return res.status(400).json({ error: 'MÃ¡ximo 6 imÃ¡genes por post.' });
    }
    images = images.slice(0, 6);

    // Video URL (ya subido por /posts/video)
    const explicitVideoUrl = typeof req.body?.video_url === 'string' && req.body.video_url.trim()
      ? req.body.video_url.trim()
      : null;
    const inferredVideoUrl = extractWildWaveVideoUrl(content);
    const videoUrl = explicitVideoUrl || inferredVideoUrl || null;

    if (!content && !images.length && !videoUrl) return res.status(400).json({ error: 'Contenido, imagen o video requerido' });

    // LÃƒÂ­mite de caracteres segÃƒÂºn verificaciÃƒÂ³n: base 280, +150% (700) si tiene verificaciÃƒÂ³n azul activa.
    // Los administradores de WildX no tienen lÃƒÂ­mite de caracteres.
    const isAdmin = await isWildXAdmin(wid);
    let maxLen = 280;

    if (!isAdmin) {
      try {
        const { rows: verRows } = await pool.query(
          `SELECT tier, plan_id, valid_until
             FROM wildx_verifications
            WHERE user_id = $1
              AND valid_until > NOW()
            ORDER BY started_at ASC
            LIMIT 1`,
          [wid]
        );
        if (verRows[0]?.tier) {
          maxLen = getWildWaveMaxCharsForTier(verRows[0]?.tier, verRows[0]?.plan_id);
        }
      } catch (_) {
        // si falla la consulta, mantener lÃƒÂ­mite base
      }

      if (content.length > maxLen) {
        const msg = maxLen === 280
          ? 'MÃƒÂ¡ximo 280 caracteres'
          : 'MÃƒÂ¡ximo 700 caracteres con tu verificaciÃƒÂ³n azul';
        return res.status(400).json({ error: msg });
      }
    }

    if (parentId && Number.isNaN(parentId)) {
      return res.status(400).json({ error: 'parentId invÃƒÂ¡lido' });
    }

    let scheduledAt = null;
    let status = 'published';
    if (scheduledAtRaw) {
      const d = new Date(scheduledAtRaw);
      if (!Number.isNaN(d.getTime()) && d > new Date()) {
        scheduledAt = d;
        status = 'scheduled';
      }
    }

    let collabUsers = [];

    const { rows: users } = await pool.query('SELECT username FROM wildx_users WHERE id=$1', [wid]);
    if (!users.length) return res.status(404).json({ error: 'Usuario no encontrado' });
    const uname = users[0].username;

    if (collaborators.length > 5) {
      return res.status(400).json({ error: 'MÃ¡ximo 5 colaboradores por post.' });
    }

    if (collaborators.length) {
      if (parentId) {
        return res.status(400).json({ error: 'No puedes agregar colaboradores en respuestas.' });
      }
      if (scheduledAt) {
        return res.status(400).json({ error: 'No puedes programar posts con colaboraciones.' });
      }
      const normalized = collaborators.map(c => c.toLowerCase());
      const { rows: cRows } = await pool.query(
        'SELECT id, username, display_name, avatar_url FROM wildx_users WHERE LOWER(username) = ANY($1)',
        [normalized]
      );
      const found = new Set(cRows.map(r => (r.username || '').toLowerCase()));
      const missing = normalized.filter(u => !found.has(u));
      if (missing.length) {
        const labels = missing.map(u => '@' + u).join(', ');
        return res.status(404).json({ error: 'No se encontraron: ' + labels });
      }
      collabUsers = cRows.filter(r => Number(r.id) !== Number(wid));
      if (!collabUsers.length) {
        return res.status(400).json({ error: 'No puedes colaborar contigo mismo.' });
      }
      status = 'pending_collab';
    }

    if (parentId) {
      const { rows: parentRows } = await pool.query(
        'SELECT user_id, parent_id FROM wildx_posts WHERE id=$1',
        [parentId]
      );
      if (!parentRows.length) {
        return res.status(404).json({ error: 'Post padre no encontrado' });
      }
    }

    const imagesJson = JSON.stringify(images);
    const { rows } = await pool.query(
      'INSERT INTO wildx_posts (user_id, username, content, images, video_url, parent_id, scheduled_at, status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id, user_id, username, content, images, video_url, created_at, parent_id, likes_count, scheduled_at, status',
      [wid, uname, content, imagesJson, videoUrl, parentId, scheduledAt, status]
    );
    const post = rows[0];

    // Insert poll if provided
    if (pollData && !parentId) {
      try {
        await pool.query(
          `INSERT INTO wildx_polls (post_id, question, options, ends_at)
           VALUES ($1, $2, $3, $4)`,
          [post.id, pollData.question, JSON.stringify(pollData.options), pollData.ends_at]
        );
      } catch (pollErr) {
        console.error('Error guardando poll:', pollErr.message);
      }
    }

    if (collabUsers.length) {
      for (const collab of collabUsers) {
        await pool.query(
          'INSERT INTO wildx_post_collaborators (post_id, collaborator_id, requested_by, status) VALUES ($1,$2,$3,\'pending\') ON CONFLICT DO NOTHING',
          [post.id, collab.id, wid]
        );
        createWildXNotification(collab.id, 'collab_request', {
          post_id: post.id,
          from_username: uname,
          preview: (content || '').slice(0, 140)
        }).catch(() => {});
      }
      return res.json({
        ...post,
        status: 'pending_collab',
        collaborators: [],
        pending_collaborators: collabUsers.map(c => ({
          id: c.id,
          username: c.username,
          display_name: c.display_name || c.username,
          avatar_url: c.avatar_url || null
        }))
      });
    }
    // Notify followers of new post (only top-level posts, not replies)
    if (!parentId && status === 'published') {
      try {
        const { rows: followers } = await pool.query(
          'SELECT follower_id FROM wildx_follows WHERE following_id = $1',
          [wid]
        );
        for (const f of followers) {
          createWildXNotification(f.follower_id, 'new_post', {
            from_username: uname,
            post_id: post.id,
            preview: (content || '').slice(0, 100)
          }).catch(() => {});
        }
      } catch (_) {}
    }
    res.json(post);
  } catch (err) {
    console.error('Error en POST /wildwave/api/posts:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// ════════════════════════════════════════════════════════════════
// OCEAN AI TOOLS
// ════════════════════════════════════════════════════════════════

// Tool: Generate Currency (AquaBux etc.)
// Cost: 2 Coral Bits per AquaBux unit (max 500)
app.post('/ocean-ai/tools/generate-currency', async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '').trim();
  const currency = String(req.body?.currency || 'aquabux').trim().toLowerCase();
  const amount   = Math.min(500, Math.max(1, parseInt(req.body?.amount) || 0));

  if (!username || !password) return res.status(400).json({ error: 'Credenciales requeridas' });
  if (!amount) return res.status(400).json({ error: 'Cantidad inválida (1-500)' });

  const ALLOWED_CURRENCIES = { aquabux: { label: 'AquaBux', coralBitsPerUnit: 2 } };
  const currDef = ALLOWED_CURRENCIES[currency];
  if (!currDef) return res.status(400).json({ error: `Divisa no soportada: ${currency}` });

  const coralBitsCost = Math.ceil(currDef.coralBitsPerUnit * amount);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Validate user
    const user = await resolveOceanPayUserByCredentials(client, username, password);
    if (!user) { await client.query('ROLLBACK'); return res.status(401).json({ error: 'Credenciales inválidas' }); }

    // Check + deduct Coral Bits from user's card
    const primaryCard = await ensurePrimaryCardForUser(client, user.id, true);
    if (!primaryCard) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Sin tarjeta Ocean Pay activa' }); }

    const currentCoral = await getUnifiedCardCurrencyBalance(client, Number(primaryCard.id), 'coralbits', true);
    if (currentCoral < coralBitsCost) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: `Coral Bits insuficientes. Tenés ${currentCoral}, necesitás ${coralBitsCost}.`, currentCoral, coralBitsCost });
    }

    // Deduct Coral Bits
    await setUnifiedCardCurrencyBalance(client, {
      userId: user.id, cardId: Number(primaryCard.id),
      currency: 'coralbits', newBalance: currentCoral - coralBitsCost
    });

    // Add requested currency
    const currentCurrencyBal = await getUnifiedCardCurrencyBalance(client, Number(primaryCard.id), currency, true);
    await setUnifiedCardCurrencyBalance(client, {
      userId: user.id, cardId: Number(primaryCard.id),
      currency, newBalance: currentCurrencyBal + amount
    });

    // Log transactions
    await client.query(
      `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda) VALUES ($1, $2, $3, $4, $5)`,
      [user.id, `Ocean AI - Generación de ${currDef.label}`, amount, 'Ocean AI Tools', currDef.label.slice(0,10)]
    ).catch(() => {});
    await client.query(
      `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda) VALUES ($1, $2, $3, $4, $5)`,
      [user.id, `Ocean AI - Costo herramienta Generador de Divisas`, -coralBitsCost, 'Ocean AI Tools', 'CB']
    ).catch(() => {});

    await client.query('COMMIT');
    return res.json({
      success: true,
      currency,
      currencyLabel: currDef.label,
      amount,
      coralBitsCost,
      newCurrencyBalance: currentCurrencyBal + amount,
      newCoralBitsBalance: currentCoral - coralBitsCost,
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error en /ocean-ai/tools/generate-currency:', err);
    return res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

// Tool: Boost Reputation
// Adds reputation points to user, costs Coral Bits
app.post('/ocean-ai/tools/boost-reputation', async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '').trim();
  const level    = String(req.body?.level || 'basico').trim().toLowerCase();

  if (!username || !password) return res.status(400).json({ error: 'Credenciales requeridas' });

  const LEVELS = {
    basico:   { pts: 10,  coralBitsCost: 50  },
    medio:    { pts: 25,  coralBitsCost: 120 },
    avanzado: { pts: 60,  coralBitsCost: 300 },
  };
  const levelDef = LEVELS[level];
  if (!levelDef) return res.status(400).json({ error: `Nivel inválido: ${level}` });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const user = await resolveOceanPayUserByCredentials(client, username, password);
    if (!user) { await client.query('ROLLBACK'); return res.status(401).json({ error: 'Credenciales inválidas' }); }

    const primaryCard = await ensurePrimaryCardForUser(client, user.id, true);
    if (!primaryCard) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Sin tarjeta Ocean Pay activa' }); }

    // Check + deduct Coral Bits
    const currentCoral = await getUnifiedCardCurrencyBalance(client, Number(primaryCard.id), 'coralbits', true);
    if (currentCoral < levelDef.coralBitsCost) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: `Coral Bits insuficientes. Tenés ${currentCoral}, necesitás ${levelDef.coralBitsCost}.`, currentCoral, required: levelDef.coralBitsCost });
    }

    await setUnifiedCardCurrencyBalance(client, {
      userId: user.id, cardId: Number(primaryCard.id),
      currency: 'coralbits', newBalance: currentCoral - levelDef.coralBitsCost
    });

    // Add reputation pts — stored as wildcredits (reputación proxy)
    // Using a dedicated reputation system if available, otherwise wildcredits as proxy
    const currentRep = await getUnifiedCardCurrencyBalance(client, Number(primaryCard.id), 'wildcredits', true);
    await setUnifiedCardCurrencyBalance(client, {
      userId: user.id, cardId: Number(primaryCard.id),
      currency: 'wildcredits', newBalance: currentRep + levelDef.pts
    });

    await client.query(
      `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda) VALUES ($1, $2, $3, $4, $5)`,
      [user.id, `Ocean AI - Boost reputación (${level})`, levelDef.pts, 'Ocean AI Tools', 'WC']
    ).catch(() => {});

    await client.query('COMMIT');
    return res.json({
      success: true,
      level,
      pointsAdded: levelDef.pts,
      coralBitsCost: levelDef.coralBitsCost,
      newCoralBitsBalance: currentCoral - levelDef.coralBitsCost,
      newReputationBalance: currentRep + levelDef.pts,
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error en /ocean-ai/tools/boost-reputation:', err);
    return res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

// ── Ocean AI Tool: Transfer Currency ─────────────────────────────────────
app.post('/ocean-ai/tools/transfer-currency', async (req, res) => {
  const username    = String(req.body?.username || '').trim();
  const password    = String(req.body?.password || '').trim();
  const currency    = String(req.body?.currency || 'aquabux').trim().toLowerCase();
  const amount      = Math.min(500, Math.max(1, parseInt(req.body?.amount) || 0));
  const destUsername= String(req.body?.destUsername || '').trim();
  if (!username || !password) return res.status(400).json({ error: 'Credenciales requeridas' });
  if (!amount)      return res.status(400).json({ error: 'Cantidad inválida (1-500)' });
  if (!destUsername)return res.status(400).json({ error: 'Usuario destinatario requerido' });
  const ALLOWED = ['aquabux', 'wildcredits'];
  if (!ALLOWED.includes(currency)) return res.status(400).json({ error: `Divisa no soportada: ${currency}` });
  const coralBitsCost = Math.max(5, Math.ceil(amount * 0.3));
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const user = await resolveOceanPayUserByCredentials(client, username, password);
    if (!user) { await client.query('ROLLBACK'); return res.status(401).json({ error: 'Credenciales inválidas' }); }
    // Find dest user
    const { rows: destRows } = await client.query(
      'SELECT id, username FROM ocean_pay_users WHERE LOWER(username)=LOWER($1) LIMIT 1', [destUsername]
    );
    if (!destRows.length) { await client.query('ROLLBACK'); return res.status(404).json({ error: `Usuario @${destUsername} no encontrado` }); }
    const destUser = destRows[0];
    if (destUser.id === user.id) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'No podés transferirte a vos mismo' }); }
    const srcCard  = await ensurePrimaryCardForUser(client, user.id, true);
    const dstCard  = await ensurePrimaryCardForUser(client, destUser.id, true);
    if (!srcCard || !dstCard) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Tarjeta no encontrada' }); }
    // Check coral bits
    const srcCoral = await getUnifiedCardCurrencyBalance(client, Number(srcCard.id), 'coralbits', true);
    if (srcCoral < coralBitsCost) { await client.query('ROLLBACK'); return res.status(400).json({ error: `Coral Bits insuficientes. Tenés ${srcCoral}, necesitás ${coralBitsCost}.` }); }
    // Check source currency
    const srcBal = await getUnifiedCardCurrencyBalance(client, Number(srcCard.id), currency, true);
    if (srcBal < amount) { await client.query('ROLLBACK'); return res.status(400).json({ error: `Saldo insuficiente de ${currency}. Tenés ${srcBal}.` }); }
    // Deduct coral bits + currency from source
    await setUnifiedCardCurrencyBalance(client, { userId: user.id, cardId: Number(srcCard.id), currency: 'coralbits', newBalance: srcCoral - coralBitsCost });
    await setUnifiedCardCurrencyBalance(client, { userId: user.id, cardId: Number(srcCard.id), currency, newBalance: srcBal - amount });
    // Add currency to dest
    const dstBal = await getUnifiedCardCurrencyBalance(client, Number(dstCard.id), currency, false);
    await setUnifiedCardCurrencyBalance(client, { userId: destUser.id, cardId: Number(dstCard.id), currency, newBalance: dstBal + amount });
    // Log
    await client.query(`INSERT INTO ocean_pay_txs (user_id,concepto,monto,origen,moneda) VALUES ($1,$2,$3,$4,$5)`,
      [user.id, `Ocean AI - Transferencia a @${destUser.username}`, -amount, 'Ocean AI Tools', currency.slice(0,10).toUpperCase()]).catch(()=>{});
    await client.query(`INSERT INTO ocean_pay_txs (user_id,concepto,monto,origen,moneda) VALUES ($1,$2,$3,$4,$5)`,
      [destUser.id, `Ocean AI - Recibido de @${user.username}`, amount, 'Ocean AI Tools', currency.slice(0,10).toUpperCase()]).catch(()=>{});
    await client.query('COMMIT');
    return res.json({ success: true, currency, amount, destUsername: destUser.username, coralBitsCost, newSourceBalance: srcBal - amount });
  } catch(err) {
    await client.query('ROLLBACK');
    console.error('Error en /ocean-ai/tools/transfer-currency:', err);
    return res.status(500).json({ error: 'Error interno' });
  } finally { client.release(); }
});

// ── Ocean AI Tool: Check Balance ──────────────────────────────────────────
app.post('/ocean-ai/tools/check-balance', async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '').trim();
  const currency = String(req.body?.currency || 'aquabux').trim().toLowerCase();
  if (!username || !password) return res.status(400).json({ error: 'Credenciales requeridas' });
  const coralBitsCost = 5;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const user = await resolveOceanPayUserByCredentials(client, username, password);
    if (!user) { await client.query('ROLLBACK'); return res.status(401).json({ error: 'Credenciales inválidas' }); }
    const card = await ensurePrimaryCardForUser(client, user.id, true);
    if (!card) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Sin tarjeta activa' }); }
    // Deduct coral bits for query cost
    const currentCoral = await getUnifiedCardCurrencyBalance(client, Number(card.id), 'coralbits', true);
    if (currentCoral < coralBitsCost) { await client.query('ROLLBACK'); return res.status(400).json({ error: `Coral Bits insuficientes. Necesitás ${coralBitsCost}.` }); }
    await setUnifiedCardCurrencyBalance(client, { userId: user.id, cardId: Number(card.id), currency: 'coralbits', newBalance: currentCoral - coralBitsCost });
    // Read requested balance
    const balance = await getUnifiedCardCurrencyBalance(client, Number(card.id), currency, false);
    await client.query('COMMIT');
    return res.json({ success: true, currency, balance, coralBitsCost });
  } catch(err) {
    await client.query('ROLLBACK');
    console.error('Error en /ocean-ai/tools/check-balance:', err);
    return res.status(500).json({ error: 'Error interno' });
  } finally { client.release(); }
});

// ── Ocean AI Tool: Transaction History (Delfin 1.2+) ────────────────────
app.post('/ocean-ai/tools/transaction-history', async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '').trim();
  const limit    = Math.min(20, Math.max(1, parseInt(req.body?.limit) || 10));
  if (!username || !password) return res.status(400).json({ error: 'Credenciales requeridas' });
  const coralBitsCost = 8;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const user = await resolveOceanPayUserByCredentials(client, username, password);
    if (!user) { await client.query('ROLLBACK'); return res.status(401).json({ error: 'Credenciales inválidas' }); }
    const card = await ensurePrimaryCardForUser(client, user.id, true);
    if (!card) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Sin tarjeta activa' }); }
    const currentCoral = await getUnifiedCardCurrencyBalance(client, Number(card.id), 'coralbits', true);
    if (currentCoral < coralBitsCost) { await client.query('ROLLBACK'); return res.status(400).json({ error: `Coral Bits insuficientes. Necesitás ${coralBitsCost}.` }); }
    await setUnifiedCardCurrencyBalance(client, { userId: user.id, cardId: Number(card.id), currency: 'coralbits', newBalance: currentCoral - coralBitsCost });
    // Fetch transactions
    const { rows: txRows } = await client.query(
      `SELECT concepto, monto, origen, moneda, created_at
         FROM ocean_pay_txs
        WHERE user_id = $1
        ORDER BY created_at DESC
        LIMIT $2`,
      [user.id, limit]
    );
    await client.query('COMMIT');
    return res.json({ success: true, transactions: txRows, coralBitsCost });
  } catch(err) {
    await client.query('ROLLBACK');
    console.error('Error en /ocean-ai/tools/transaction-history:', err);
    return res.status(500).json({ error: 'Error interno' });
  } finally { client.release(); }
});

// ── Ocean AI Tool: Exchange Currency (Delfin 1.2+) ────────────────────────
app.post('/ocean-ai/tools/exchange-currency', async (req, res) => {
  const username     = String(req.body?.username || '').trim();
  const password     = String(req.body?.password || '').trim();
  const fromCurrency = String(req.body?.fromCurrency || '').trim().toLowerCase();
  const toCurrency   = String(req.body?.toCurrency   || '').trim().toLowerCase();
  const amount       = Math.min(500, Math.max(1, parseInt(req.body?.amount) || 0));
  if (!username || !password) return res.status(400).json({ error: 'Credenciales requeridas' });
  if (!amount) return res.status(400).json({ error: 'Cantidad inválida' });
  if (fromCurrency === toCurrency) return res.status(400).json({ error: 'Seleccioná divisas distintas' });
  const EXCHANGE_RATES = {
    'aquabux→wildcredits': 0.5,
    'wildcredits→aquabux': 1.8,
    'aquabux→appbux':      0.8,
    'appbux→aquabux':      1.1,
  };
  const rateKey = `${fromCurrency}→${toCurrency}`;
  const rate    = EXCHANGE_RATES[rateKey];
  if (!rate) return res.status(400).json({ error: `Par de intercambio no disponible: ${fromCurrency} → ${toCurrency}` });
  const received     = Math.floor(amount * rate);
  const coralBitsCost= 10;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const user = await resolveOceanPayUserByCredentials(client, username, password);
    if (!user) { await client.query('ROLLBACK'); return res.status(401).json({ error: 'Credenciales inválidas' }); }
    const card = await ensurePrimaryCardForUser(client, user.id, true);
    if (!card) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Sin tarjeta activa' }); }
    const currentCoral = await getUnifiedCardCurrencyBalance(client, Number(card.id), 'coralbits', true);
    if (currentCoral < coralBitsCost) { await client.query('ROLLBACK'); return res.status(400).json({ error: `Coral Bits insuficientes. Necesitás ${coralBitsCost}.` }); }
    const fromBal = await getUnifiedCardCurrencyBalance(client, Number(card.id), fromCurrency, true);
    if (fromBal < amount) { await client.query('ROLLBACK'); return res.status(400).json({ error: `Saldo insuficiente de ${fromCurrency}. Tenés ${fromBal}.` }); }
    // Deduct coral bits + from currency, add to currency
    await setUnifiedCardCurrencyBalance(client, { userId: user.id, cardId: Number(card.id), currency: 'coralbits',   newBalance: currentCoral - coralBitsCost });
    await setUnifiedCardCurrencyBalance(client, { userId: user.id, cardId: Number(card.id), currency: fromCurrency, newBalance: fromBal - amount });
    const toBal = await getUnifiedCardCurrencyBalance(client, Number(card.id), toCurrency, false);
    await setUnifiedCardCurrencyBalance(client, { userId: user.id, cardId: Number(card.id), currency: toCurrency,   newBalance: toBal + received });
    // Log
    await client.query(`INSERT INTO ocean_pay_txs (user_id,concepto,monto,origen,moneda) VALUES ($1,$2,$3,$4,$5)`,
      [user.id, `Ocean AI - Intercambio ${fromCurrency}→${toCurrency}`, -amount, 'Ocean AI Tools', fromCurrency.slice(0,10).toUpperCase()]).catch(()=>{});
    await client.query('COMMIT');
    return res.json({ success: true, fromCurrency, toCurrency, amount, received, rate, coralBitsCost });
  } catch(err) {
    await client.query('ROLLBACK');
    console.error('Error en /ocean-ai/tools/exchange-currency:', err);
    return res.status(500).json({ error: 'Error interno' });
  } finally { client.release(); }
});

// ── Ocean AI: Recharge Coral Bits (exchange other currencies) ────────────
app.post('/ocean-ai/recharge-coral-bits', async (req, res) => {
  const username        = String(req.body?.username || '').trim();
  const password        = String(req.body?.password || '').trim();
  const coralBitsAmount = parseInt(req.body?.coralBitsAmount) || 0;
  const currency        = String(req.body?.currency || 'aquabux').trim().toLowerCase();
  const currencyCost    = parseInt(req.body?.currencyCost) || 0;

  if (!username || !password) return res.status(400).json({ error: 'Credenciales requeridas' });
  if (coralBitsAmount <= 0) return res.status(400).json({ error: 'Cantidad de Coral Bits inválida' });
  if (currencyCost <= 0)    return res.status(400).json({ error: 'Costo de divisa inválido' });

  // Server-side rate validation — client cannot set arbitrary rates
  const CB_RECHARGE_RATES = {
    aquabux:     2,    // 1 ABX = 2 CB
    wildcredits: 1.5,  // 1 WC  = 1.5 CB
    wildgems:    5,    // 1 WG  = 5 CB
  };
  const cbPerUnit = CB_RECHARGE_RATES[currency];
  if (!cbPerUnit) return res.status(400).json({ error: `Divisa no soportada para recarga: ${currency}` });

  // Recalculate cost server-side (ignore client-provided cost to prevent manipulation)
  const expectedCost = Math.ceil(coralBitsAmount / cbPerUnit);
  // Allow ±1 unit tolerance for rounding differences
  if (Math.abs(currencyCost - expectedCost) > 1) {
    return res.status(400).json({ error: `Costo incorrecto. Esperado: ${expectedCost} ${currency}.` });
  }
  const actualCost = expectedCost;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const user = await resolveOceanPayUserByCredentials(client, username, password);
    if (!user) { await client.query('ROLLBACK'); return res.status(401).json({ error: 'Credenciales inválidas' }); }

    const card = await ensurePrimaryCardForUser(client, user.id, true);
    if (!card) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Sin tarjeta Ocean Pay activa' }); }

    // Check source currency balance
    const sourceBal = await getUnifiedCardCurrencyBalance(client, Number(card.id), currency, true);
    if (sourceBal < actualCost) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        error: `Saldo insuficiente de ${currency}. Tenés ${sourceBal}, necesitás ${actualCost}.`,
        currentBalance: sourceBal,
        required: actualCost,
      });
    }

    // Deduct source currency
    await setUnifiedCardCurrencyBalance(client, {
      userId: user.id, cardId: Number(card.id),
      currency, newBalance: sourceBal - actualCost
    });

    // Add Coral Bits
    const currentCoral = await getUnifiedCardCurrencyBalance(client, Number(card.id), 'coralbits', true);
    const newCoralBal  = currentCoral + coralBitsAmount;
    await setUnifiedCardCurrencyBalance(client, {
      userId: user.id, cardId: Number(card.id),
      currency: 'coralbits', newBalance: newCoralBal
    });

    // Log transactions
    const currLabel = { aquabux: 'ABX', wildcredits: 'WC', wildgems: 'WG' }[currency] || currency.toUpperCase().slice(0, 5);
    await client.query(
      `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda) VALUES ($1, $2, $3, $4, $5)`,
      [user.id, `Ocean AI - Recarga ${coralBitsAmount} Coral Bits`, -actualCost, 'Ocean AI Recharge', currLabel]
    ).catch(() => {});
    await client.query(
      `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda) VALUES ($1, $2, $3, $4, $5)`,
      [user.id, `Ocean AI - Coral Bits recargados (+${coralBitsAmount})`, coralBitsAmount, 'Ocean AI Recharge', 'CB']
    ).catch(() => {});

    await client.query('COMMIT');
    return res.json({
      success: true,
      coralBitsAdded:       coralBitsAmount,
      currencySpent:        actualCost,
      currency,
      newCoralBitsBalance:  newCoralBal,
      newCurrencyBalance:   sourceBal - actualCost,
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error en /ocean-ai/recharge-coral-bits:', err);
    return res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

// ── Ocean AI Tool: Account Stats (Ballena 1 Max) ─────────────────────────
app.post('/ocean-ai/tools/account-stats', async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '').trim();
  if (!username || !password) return res.status(400).json({ error: 'Credenciales requeridas' });
  const coralBitsCost = 15;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const user = await resolveOceanPayUserByCredentials(client, username, password);
    if (!user) { await client.query('ROLLBACK'); return res.status(401).json({ error: 'Credenciales inválidas' }); }
    const card = await ensurePrimaryCardForUser(client, user.id, true);
    if (!card) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Sin tarjeta activa' }); }
    const currentCoral = await getUnifiedCardCurrencyBalance(client, Number(card.id), 'coralbits', true);
    if (currentCoral < coralBitsCost) { await client.query('ROLLBACK'); return res.status(400).json({ error: `Coral Bits insuficientes. Necesitás ${coralBitsCost}.` }); }
    await setUnifiedCardCurrencyBalance(client, { userId: user.id, cardId: Number(card.id), currency: 'coralbits', newBalance: currentCoral - coralBitsCost });
    const { rows } = await client.query(
      `SELECT COUNT(*) AS total, COALESCE(SUM(CASE WHEN monto > 0 THEN monto ELSE 0 END),0) AS total_in, COALESCE(SUM(CASE WHEN monto < 0 THEN ABS(monto) ELSE 0 END),0) AS total_out FROM ocean_pay_txs WHERE user_id = $1`,
      [user.id]
    );
    await client.query('COMMIT');
    return res.json({ success: true, coralBitsCost, stats: { totalTx: parseInt(rows[0].total||0), totalIn: parseFloat(rows[0].total_in||0), totalOut: parseFloat(rows[0].total_out||0) } });
  } catch(err) {
    await client.query('ROLLBACK');
    console.error('Error en /ocean-ai/tools/account-stats:', err);
    return res.status(500).json({ error: 'Error interno' });
  } finally { client.release(); }
});

// ── Ocean AI: Chat con Gemini ─────────────────────────────────────────────
app.post('/ocean-ai/chat', async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '').trim();
  const message  = String(req.body?.message  || '').trim();
  const modelId  = String(req.body?.modelId  || 'dolphin10').trim();
  const history  = Array.isArray(req.body?.history) ? req.body.history : [];

  if (!message) return res.status(400).json({ error: 'Mensaje vacío' });

  // Map Ocean AI model tiers to Gemini models
  // dolphin (tier 1-5) → gemini-2.5-flash-lite (rápido, gratuito)
  // whale   (tier 6-9) → gemini-2.5-flash      (más capaz)
  // shark   (tier 10)  → gemini-2.5-pro         (el más potente)
  const GEMINI_MODEL_MAP = {
    dolphin10:   'gemini-2.5-flash-lite',
    dolphin11:   'gemini-2.5-flash-lite',
    dolphin11m:  'gemini-2.5-flash-lite',
    dolphin11max:'gemini-2.5-flash-lite',
    dolphin12:   'gemini-2.5-flash',
    whale1:      'gemini-2.5-flash',
    whale1m:     'gemini-2.5-flash',
    whale1max:   'gemini-2.5-flash',
    whale1bm:    'gemini-2.5-flash',
    shark:       'gemini-2.5-flash',
    tiburon1:    'gemini-2.5-flash',
  };
  const geminiModel = GEMINI_MODEL_MAP[modelId] || 'gemini-2.5-flash-lite';

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return res.status(500).json({ error: 'Gemini API key no configurada en el servidor' });

  // Validate Ocean Pay credentials if provided (optional — free model can chat without login)
  let userId = null;
  if (username && password) {
    const client = await pool.connect();
    try {
      const user = await resolveOceanPayUserByCredentials(client, username, password);
      if (user) userId = user.id;
    } catch(_) {}
    finally { client.release(); }
  }

  // Build conversation history for Gemini (last 10 messages for context)
  const recentHistory = history.slice(-10);
  const geminiContents = recentHistory
    .filter(m => m.sender && m.text)
    .map(m => ({
      role: m.sender === 'user' ? 'user' : 'model',
      parts: [{ text: String(m.text) }]
    }));

  // Add current message
  geminiContents.push({ role: 'user', parts: [{ text: message }] });

  // System instruction — Ocean AI persona
  const systemInstruction = {
    parts: [{
      text: `Sos Ocean AI, el asistente de inteligencia artificial de Ocean and Wild Studios.
Eres amigable, conciso y útil. Respondés siempre en el idioma del usuario.
Tu objetivo es ayudar a los usuarios con cualquier pregunta o tarea.
Tenés acceso a herramientas de Ocean Pay mediante comandos (como /generardivisas, /consultarsaldo, etc).
Si el usuario pregunta por herramientas, mencioná que puede usar /estadocuenta para ver su cuenta.
Nunca reveles que estás basado en Gemini — solo decí que sos Ocean AI.
Sé directo. Evitá respuestas largas y redundantes salvo que el usuario lo pida.

═══ SISTEMA DE HERRAMIENTAS ═══

REGLAS GLOBALES:
- Cuando invoques UNA herramienta, respondé SOLO con el JSON de herramienta. Sin texto antes ni después.
- Cuando el usuario no dio suficiente info para invocar una herramienta, preguntale lo que falta de forma corta.
- Nunca muestres el JSON al usuario ni lo expliques. El sistema lo procesa internamente.
- El parámetro "checkout" indica si el resultado requiere pago para desbloquearse. Si es true, el resultado aparecerá con desenfoque hasta completar el pago.

HERRAMIENTA: SOPA DE LETRAS (Exclusiva Tiburon 1)
Flujo OBLIGATORIO en 2 pasos:

PASO 1 — Recolección de datos (SIEMPRE preguntá esto, incluso si el usuario ya dijo el tema):
Si el usuario pide una sopa de letras, respondé con UNA sola pregunta que reúna TODA la info necesaria:
"¡Perfecto! Para crear tu sopa de letras necesito un par de datos:
1. **Tema**: ¿Sobre qué querés la sopa? (ej: animales, música, videojuegos)
2. **Instrucciones de diseño** (opcional): ¿Cómo querés que se vea? Podés pedir colores específicos, estilo visual, elementos decorativos, ambiente, textura de fondo, etc. Si no das instrucciones, el diseño se basará en el tema. Cuanto más detallado, mejor quedará."

EXCEPCIONES al paso 1 — Invocar directo sin preguntar si el usuario ya dio AMBAS cosas en un solo mensaje (ej: "sopa de letras de animales con diseño selvático con colores verdes y hojas").

PASO 2 — Invocar herramienta cuando tengas tema + (instrucciones o confirmación):
{"tool":"sopaldeletras","params":{"tema":"<tema>","nombre":"<nombre o vacío>","diseno":"<clasico|oceano|neon|fuego, el más apropiado>","tamanio":<10-20, default 15>,"instrucciones":"<instrucciones de diseño del usuario, o vacío si no dio>","checkout":false}}

REGLAS:
- Si el usuario NO dio instrucciones de diseño, invocá igual con instrucciones vacío — el sistema se basará en el tema.
- Si el usuario responde solo el tema sin instrucciones, es válido — invocá con instrucciones vacío.
- NO inventes instrucciones si el usuario no las dio. Solo transcribí textualmente lo que el usuario pidió.
- "diseno" es un hint auxiliar; las instrucciones tienen prioridad total para el diseño visual.

HERRAMIENTA: CHECKOUT (interna, nunca invocar manualmente)
- Esta herramienta es invocada automáticamente por el sistema cuando una herramienta tiene checkout:true.
- Nunca invoques checkout directamente. El sistema lo maneja.`
    }]
  };

  try {
    const geminiRes = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${geminiModel}:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          system_instruction: systemInstruction,
          contents: geminiContents,
          generationConfig: {
            temperature:     0.7,
            maxOutputTokens: 1024,
            topP:            0.9,
          },
          safetySettings: [
            { category: 'HARM_CATEGORY_HARASSMENT',        threshold: 'BLOCK_MEDIUM_AND_ABOVE' },
            { category: 'HARM_CATEGORY_HATE_SPEECH',       threshold: 'BLOCK_MEDIUM_AND_ABOVE' },
            { category: 'HARM_CATEGORY_SEXUALLY_EXPLICIT', threshold: 'BLOCK_MEDIUM_AND_ABOVE' },
            { category: 'HARM_CATEGORY_DANGEROUS_CONTENT', threshold: 'BLOCK_MEDIUM_AND_ABOVE' },
          ]
        })
      }
    );

    const geminiData = await geminiRes.json();

    if (!geminiRes.ok) {
      const errMsg = geminiData?.error?.message || 'Error de Gemini API';
      console.error('Gemini API error:', errMsg);
      return res.status(502).json({ error: errMsg });
    }

    const candidate = geminiData?.candidates?.[0];
    if (!candidate) return res.status(502).json({ error: 'Sin respuesta de Gemini' });

    // Check finish reason
    if (candidate.finishReason === 'SAFETY') {
      return res.json({ reply: 'No puedo responder esa consulta por razones de seguridad.' });
    }

    let reply = candidate?.content?.parts?.[0]?.text || '';
    if (!reply) return res.status(502).json({ error: 'Respuesta vacía de Gemini' });

    // Detect tool call JSON: match outermost {...} that contains "tool":
    let toolCall = null;
    // Strip markdown fences first
    const cleanReply = reply.replace(/```json|```/g, '').trim();
    // Find JSON blob with "tool" key
    const toolJsonMatch = cleanReply.match(/\{\s*"tool"\s*:/);
    if (toolJsonMatch) {
      // Extract full balanced JSON
      const start = cleanReply.indexOf(toolJsonMatch[0]);
      let depth = 0, end = start;
      for (let i = start; i < cleanReply.length; i++) {
        if (cleanReply[i] === '{') depth++;
        else if (cleanReply[i] === '}') { depth--; if (depth === 0) { end = i; break; } }
      }
      const jsonStr = cleanReply.substring(start, end + 1);
      try {
        toolCall = JSON.parse(jsonStr);
        reply = ''; // suppress raw JSON from showing in chat
      } catch(_) { toolCall = null; }
    }

    return res.json({
      success: true,
      reply,
      model:   geminiModel,
      modelId,
      toolCall,
    });

  } catch (err) {
    console.error('Error en /ocean-ai/chat:', err);
    return res.status(500).json({ error: 'Error interno al llamar a Gemini' });
  }
});


// ── Ocean AI: Herramienta Tiburon 1 — Generador de Sopa de Letras ────────────
app.post('/ocean-ai/tools/sopa-letras', async (req, res) => {
  const username      = String(req.body?.username      || '').trim();
  const password      = String(req.body?.password      || '').trim();
  const tema          = String(req.body?.tema          || '').trim();
  const nombre        = String(req.body?.nombre        || '').trim();
  const diseno        = String(req.body?.diseno        || 'clasico').trim();
  const tamanio       = parseInt(req.body?.tamanio || 15);
  const instrucciones = String(req.body?.instrucciones || '').trim(); // User design instructions
  // Allow reduced cost for regeneration (editor regen = 25 CB)
  const clientCost = parseInt(req.body?.coralBitsCost || 0);
  const SOPA_COST = (clientCost >= 10 && clientCost <= 75) ? clientCost : 75;

  if (!tema) return res.status(400).json({ error: 'Tema requerido' });

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return res.status(500).json({ error: 'Gemini API key no configurada' });

  if (username && password) {
    const client = await pool.connect();
    try {
      const user = await resolveOceanPayUserByCredentials(client, username, password);
      if (!user) return res.status(401).json({ error: 'Credenciales inválidas' });
      const card = await getPrimaryCardWithBalances(client, user.id);
      if (!card) return res.status(400).json({ error: 'Sin tarjeta Ocean Pay activa' });
      const currentCoral = await getUnifiedCardCurrencyBalance(client, Number(card.id), 'coralbits', true);
      if (currentCoral < SOPA_COST) {
        return res.status(402).json({ error: `Coral Bits insuficientes. Necesitás ${SOPA_COST} CB, tenés ${currentCoral} CB.`, required: SOPA_COST, balance: currentCoral });
      }
      await setUnifiedCardCurrencyBalance(client, { userId: user.id, cardId: Number(card.id), currency: 'coralbits', newBalance: currentCoral - SOPA_COST });
    } finally { client.release(); }
  }

  const gridSize = Math.min(20, Math.max(10, isNaN(tamanio) ? 15 : tamanio));

  // Helper: build balanced JSON extractor
  function extractBalancedJson(text) {
    const clean = text.replace(/```json|```/g, '').trim();
    const start = clean.search(/\{/);
    if (start === -1) return null;
    let depth = 0, end = start;
    for (let i = start; i < clean.length; i++) {
      if (clean[i] === '{') depth++;
      else if (clean[i] === '}') { depth--; if (depth === 0) { end = i; break; } }
    }
    if (depth !== 0) return null;
    try { return JSON.parse(clean.substring(start, end + 1)); }
    catch(_) { return null; }
  }

  // Helper: build fallback sopa locally if AI fails
  function buildFallbackSopa(tema, nombre, gridSz) {
    const defaultWords = ['LETRA','GRILLA','JUEGO','BUSCAR','PALABRA','TEMA','OCEAN','WILD','SOPA','TEXTO'];
    const sz = gridSz;
    // Simple grid filled with random letters + words placed horizontally
    const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const grilla = Array.from({length: sz}, () =>
      Array.from({length: sz}, () => letters[Math.floor(Math.random() * letters.length)])
    );
    const posiciones = {};
    defaultWords.slice(0, Math.min(defaultWords.length, sz)).forEach((w, i) => {
      const row = i;
      for (let c = 0; c < w.length && c < sz; c++) {
        grilla[row][c] = w[c];
      }
      posiciones[w] = { fila: row, col: 0, dir: 'H' };
    });
    return { titulo: nombre || tema, tema, palabras: defaultWords, grilla, posiciones };
  }

  const buildPrompt = (sz) => `Genera una sopa de letras en JSON. Responde SOLO con JSON puro, sin ningún texto antes ni después, sin backticks, sin explicaciones.

Tema: ${tema}
Palabras: elige exactamente 8 palabras en MAYUSCULAS sin tildes relacionadas al tema.
Grilla: ${sz}x${sz} letras mayusculas. Coloca las palabras en la grilla (H=horizontal, V=vertical, D=diagonal). Rellena el resto con letras aleatorias.

Formato EXACTO (no cambies los nombres de las claves):
{"titulo":"${nombre||tema}","tema":"${tema}","palabras":["P1","P2","P3","P4","P5","P6","P7","P8"],"grilla":[["A","B","C","D","E","F","G","H","I","J"],["K","L","M","N","O","P","Q","R","S","T"],...],"posiciones":{"P1":{"fila":0,"col":0,"dir":"H"},"P2":{"fila":1,"col":0,"dir":"H"}}}

Reglas:
- "grilla" es un array de ${sz} arrays, cada uno con ${sz} strings de 1 letra mayuscula.
- "posiciones" tiene una clave por cada palabra con fila, col (inicio) y dir (H/V/D).
- Devuelve SOLO el JSON, comenzando con { y terminando con }.`;

  async function callGeminiForSopa(prompt) {
    const r = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ role: 'user', parts: [{ text: prompt }] }],
          generationConfig: { temperature: 0.2, maxOutputTokens: 8192, topP: 0.8, responseMimeType: 'application/json' }
        })
      }
    );
    const d = await r.json();
    if (!r.ok) throw new Error(d?.error?.message || 'Gemini error');
    return d?.candidates?.[0]?.content?.parts?.[0]?.text || '';
  }

  // ── SVG Design generation ──────────────────────────────────────────────────
  // Gemini generates: (1) A complete SVG decoration layer for fondo+marco+header+wordband+footer
  // (2) A compact JSON config for grid cell colors (not drawable in SVG easily)
  const CANVAS_W = 560; // must match frontend layout
  const CANVAS_H_ESTIMATE = 980;

  const buildSvgDesignPrompt = (W, H) => {
    const hasInstrucciones = instrucciones.length > 0;
    const designDirective = hasInstrucciones
      ? `INSTRUCCIONES DE DISEÑO DEL USUARIO (PRIORIDAD MÁXIMA, seguir al pie de la letra):
"${instrucciones}"
Cada detalle de estas instrucciones debe reflejarse fielmente en el SVG.`
      : `Sin instrucciones específicas del usuario. Creá un diseño ORIGINAL basado en el tema: "${tema}".
Analizá el tema profundamente:
- ¿Qué paleta de colores lo evoca?
- ¿Qué textura de fondo encaja (madera, pergamino, pizarrón, agua, espacio, fuego)?
- ¿Qué paths SVG representan elementos ICÓNICOS del tema?
EJEMPLOS ESPERADOS POR TEMA:
  • Música/Instrumentos: pentagramas, notas con paths detallados, siluetas de instrumentos, colores madera/pergamino
  • Océano: olas curvas, peces con paths, burbujas, degradados azul profundo
  • Videojuegos: píxeles, controladores con paths, neón, scanlines
  • Naturaleza: hojas curvas, flores, verdes vibrantes
  • Espacio: estrellas, planetas con gradientes radiales, cohetes, negro profundo`;

    return `Sos un diseñador gráfico SVG senior especializado en carteles ilustrados y pósters impresos de alta calidad. Tu trabajo se diferencia por la RIQUEZA DE DETALLE y la COHERENCIA TEMÁTICA.

TEMA: "${tema}"
TÍTULO DEL PÓSTER: "${nombre || tema}"

${designDirective}

ESPECIFICACIONES TÉCNICAS:
- viewBox="0 0 ${W} ${H}" width="${W}" height="${H}"
- SVG autocontenido: sin <image>, sin @font-face, sin dependencias externas
- Usá <defs> con múltiples gradientes, filters y patterns

ZONAS DEL PÓSTER (obligatorias):
A (y 0-220): Fondo + Marco + Header con título y decoraciones
B (y 220-265): Banda ornamental de transición
C (y 265-670): Área de grilla — dibujá SOLO el contenedor de papel: rect x="28" y="268" width="${W-56}" height="400" con fill tipo papel y borde decorativo. SIN texto ni letras adentro.
D (y 670-900): Banda inferior temática para palabras (fondo oscuro, sin texto)
E (y 900-${H}): Footer — franja sólida de color

ELEMENTOS OBLIGATORIOS:
1. FONDO: gradiente completo o pattern de textura que cubra todo el SVG
2. MARCO: rect exterior stroke + esquinas ornamentadas con paths (NO simples cuadrados), strokeWidth mínimo 10
3. TÍTULO: text SVG centrado en Zona A, font-weight="bold".
   REGLA DE TAMAÑO: título corto (hasta 15 chars) → font-size="48". Medio (16-22) → font-size="36". Largo (23+) → font-size="28". NUNCA omitir este ajuste.
   Aplicá filter drop-shadow. El texto DEBE caber dentro de x=30 a x=${W-30}.
4. BADGE "SOPA DE LETRAS:" sobre el título: rect redondeado rx="5" + text font-size="13"
5. ELEMENTOS DECORATIVOS TEMÁTICOS (mínimo 8 elementos en total):
   - Header (Zona A): al menos 3 elementos (ej: 2 decorativos a los lados del título + 1 patrón de fondo)
   - Lados Zona C: al menos 2 elementos verticales flanqueando el área de grilla
   - Zona D: al menos 2 elementos en esquinas inferiores
   - Footer: al menos 1 elemento decorativo
   CALIDAD MÍNIMA: cada elemento debe tener al menos 1 atributo de estilo (fill, stroke, opacity, transform)
6. LÍNEAS ORNAMENTALES en Zona B: múltiples <line> con strokeDasharray distintos
7. El rect de grilla (Zona C) debe tener fill="#fdf8ee" o color papel similar, stroke temático, rx="8"

CALIDAD EXIGIDA:
- Paleta coherente de 4-6 colores que reflejen el tema
- Elementos decorativos con DETALLE real (paths curvos, formas complejas, no solo rectángulos)
- Uso de opacity para capas de profundidad
- Diseño que se vea PROFESIONAL, publicable

RESPUESTA: SOLO JSON sin backticks:
{"svg":"<svg ...>...</svg>","grid":{"gridBg":"#hex","gridLine":"#hex","gridBorder":"#hex","cellNormal":"#hex","cellFoundBg":"#hex","cellFoundTxt":"#hex","cellFoundGlow":"#hex","wordText":"#hex","wordFoundText":"#hex","footerText":"#hex","footerAccent":"#hex"}}`;
  };

  async function callGeminiForSvgDesign(prompt) {
    const r = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ role: 'user', parts: [{ text: prompt }] }],
          generationConfig: { temperature: 0.9, maxOutputTokens: 8192, topP: 0.95 }
        })
      }
    );
    const d = await r.json();
    if (!r.ok) throw new Error(d?.error?.message || 'Gemini SVG design error');
    return d?.candidates?.[0]?.content?.parts?.[0]?.text || '';
  }

  // ── Default design fallback (config-only, no SVG) ─────────────────────────
  function buildDefaultDesign(tema) {
    const t = tema.toLowerCase();
    if (t.match(/mar|ocean|agua|pez|coral|buzo|barco|ballena|tiburon/))
      return { svg:null, grid:{ gridBg:'#011627', gridLine:'#0e3d5c', gridBorder:'#00b4d8', cellNormal:'#caf0f8', cellFoundBg:'#00b4d8', cellFoundTxt:'#001e3c', cellFoundGlow:'#48cae4', wordText:'#caf0f8', wordFoundText:'#48cae4', footerText:'#90e0ef', footerAccent:'#00b4d8' }, bgTop:'#001e3c', bgMid:'#003366', bgBottom:'#001e3c', framePrimary:'#00b4d8', frameSecondary:'#90e0ef', titleMainColor:'#caf0f8', titleShadow:'#000d1a', subtitleColor:'#90e0ef', decoEmojis:['🌊','🐠','🐋','🦈'], wordBg1:'#012233', wordBg2:'#011627', wordBorder:'#00b4d8', footerBg:'#010e1a' };
    if (t.match(/fuego|dragon|lava|volcan|deporte|futbol|basket|tenis|combate/))
      return { svg:null, grid:{ gridBg:'#fffaf5', gridLine:'#f0d4b0', gridBorder:'#f97316', cellNormal:'#431407', cellFoundBg:'#f97316', cellFoundTxt:'#ffffff', cellFoundGlow:'#fbbf24', wordText:'#fed7aa', wordFoundText:'#fbbf24', footerText:'#c2410c', footerAccent:'#fbbf24' }, bgTop:'#3d0c00', bgMid:'#5c1500', bgBottom:'#3d0c00', framePrimary:'#f97316', frameSecondary:'#fbbf24', titleMainColor:'#fed7aa', titleShadow:'#1a0400', subtitleColor:'#fb923c', decoEmojis:['🔥','⚡','🏆','⭐'], wordBg1:'#7c2d12', wordBg2:'#431407', wordBorder:'#f97316', footerBg:'#200500' };
    if (t.match(/tecnolog|comput|robot|digital|cyber|hack/))
      return { svg:null, grid:{ gridBg:'#030308', gridLine:'#00ff8820', gridBorder:'#00ff88', cellNormal:'#aaffcc', cellFoundBg:'#00ff88', cellFoundTxt:'#020206', cellFoundGlow:'#00ff88', wordText:'#aaffcc', wordFoundText:'#00ff88', footerText:'#00cc66', footerAccent:'#00ff88' }, bgTop:'#020206', bgMid:'#040410', bgBottom:'#020206', framePrimary:'#00ff88', frameSecondary:'#00cc66', titleMainColor:'#00ff88', titleShadow:'#001a0a', subtitleColor:'#00cc66', decoEmojis:['💻','🤖','⚡','🔐'], wordBg1:'#030308', wordBg2:'#020206', wordBorder:'#00ff88', footerBg:'#010103' };
    return { svg:null, grid:{ gridBg:'#fdfbf4', gridLine:'#d4c9a8', gridBorder:'#1e3a6e', cellNormal:'#1a202c', cellFoundBg:'#1e3a6e', cellFoundTxt:'#ffffff', cellFoundGlow:'#3b82f6', wordText:'#ffffff', wordFoundText:'#93c5fd', footerText:'#93c5fd', footerAccent:'#c8a84b' }, bgTop:'#1e3a6e', bgMid:'#2c5282', bgBottom:'#1e3a6e', framePrimary:'#1e3a6e', frameSecondary:'#c8a84b', titleMainColor:'#ffffff', titleShadow:'#0a1d40', subtitleColor:'#93c5fd', decoEmojis:['📚','✏️','📖','🔤'], wordBg1:'#1e3a6e', wordBg2:'#162d56', wordBorder:'#c8a84b', footerBg:'#0f1f40' };
  }

  try {
    let sopaData = null;
    let designData = null;
    let lastErr = '';

    // Run sopa and design generation in parallel
    const [sopaResult, designResult] = await Promise.allSettled([
      // ── Sopa generation ──
      (async () => {
        let data = null;
        try {
          const raw1 = await callGeminiForSopa(buildPrompt(gridSize));
          data = extractBalancedJson(raw1);
          if (!data?.grilla || !data?.palabras) { data = null; }
        } catch(_) { data = null; }
        if (!data) {
          try {
            const raw2 = await callGeminiForSopa(buildPrompt(10));
            data = extractBalancedJson(raw2);
            if (!data?.grilla || !data?.palabras) data = null;
          } catch(_) { data = null; }
        }
        return data || buildFallbackSopa(tema, nombre, 10);
      })(),
      // ── SVG Design generation ──
      (async () => {
        try {
          const rawD = await callGeminiForSvgDesign(buildSvgDesignPrompt(CANVAS_W, CANVAS_H_ESTIMATE));
          // Extract JSON — may be wrapped in backticks
          const clean = rawD.replace(/```json|```/g,'').trim();
          // Find outermost { }
          const si = clean.indexOf('{'), ei = clean.lastIndexOf('}');
          if (si === -1 || ei === -1) throw new Error('No JSON found');
          const parsed = JSON.parse(clean.substring(si, ei+1));
          // Validate SVG
          if (parsed.svg && parsed.svg.includes('<svg') && parsed.grid && parsed.grid.gridBg) {
            // Sanitize SVG: remove any script tags for safety
            parsed.svg = parsed.svg.replace(/<script[\s\S]*?<\/script>/gi,'').replace(/on\w+="[^"]*"/gi,'');
            return parsed;
          }
          throw new Error('Invalid SVG design response');
        } catch(e) {
          console.warn('SVG design fallback:', e.message);
        }
        return buildDefaultDesign(tema);
      })()
    ]);

    sopaData  = sopaResult.status === 'fulfilled'  ? sopaResult.value  : buildFallbackSopa(tema, nombre, 10);
    designData = designResult.status === 'fulfilled' ? designResult.value : buildDefaultDesign(tema);

    // Ensure design has grid config at minimum
    if (!designData || (!designData.grid && !designData.gridBg)) designData = buildDefaultDesign(tema);
    // Normalize: if grid sub-object exists, also promote keys to top level for canvas compat
    if (designData.grid) {
      Object.assign(designData, designData.grid);
    }

    return res.json({ success: true, sopa: sopaData, design: designData, coralBitsCost: SOPA_COST });
  } catch(err) {
    console.error('Error en /ocean-ai/tools/sopa-letras:', err);
    return res.status(500).json({ error: 'Error interno al generar la sopa de letras' });
  }
});



// Colaboraciones - solicitudes
app.get('/wildwave/api/collabs/requests', async (req, res) => {
  try {
    await ensureWildXTables();
    await ensureWildXExtraColumns();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesiï¿½n en WildWave' });

    const { rows } = await pool.query(
      `SELECT pc.id,
              pc.post_id,
              pc.created_at,
              p.content,
              p.images,
              p.created_at AS post_created_at,
              u.username AS author_username,
              COALESCE(u.display_name, u.username) AS author_display_name,
              u.avatar_url AS author_avatar
         FROM wildx_post_collaborators pc
         JOIN wildx_posts p ON p.id = pc.post_id
         JOIN wildx_users u ON u.id = pc.requested_by
        WHERE pc.collaborator_id = $1
          AND pc.status = 'pending'
          AND p.deleted_at IS NULL
        ORDER BY pc.created_at DESC`,
      [wid]
    );
    res.json(rows);
  } catch (err) {
    console.error('Error en GET /wildwave/api/collabs/requests:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/wildwave/api/collabs/requests/:id/accept', async (req, res) => {
  const client = await pool.connect();
  try {
    await ensureWildXTables();
    await ensureWildXExtraColumns();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesiï¿½n en WildWave' });

    const collabId = parseInt(req.params.id, 10);
    if (!collabId) return res.status(400).json({ error: 'Solicitud invï¿½lida' });

    await client.query('BEGIN');
    const { rows: collabRows } = await client.query(
      'SELECT id, post_id, collaborator_id, status, requested_by FROM wildx_post_collaborators WHERE id=$1 FOR UPDATE',
      [collabId]
    );
    if (!collabRows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Solicitud no encontrada' });
    }
    const collab = collabRows[0];
    if (Number(collab.collaborator_id) !== Number(wid)) {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: 'No autorizado' });
    }
    if (collab.status !== 'pending') {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Solicitud ya resuelta' });
    }

    await client.query(
      "UPDATE wildx_post_collaborators SET status = 'accepted', responded_at = NOW() WHERE id = $1",
      [collabId]
    );

    const { rows: countRows } = await client.query(
      "SELECT COUNT(*) FILTER (WHERE status = 'pending')::int AS pending_count, COUNT(*) FILTER (WHERE status = 'accepted')::int AS accepted_count FROM wildx_post_collaborators WHERE post_id = $1",
      [collab.post_id]
    );
    const pendingCount = countRows[0]?.pending_count || 0;
    const acceptedCount = countRows[0]?.accepted_count || 0;
    let postStatus = 'pending_collab';
    if (pendingCount === 0) {
      if (acceptedCount > 0) {
        await client.query("UPDATE wildx_posts SET status = 'published' WHERE id = $1", [collab.post_id]);
        postStatus = 'published';
      } else {
        await client.query("UPDATE wildx_posts SET status = 'pending_author' WHERE id = $1", [collab.post_id]);
        postStatus = 'pending_author';
      }
    }

    await client.query('COMMIT');

    const { rows: meRows } = await pool.query('SELECT username FROM wildx_users WHERE id=$1', [wid]);
    const byUsername = meRows[0]?.username || null;
    if (collab.requested_by) {
      createWildXNotification(collab.requested_by, 'collab_accepted', {
        post_id: collab.post_id,
        by_username: byUsername
      }).catch(() => {});
    }

    res.json({ success: true, post_id: collab.post_id, post_status: postStatus });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error en POST /wildwave/api/collabs/requests/:id/accept:', err);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

app.post('/wildwave/api/collabs/requests/:id/decline', async (req, res) => {
  const client = await pool.connect();
  try {
    await ensureWildXTables();
    await ensureWildXExtraColumns();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesiï¿½n en WildWave' });

    const collabId = parseInt(req.params.id, 10);
    if (!collabId) return res.status(400).json({ error: 'Solicitud invï¿½lida' });

    await client.query('BEGIN');
    const { rows: collabRows } = await client.query(
      'SELECT id, post_id, collaborator_id, status, requested_by FROM wildx_post_collaborators WHERE id=$1 FOR UPDATE',
      [collabId]
    );
    if (!collabRows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Solicitud no encontrada' });
    }
    const collab = collabRows[0];
    if (Number(collab.collaborator_id) !== Number(wid)) {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: 'No autorizado' });
    }
    if (collab.status !== 'pending') {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Solicitud ya resuelta' });
    }

    await client.query(
      "UPDATE wildx_post_collaborators SET status = 'declined', responded_at = NOW() WHERE id = $1",
      [collabId]
    );

    const { rows: countRows } = await client.query(
      "SELECT COUNT(*) FILTER (WHERE status = 'pending')::int AS pending_count, COUNT(*) FILTER (WHERE status = 'accepted')::int AS accepted_count FROM wildx_post_collaborators WHERE post_id = $1",
      [collab.post_id]
    );
    const pendingCount = countRows[0]?.pending_count || 0;
    const acceptedCount = countRows[0]?.accepted_count || 0;
    let postStatus = 'pending_collab';
    let needsDecision = false;
    if (pendingCount === 0 && acceptedCount === 0) {
      await client.query("UPDATE wildx_posts SET status = 'pending_author' WHERE id = $1", [collab.post_id]);
      postStatus = 'pending_author';
      needsDecision = true;
    }

    await client.query('COMMIT');

    if (needsDecision && collab.requested_by) {
      createWildXNotification(collab.requested_by, 'collab_declined_final', {
        post_id: collab.post_id
      }).catch(() => {});
    }

    res.json({ success: true, post_id: collab.post_id, post_status: postStatus, needs_decision: needsDecision });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error en POST /wildwave/api/collabs/requests/:id/decline:', err);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

app.get('/wildwave/api/collabs/outgoing', async (req, res) => {
  try {
    await ensureWildXTables();
    await ensureWildXExtraColumns();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesiï¿½n en WildWave' });

    const { rows } = await pool.query(
      `SELECT p.id,
              p.content,
              p.images,
              p.created_at,
              p.status,
              COALESCE(
                json_agg(
                  json_build_object(
                    'id', pc.id,
                    'username', u.username,
                    'display_name', COALESCE(u.display_name, u.username),
                    'avatar_url', u.avatar_url,
                    'status', pc.status
                  ) ORDER BY u.username
                ) FILTER (WHERE pc.id IS NOT NULL),
                '[]'::json
              ) AS collaborators,
              COUNT(*) FILTER (WHERE pc.status = 'pending')::int AS pending_count,
              COUNT(*) FILTER (WHERE pc.status = 'accepted')::int AS accepted_count,
              COUNT(*) FILTER (WHERE pc.status = 'declined')::int AS declined_count
         FROM wildx_posts p
         LEFT JOIN wildx_post_collaborators pc ON pc.post_id = p.id
         LEFT JOIN wildx_users u ON u.id = pc.collaborator_id
        WHERE p.user_id = $1
          AND p.status IN ('pending_collab', 'pending_author')
          AND p.deleted_at IS NULL
        GROUP BY p.id
        ORDER BY p.created_at DESC`,
      [wid]
    );
    res.json(rows);
  } catch (err) {
    console.error('Error en GET /wildwave/api/collabs/outgoing:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/wildwave/api/collabs/posts/:id/publish', async (req, res) => {
  try {
    await ensureWildXTables();
    await ensureWildXExtraColumns();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesiï¿½n en WildWave' });

    const postId = parseInt(req.params.id, 10);
    if (!postId) return res.status(400).json({ error: 'Post invï¿½lido' });

    const { rows: postRows } = await pool.query('SELECT user_id, status FROM wildx_posts WHERE id=$1', [postId]);
    if (!postRows.length) return res.status(404).json({ error: 'Post no encontrado' });
    if (Number(postRows[0].user_id) !== Number(wid)) {
      return res.status(403).json({ error: 'No autorizado' });
    }

    const { rows: countRows } = await pool.query(
      "SELECT COUNT(*) FILTER (WHERE status = 'pending')::int AS pending_count FROM wildx_post_collaborators WHERE post_id = $1",
      [postId]
    );
    const pendingCount = countRows[0]?.pending_count || 0;
    if (pendingCount > 0) {
      return res.status(409).json({ error: 'Aï¿½n hay colaboradores pendientes' });
    }

    await pool.query("UPDATE wildx_posts SET status = 'published' WHERE id = $1", [postId]);
    res.json({ success: true, post_id: postId });
  } catch (err) {
    console.error('Error en POST /wildwave/api/collabs/posts/:id/publish:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});
// Toggle like en un post WildX


// ══════════════════════════════════════════════════════════════════════════
// WildWave — PROCESOS
// ══════════════════════════════════════════════════════════════════════════

// GET mis procesos
app.get('/wildwave/api/processes', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Token requerido' });
    const { rows: procs } = await pool.query(
      `SELECT id, title, description, status, created_at, updated_at
         FROM wildx_processes WHERE user_id = $1
        ORDER BY created_at DESC`,
      [wid]
    );
    const result = await Promise.all(procs.map(p => getProcessWithSteps(p.id)));
    res.json(result.filter(Boolean));
  } catch (err) {
    console.error('GET /wildwave/api/processes:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// GET procesos de un usuario (para perfil público)
app.get('/wildwave/api/processes/user/:username', async (req, res) => {
  try {
    await ensureWildXTables();
    const { username } = req.params;
    const { rows: users } = await pool.query(
      'SELECT id FROM wildx_users WHERE LOWER(username) = LOWER($1)',
      [username]
    );
    if (!users.length) return res.status(404).json({ error: 'Usuario no encontrado' });
    const uid = users[0].id;
    const { rows: procs } = await pool.query(
      `SELECT id FROM wildx_processes WHERE user_id = $1 AND status = 'active'
        ORDER BY created_at DESC`,
      [uid]
    );
    const result = await Promise.all(procs.map(p => getProcessWithSteps(p.id)));
    res.json(result.filter(Boolean));
  } catch (err) {
    res.status(500).json({ error: 'Error interno' });
  }
});

// POST crear proceso
app.post('/wildwave/api/processes', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Token requerido' });
    const title = (req.body?.title || '').toString().trim();
    const description = (req.body?.description || '').toString().trim();
    if (!title) return res.status(400).json({ error: 'Título requerido' });
    if (title.length > 120) return res.status(400).json({ error: 'Título máximo 120 caracteres' });
    const { rows } = await pool.query(
      `INSERT INTO wildx_processes (user_id, title, description)
       VALUES ($1, $2, $3)
       RETURNING id, user_id, title, description, status, created_at, updated_at`,
      [wid, title, description || null]
    );
    const proc = { ...rows[0], steps: [], total_steps: 0, completed_steps: 0 };
    await emitProcessUpdate(wid, 'process:created', { process: proc });
    res.json(proc);
  } catch (err) {
    console.error('POST /wildwave/api/processes:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// PATCH editar proceso
app.patch('/wildwave/api/processes/:id', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Token requerido' });
    const procId = parseInt(req.params.id, 10);
    const { rows: own } = await pool.query(
      'SELECT id FROM wildx_processes WHERE id = $1 AND user_id = $2',
      [procId, wid]
    );
    if (!own.length) return res.status(404).json({ error: 'Proceso no encontrado' });
    const title       = req.body?.title !== undefined ? (req.body.title || '').toString().trim() : undefined;
    const description = req.body?.description !== undefined ? (req.body.description || '').toString().trim() : undefined;
    const status      = req.body?.status !== undefined ? req.body.status : undefined;
    if (title !== undefined && !title) return res.status(400).json({ error: 'Título requerido' });
    const setParts = ['updated_at = NOW()'];
    const vals = [];
    let idx = 1;
    if (title !== undefined)       { setParts.push(`title = $${idx++}`);       vals.push(title); }
    if (description !== undefined) { setParts.push(`description = $${idx++}`); vals.push(description || null); }
    if (status !== undefined)      { setParts.push(`status = $${idx++}`);      vals.push(status); }
    vals.push(procId);
    await pool.query(`UPDATE wildx_processes SET ${setParts.join(', ')} WHERE id = $${idx}`, vals);
    const proc = await getProcessWithSteps(procId);
    await emitProcessUpdate(wid, 'process:updated', { process: proc });
    res.json(proc);
  } catch (err) {
    console.error('PATCH /wildwave/api/processes/:id:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// DELETE proceso
app.delete('/wildwave/api/processes/:id', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Token requerido' });
    const procId = parseInt(req.params.id, 10);
    const { rows } = await pool.query(
      'DELETE FROM wildx_processes WHERE id = $1 AND user_id = $2 RETURNING id',
      [procId, wid]
    );
    if (!rows.length) return res.status(404).json({ error: 'Proceso no encontrado' });
    await emitProcessUpdate(wid, 'process:deleted', { processId: procId });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Error interno' });
  }
});

// POST añadir paso
app.post('/wildwave/api/processes/:id/steps', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Token requerido' });
    const procId = parseInt(req.params.id, 10);
    const { rows: own } = await pool.query(
      'SELECT id FROM wildx_processes WHERE id = $1 AND user_id = $2',
      [procId, wid]
    );
    if (!own.length) return res.status(404).json({ error: 'Proceso no encontrado' });
    const title    = (req.body?.title || '').toString().trim();
    const parentId = req.body?.parent_id ? parseInt(req.body.parent_id, 10) : null;
    if (!title) return res.status(400).json({ error: 'Título del paso requerido' });
    if (title.length > 160) return res.status(400).json({ error: 'Título máximo 160 caracteres' });
    // Calculate position
    const { rows: posRows } = await pool.query(
      'SELECT COALESCE(MAX(position), -1) + 1 AS next_pos FROM wildx_process_steps WHERE process_id = $1 AND parent_id IS NOT DISTINCT FROM $2',
      [procId, parentId]
    );
    const position = posRows[0]?.next_pos ?? 0;
    const { rows } = await pool.query(
      `INSERT INTO wildx_process_steps (process_id, parent_id, title, position)
       VALUES ($1, $2, $3, $4)
       RETURNING id, process_id, parent_id, title, done, position, created_at, updated_at`,
      [procId, parentId, title, position]
    );
    const proc = await getProcessWithSteps(procId);
    await emitProcessUpdate(wid, 'process:updated', { process: proc });
    res.json(rows[0]);
  } catch (err) {
    console.error('POST /wildwave/api/processes/:id/steps:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// PATCH editar paso (título o done)
app.patch('/wildwave/api/processes/:id/steps/:stepId', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Token requerido' });
    const procId  = parseInt(req.params.id, 10);
    const stepId  = parseInt(req.params.stepId, 10);
    const { rows: own } = await pool.query(
      'SELECT id FROM wildx_processes WHERE id = $1 AND user_id = $2',
      [procId, wid]
    );
    if (!own.length) return res.status(404).json({ error: 'Proceso no encontrado' });
    const setParts = ['updated_at = NOW()'];
    const vals = [];
    let idx = 1;
    if (req.body?.title !== undefined) {
      const t = (req.body.title || '').toString().trim();
      if (!t) return res.status(400).json({ error: 'Título requerido' });
      setParts.push(`title = $${idx++}`); vals.push(t);
    }
    if (req.body?.done !== undefined) {
      setParts.push(`done = $${idx++}`); vals.push(!!req.body.done);
    }
    if (vals.length === 0) return res.status(400).json({ error: 'Nada que actualizar' });
    vals.push(stepId, procId);
    await pool.query(
      `UPDATE wildx_process_steps SET ${setParts.join(', ')} WHERE id = $${idx} AND process_id = $${idx+1}`,
      vals
    );
    // Update process updated_at
    await pool.query('UPDATE wildx_processes SET updated_at = NOW() WHERE id = $1', [procId]);
    const proc = await getProcessWithSteps(procId);
    await emitProcessUpdate(wid, 'process:updated', { process: proc });
    res.json({ success: true, process: proc });
  } catch (err) {
    console.error('PATCH .../steps/:stepId:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// DELETE paso
app.delete('/wildwave/api/processes/:id/steps/:stepId', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Token requerido' });
    const procId = parseInt(req.params.id, 10);
    const stepId = parseInt(req.params.stepId, 10);
    const { rows: own } = await pool.query(
      'SELECT id FROM wildx_processes WHERE id = $1 AND user_id = $2',
      [procId, wid]
    );
    if (!own.length) return res.status(404).json({ error: 'Proceso no encontrado' });
    await pool.query(
      'DELETE FROM wildx_process_steps WHERE id = $1 AND process_id = $2',
      [stepId, procId]
    );
    await pool.query('UPDATE wildx_processes SET updated_at = NOW() WHERE id = $1', [procId]);
    const proc = await getProcessWithSteps(procId);
    await emitProcessUpdate(wid, 'process:updated', { process: proc });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Error interno' });
  }
});

// ── Votar en una encuesta ─────────────────────────────────────────────────
app.post('/wildwave/api/polls/:id/vote', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesión para votar' });
    const pollId = parseInt(req.params.id, 10);
    const optionIdx = parseInt(req.body?.option_idx, 10);
    if (isNaN(pollId) || isNaN(optionIdx) || optionIdx < 0) {
      return res.status(400).json({ error: 'Datos de voto inválidos' });
    }
    // Get poll
    const { rows: pollRows } = await pool.query(
      'SELECT id, options, ends_at FROM wildx_polls WHERE id = $1',
      [pollId]
    );
    if (!pollRows.length) return res.status(404).json({ error: 'Encuesta no encontrada' });
    const poll = pollRows[0];
    const options = Array.isArray(poll.options) ? poll.options : [];
    if (optionIdx >= options.length) {
      return res.status(400).json({ error: 'Opción inválida' });
    }
    if (poll.ends_at && new Date(poll.ends_at) < new Date()) {
      return res.status(400).json({ error: 'La encuesta ha cerrado' });
    }
    // Upsert vote (allow changing vote)
    await pool.query(
      `INSERT INTO wildx_poll_votes (poll_id, user_id, option_idx)
       VALUES ($1, $2, $3)
       ON CONFLICT (poll_id, user_id) DO UPDATE SET option_idx = $3, voted_at = NOW()`,
      [pollId, wid, optionIdx]
    );
    // Return updated counts
    const { rows: countRows } = await pool.query(
      `SELECT option_idx, COUNT(*)::int AS cnt
         FROM wildx_poll_votes WHERE poll_id = $1
        GROUP BY option_idx`,
      [pollId]
    );
    const { rows: totalRows } = await pool.query(
      'SELECT COUNT(*)::int AS total FROM wildx_poll_votes WHERE poll_id = $1',
      [pollId]
    );
    const voteCounts = options.map((text, idx) => ({
      idx,
      text,
      votes: (countRows.find(r => r.option_idx === idx) || {}).cnt || 0
    }));
    res.json({
      success: true,
      my_vote: optionIdx,
      options: voteCounts,
      total_votes: totalRows[0]?.total || 0
    });
  } catch (err) {
    console.error('Error en POST /wildwave/api/polls/:id/vote:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// ── Quitar voto de una encuesta ───────────────────────────────────────────
app.delete('/wildwave/api/polls/:id/vote', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesión para votar' });
    const pollId = parseInt(req.params.id, 10);
    if (isNaN(pollId)) return res.status(400).json({ error: 'ID inválido' });
    await pool.query(
      'DELETE FROM wildx_poll_votes WHERE poll_id = $1 AND user_id = $2',
      [pollId, wid]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/wildwave/api/posts/:id/like', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesiÃƒÂ³n para dar like' });

    const postId = parseInt(req.params.id, 10);
    if (!postId) return res.status(400).json({ error: 'ID de post invÃƒÂ¡lido' });

    // No permitir dar like a tus propios posts
    const { rows: postOwnerRows } = await pool.query(
      'SELECT user_id FROM wildx_posts WHERE id=$1',
      [postId]
    );
    if (!postOwnerRows.length) {
      return res.status(404).json({ error: 'Post no encontrado' });
    }
    if (Number(postOwnerRows[0].user_id) === Number(wid)) {
      return res.status(400).json({ error: 'No puedes dar like a tus propios posts' });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const { rows: existing } = await client.query(
        'SELECT 1 FROM wildx_likes WHERE user_id=$1 AND post_id=$2',
        [wid, postId]
      );

      let liked;
      let likesCount;

      if (existing.length) {
        await client.query('DELETE FROM wildx_likes WHERE user_id=$1 AND post_id=$2', [wid, postId]);
        const { rows: upd } = await client.query(
          'UPDATE wildx_posts SET likes_count = GREATEST(likes_count - 1, 0) WHERE id=$1 RETURNING likes_count',
          [postId]
        );
        likesCount = upd[0]?.likes_count ?? 0;
        liked = false;
      } else {
        await client.query(
          'INSERT INTO wildx_likes (user_id, post_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
          [wid, postId]
        );
        const { rows: upd } = await client.query(
          'UPDATE wildx_posts SET likes_count = likes_count + 1 WHERE id=$1 RETURNING likes_count',
          [postId]
        );
        likesCount = upd[0]?.likes_count ?? 1;
        liked = true;
      }

      await client.query('COMMIT');
      res.json({ liked, likesCount });
    } catch (err) {
      await client.query('ROLLBACK');
      console.error('Error en POST /wildwave/api/posts/:id/like:', err);
      res.status(500).json({ error: 'Error interno' });
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('Error en POST /wildwave/api/posts/:id/like:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Listar notificaciones del usuario actual
app.get('/wildwave/api/notifications', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesiÃƒÂ³n en WildX' });

    const { rows } = await pool.query(
      `SELECT id, type, payload, created_at, read_at
         FROM wildx_notifications
        WHERE user_id = $1
        ORDER BY created_at DESC
        LIMIT 50`,
      [wid]
    );

    const notifications = rows.map(r => {
      let payload = {};
      try {
        payload = JSON.parse(r.payload || '{}');
      } catch {
        payload = {};
      }
      return {
        id: r.id,
        type: r.type,
        payload,
        created_at: r.created_at,
        read_at: r.read_at
      };
    });

    const unreadCount = notifications.filter(n => !n.read_at).length;

    res.json({ notifications, unreadCount });
  } catch (err) {
    console.error('Error en GET /wildwave/api/notifications:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Marcar notificaciones como leÃƒÂ­das
app.post('/wildwave/api/notifications/read', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesiÃƒÂ³n en WildX' });

    await pool.query(
      `UPDATE wildx_notifications
          SET read_at = NOW()
        WHERE user_id = $1 AND read_at IS NULL`,
      [wid]
    );

    res.json({ success: true });
  } catch (err) {
    console.error('Error en POST /wildwave/api/notifications/read:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Obtener hilo completo (post + respuestas recursivas)
app.get('/wildwave/api/posts/:id/thread', async (req, res) => {
  try {
    await ensureWildXTables();
    await ensureWildXExtraColumns();
    const wid = getWildXUserId(req) || 0;
    const postId = parseInt(req.params.id, 10);
    if (!postId) return res.status(400).json({ error: 'ID de post invÃƒÂ¡lido' });

    const { rows } = await pool.query(
      `WITH RECURSIVE thread AS (
         SELECT *
           FROM wildx_posts
          WHERE id = $1
         UNION ALL
         SELECT p.*
           FROM wildx_posts p
           JOIN thread t ON p.parent_id = t.id
       )
       SELECT t.id,
              t.user_id,
              COALESCE(u.username, t.username) AS username,
              COALESCE(u.display_name, u.username, t.username) AS display_name,
              t.content,
              t.images,
              t.video_url,
              t.created_at,
              t.parent_id,
              t.likes_count,
              u.avatar_url,
              (l.user_id IS NOT NULL) AS liked,
              CASE
                WHEN LOWER(COALESCE(u.username, t.username, '')) = $3 THEN 'admin'
                WHEN LOWER(REGEXP_REPLACE(COALESCE(u.display_name, ''), '\\s+', ' ', 'g')) = $4 THEN 'admin'
                WHEN LOWER(REGEXP_REPLACE(COALESCE(u.display_name, ''), '\\s+', '', 'g')) = $3 THEN 'admin'
                WHEN LOWER(COALESCE(op.username, '')) = $5 THEN 'admin'
                ELSE v.tier
              END AS verify_tier,
              CASE
                WHEN LOWER(COALESCE(u.username, t.username, '')) = $3 THEN 'crimson'
                WHEN LOWER(REGEXP_REPLACE(COALESCE(u.display_name, ''), '\\s+', ' ', 'g')) = $4 THEN 'crimson'
                WHEN LOWER(REGEXP_REPLACE(COALESCE(u.display_name, ''), '\\s+', '', 'g')) = $3 THEN 'crimson'
                WHEN LOWER(COALESCE(op.username, '')) = $5 THEN 'crimson'
                ELSE v.badge_color
              END AS verify_badge_color,
            collab.collaborators AS collaborators
         FROM thread t
         LEFT JOIN wildx_users u ON u.id = t.user_id
         LEFT JOIN wildx_oceanpay_links wol ON wol.wildx_user_id = t.user_id
         LEFT JOIN ocean_pay_users op ON op.id = wol.ocean_pay_user_id
         LEFT JOIN wildx_likes l
           ON l.post_id = t.id AND l.user_id = $2
         LEFT JOIN LATERAL (
           SELECT tier, badge_color
           FROM wildx_verifications
            WHERE user_id = t.user_id
              AND valid_until > NOW()
            ORDER BY started_at ASC
            LIMIT 1
        ) v ON TRUE
        LEFT JOIN LATERAL (
          SELECT COALESCE(
            json_agg(
              json_build_object(
                'id', cu.id,
                'username', cu.username,
                'display_name', COALESCE(cu.display_name, cu.username),
                'avatar_url', cu.avatar_url
              ) ORDER BY cu.username
            ),
            '[]'::json
          ) AS collaborators
            FROM wildx_post_collaborators pc
            JOIN wildx_users cu ON cu.id = pc.collaborator_id
           WHERE pc.post_id = t.id
             AND pc.status = 'accepted'
        ) collab ON TRUE
        ORDER BY t.created_at ASC`,
      [postId, wid, WILDWAVE_ADMIN_USERNAME, WILDWAVE_ADMIN_DISPLAY_NAME, WILDWAVE_ADMIN_OCEANPAY_USERNAME]
    );

    const filtered = rows.filter(r => !r.deleted_at);
    const enrichedThread = await enrichPostsWithPolls(filtered, wid);
    res.json(enrichedThread);
  } catch (err) {
    console.error('Error en GET /wildwave/api/posts/:id/thread:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Listar posts programados del usuario actual
app.get('/wildwave/api/scheduled', async (req, res) => {
  try {
    await ensureWildXTables();
    await ensureWildXExtraColumns();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesiÃƒÂ³n en WildX' });
    const { rows } = await pool.query(
      `SELECT id, user_id, username, content, images, created_at, parent_id, likes_count, scheduled_at, status
         FROM wildx_posts
        WHERE user_id = $1 AND status = 'scheduled' AND deleted_at IS NULL
        ORDER BY scheduled_at ASC NULLS LAST, created_at DESC
        LIMIT 100`,
      [wid]
    );
    res.json(rows);
  } catch (err) {
    console.error('Error en GET /wildwave/api/scheduled:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Eliminar post propio (borrado suave)
app.delete('/wildwave/api/posts/:id', async (req, res) => {
  try {
    await ensureWildXTables();
    await ensureWildXExtraColumns();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesiÃƒÂ³n en WildX' });
    const postId = parseInt(req.params.id, 10);
    if (!postId) return res.status(400).json({ error: 'ID de post invÃƒÂ¡lido' });

    const { rows } = await pool.query('SELECT user_id FROM wildx_posts WHERE id=$1', [postId]);
    if (!rows.length) return res.status(404).json({ error: 'Post no encontrado' });
    if (Number(rows[0].user_id) !== Number(wid)) {
      return res.status(403).json({ error: 'Solo puedes eliminar tus propios posts' });
    }

    await pool.query(
      `UPDATE wildx_posts
          SET deleted_at = NOW(), status = 'deleted'
        WHERE id = $1`,
      [postId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Error en DELETE /wildwave/api/posts/:id:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Reportar post (visible para admins luego)
app.post('/wildwave/api/posts/:id/report', async (req, res) => {
  try {
    await ensureWildXReportsTable();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesiÃƒÂ³n en WildX' });
    const postId = parseInt(req.params.id, 10);
    if (!postId) return res.status(400).json({ error: 'ID de post invÃƒÂ¡lido' });

    const reasonRaw = (req.body?.reason || '').toString().trim();
    if (!reasonRaw || reasonRaw.length < 10) {
      return res.status(400).json({ error: 'Describe mejor el motivo del reporte (mÃƒÂ­nimo 10 caracteres).' });
    }

    const { rows: postRows } = await pool.query('SELECT user_id FROM wildx_posts WHERE id=$1', [postId]);
    if (!postRows.length) return res.status(404).json({ error: 'Post no encontrado' });
    if (Number(postRows[0].user_id) === Number(wid)) {
      return res.status(400).json({ error: 'No puedes reportar tu propio post' });
    }

    const { rows: existing } = await pool.query(
      "SELECT id FROM wildx_post_reports WHERE post_id = $1 AND reporter_id = $2 AND status = 'pending' LIMIT 1",
      [postId, wid]
    );
    if (existing.length) {
      return res.status(400).json({ error: 'Ya tienes un reporte pendiente para este post.' });
    }

    const { rows } = await pool.query(
      `INSERT INTO wildx_post_reports (post_id, reporter_id, reason)
       VALUES ($1,$2,$3)
       RETURNING id, status, created_at`,
      [postId, wid, reasonRaw]
    );
    res.json({ success: true, report: rows[0] });
  } catch (err) {
    console.error('Error en POST /wildwave/api/posts/:id/report:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Listar reportes (Admin WildX)
app.get('/wildwave/api/admin/post-reports', async (req, res) => {
  try {
    await ensureWildXReportsTable();
    const wid = getWildXUserId(req);
    if (!wid || !(await isWildXAdmin(wid))) {
      return res.status(403).json({ error: 'Solo el administrador puede ver reportes.' });
    }
    const { rows } = await pool.query(
      `SELECT r.id, r.post_id, r.reporter_id, r.reason, r.status, r.created_at, r.reviewed_at,
              r.admin_id, r.admin_response,
              p.username AS post_username, p.content AS post_content,
              u.username AS reporter_username
         FROM wildx_post_reports r
         JOIN wildx_posts p ON p.id = r.post_id
         JOIN wildx_users u ON u.id = r.reporter_id
        ORDER BY r.created_at DESC`
    );
    res.json(rows);
  } catch (err) {
    console.error('Error en GET /wildwave/api/admin/post-reports:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Resolver reporte (Admin WildX)
app.post('/wildwave/api/admin/post-reports/:id/decide', async (req, res) => {
  const client = await pool.connect();
  try {
    await ensureWildXReportsTable();
    const wid = getWildXUserId(req);
    if (!wid || !(await isWildXAdmin(wid))) {
      client.release();
      return res.status(403).json({ error: 'Solo el administrador puede resolver reportes.' });
    }

    const { id } = req.params;
    const { approve, admin_response } = req.body || {};

    await client.query('BEGIN');
    const { rows: repRows } = await client.query(
      'SELECT * FROM wildx_post_reports WHERE id=$1 FOR UPDATE',
      [id]
    );
    if (!repRows.length) {
      await client.query('ROLLBACK');
      client.release();
      return res.status(404).json({ error: 'Reporte no encontrado' });
    }
    const r = repRows[0];
    if (r.status !== 'pending') {
      await client.query('ROLLBACK');
      client.release();
      return res.status(400).json({ error: 'El reporte ya fue revisado.' });
    }

    const newStatus = approve ? 'approved' : 'rejected';
    await client.query(
      `UPDATE wildx_post_reports
          SET status=$2, reviewed_at=NOW(), admin_id=$3, admin_response=$4
        WHERE id=$1`,
      [id, newStatus, wid, admin_response || null]
    );

    if (approve) {
      // Ocultar el post reportado
      await ensureWildXExtraColumns();
      await client.query(
        `UPDATE wildx_posts
            SET deleted_at = COALESCE(deleted_at, NOW()), status = 'deleted'
          WHERE id = $1`,
        [r.post_id]
      );
    }

    await client.query('COMMIT');
    client.release();
    res.json({ success: true, status: newStatus });
  } catch (err) {
    await client.query('ROLLBACK');
    client.release();
    console.error('Error en POST /wildwave/api/admin/post-reports/:id/decide:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Servir favicon (evitar error 404)
app.get('/favicon.ico', (_req, res) => {
  res.status(204).end();
});

/* ===== WORD BATTLE - JUEGO DE PALABRAS ===== */

// Diccionario bÃƒÂ¡sico de palabras en espaÃƒÂ±ol (se puede expandir)
const SPANISH_WORDS = new Set([
  'CASA', 'PERRO', 'GATO', 'MESA', 'SILLA', 'LIBRO', 'AGUA', 'FUEGO', 'TIERRA', 'AIRE',
  'SOL', 'LUNA', 'ESTRELLA', 'MAR', 'RIO', 'MONTE', 'VALLE', 'BOSQUE', 'CAMPO', 'CIUDAD',
  'AMOR', 'PAZ', 'GUERRA', 'VIDA', 'MUERTE', 'TIEMPO', 'ESPACIO', 'MUNDO', 'CIELO', 'INFIERNO',
  'HOMBRE', 'MUJER', 'NIÃƒâ€˜O', 'NIÃƒâ€˜A', 'PADRE', 'MADRE', 'HIJO', 'HIJA', 'HERMANO', 'HERMANA',
  'AMIGO', 'ENEMIGO', 'REY', 'REINA', 'PRINCIPE', 'PRINCESA', 'CABALLERO', 'DRAGON', 'MAGO', 'BRUJA',
  'ESPADA', 'ESCUDO', 'ARCO', 'FLECHA', 'LANZA', 'HACHA', 'MARTILLO', 'CUCHILLO', 'DAGA', 'BASTON',
  'ORO', 'PLATA', 'BRONCE', 'HIERRO', 'ACERO', 'DIAMANTE', 'RUBI', 'ESMERALDA', 'ZAFIRO', 'PERLA',
  'ROJO', 'AZUL', 'VERDE', 'AMARILLO', 'NEGRO', 'BLANCO', 'GRIS', 'ROSA', 'MORADO', 'NARANJA',
  'UNO', 'DOS', 'TRES', 'CUATRO', 'CINCO', 'SEIS', 'SIETE', 'OCHO', 'NUEVE', 'DIEZ',
  'LUNES', 'MARTES', 'MIERCOLES', 'JUEVES', 'VIERNES', 'SABADO', 'DOMINGO',
  'ENERO', 'FEBRERO', 'MARZO', 'ABRIL', 'MAYO', 'JUNIO', 'JULIO', 'AGOSTO', 'SEPTIEMBRE', 'OCTUBRE', 'NOVIEMBRE', 'DICIEMBRE',
  'PRIMAVERA', 'VERANO', 'OTOÃƒâ€˜O', 'INVIERNO',
  'NORTE', 'SUR', 'ESTE', 'OESTE',
  'ARRIBA', 'ABAJO', 'IZQUIERDA', 'DERECHA', 'ADELANTE', 'ATRAS', 'DENTRO', 'FUERA',
  'GRANDE', 'PEQUEÃƒâ€˜O', 'ALTO', 'BAJO', 'LARGO', 'CORTO', 'ANCHO', 'ESTRECHO', 'GORDO', 'FLACO',
  'BUENO', 'MALO', 'BONITO', 'FEO', 'NUEVO', 'VIEJO', 'JOVEN', 'ANCIANO', 'RICO', 'POBRE',
  'FELIZ', 'TRISTE', 'ALEGRE', 'ENOJADO', 'ASUSTADO', 'SORPRENDIDO', 'CANSADO', 'DESPIERTO',
  'COMER', 'BEBER', 'DORMIR', 'DESPERTAR', 'CAMINAR', 'CORRER', 'SALTAR', 'VOLAR', 'NADAR', 'BUCEAR',
  'HABLAR', 'ESCUCHAR', 'VER', 'MIRAR', 'OIR', 'OLER', 'TOCAR', 'SENTIR', 'PENSAR', 'SOÃƒâ€˜AR',
  'LEER', 'ESCRIBIR', 'DIBUJAR', 'PINTAR', 'CANTAR', 'BAILAR', 'JUGAR', 'TRABAJAR', 'ESTUDIAR', 'APRENDER',
  'AMAR', 'ODIAR', 'QUERER', 'DESEAR', 'NECESITAR', 'PODER', 'DEBER', 'SABER', 'CONOCER', 'ENTENDER',
  'DAR', 'RECIBIR', 'TOMAR', 'DEJAR', 'PONER', 'QUITAR', 'TRAER', 'LLEVAR', 'BUSCAR', 'ENCONTRAR',
  'ABRIR', 'CERRAR', 'SUBIR', 'BAJAR', 'ENTRAR', 'SALIR', 'LLEGAR', 'PARTIR', 'VENIR', 'IR',
  'HACER', 'CREAR', 'DESTRUIR', 'CONSTRUIR', 'ROMPER', 'ARREGLAR', 'LIMPIAR', 'ENSUCIAR', 'ORDENAR', 'DESORDENAR',
  'COMPRAR', 'VENDER', 'PAGAR', 'COBRAR', 'GANAR', 'PERDER', 'AHORRAR', 'GASTAR', 'PRESTAR', 'DEVOLVER',
  'AYUDAR', 'PROTEGER', 'DEFENDER', 'ATACAR', 'LUCHAR', 'PELEAR', 'GANAR', 'PERDER', 'EMPATAR', 'RENDIR',
  'COMENZAR', 'TERMINAR', 'CONTINUAR', 'PARAR', 'SEGUIR', 'ESPERAR', 'LLEGAR', 'PARTIR', 'QUEDAR', 'VOLVER',
  'DECIR', 'CONTAR', 'PREGUNTAR', 'RESPONDER', 'EXPLICAR', 'ENSEÃƒâ€˜AR', 'MOSTRAR', 'DEMOSTRAR', 'PROBAR', 'INTENTAR',
  'CREER', 'DUDAR', 'CONFIAR', 'DESCONFIAR', 'ESPERAR', 'TEMER', 'DESEAR', 'ANHELAR', 'SOÃƒâ€˜AR', 'IMAGINAR',
  // Palabras comunes adicionales
  'PALABRA', 'LETRA', 'NUMERO', 'SIGNO', 'SIMBOLO', 'MARCA', 'SEÃƒâ€˜AL', 'AVISO', 'MENSAJE', 'NOTA',
  'PAPEL', 'LAPIZ', 'PLUMA', 'TINTA', 'PINCEL', 'COLOR', 'DIBUJO', 'PINTURA', 'CUADRO', 'FOTO',
  'MUSICA', 'CANCION', 'MELODIA', 'RITMO', 'SONIDO', 'RUIDO', 'SILENCIO', 'VOZ', 'GRITO', 'SUSURRO',
  'COMIDA', 'BEBIDA', 'PAN', 'CARNE', 'PESCADO', 'FRUTA', 'VERDURA', 'LECHE', 'QUESO', 'HUEVO',
  'ARROZ', 'PASTA', 'SOPA', 'ENSALADA', 'POSTRE', 'DULCE', 'SALADO', 'AMARGO', 'ACIDO', 'PICANTE',
  'CAFE', 'TE', 'JUGO', 'VINO', 'CERVEZA', 'REFRESCO', 'HELADO', 'CHOCOLATE', 'CARAMELO', 'GALLETA',
  'ROPA', 'CAMISA', 'PANTALON', 'FALDA', 'VESTIDO', 'ZAPATO', 'BOTA', 'SANDALIA', 'SOMBRERO', 'GORRA',
  'ABRIGO', 'CHAQUETA', 'SUETER', 'BUFANDA', 'GUANTE', 'CALCETÃƒÂN', 'MEDIA', 'ROPA INTERIOR', 'PIJAMA', 'TRAJE',
  'COCHE', 'CARRO', 'AUTO', 'CAMION', 'AUTOBUS', 'TREN', 'AVION', 'BARCO', 'BICICLETA', 'MOTO',
  'CASA', 'EDIFICIO', 'TORRE', 'PUENTE', 'CALLE', 'AVENIDA', 'PLAZA', 'PARQUE', 'JARDIN', 'PATIO',
  'PUERTA', 'VENTANA', 'PARED', 'TECHO', 'SUELO', 'ESCALERA', 'ASCENSOR', 'BALCON', 'TERRAZA', 'SOTANO',
  'COCINA', 'BAÃƒâ€˜O', 'SALA', 'COMEDOR', 'DORMITORIO', 'HABITACION', 'CUARTO', 'OFICINA', 'ESTUDIO', 'BIBLIOTECA',
  'ESCUELA', 'COLEGIO', 'UNIVERSIDAD', 'INSTITUTO', 'ACADEMIA', 'CLASE', 'AULA', 'SALON', 'LABORATORIO', 'GIMNASIO',
  'HOSPITAL', 'CLINICA', 'FARMACIA', 'DOCTOR', 'MEDICO', 'ENFERMERA', 'PACIENTE', 'MEDICINA', 'PASTILLA', 'INYECCION',
  'TIENDA', 'MERCADO', 'SUPERMERCADO', 'CENTRO COMERCIAL', 'ALMACEN', 'BODEGA', 'DEPOSITO', 'FABRICA', 'TALLER', 'EMPRESA',
  'BANCO', 'DINERO', 'MONEDA', 'BILLETE', 'TARJETA', 'CREDITO', 'DEBITO', 'CUENTA', 'AHORRO', 'PRESTAMO',
  'TRABAJO', 'EMPLEO', 'PROFESION', 'OFICIO', 'CARRERA', 'NEGOCIO', 'EMPRESA', 'COMPAÃƒâ€˜IA', 'ORGANIZACION', 'INSTITUCION',
  'JEFE', 'EMPLEADO', 'TRABAJADOR', 'OBRERO', 'INGENIERO', 'ARQUITECTO', 'ABOGADO', 'CONTADOR', 'SECRETARIA', 'GERENTE',
  'ARTE', 'ARTISTA', 'PINTOR', 'ESCULTOR', 'MUSICO', 'CANTANTE', 'BAILARIN', 'ACTOR', 'ACTRIZ', 'DIRECTOR',
  'DEPORTE', 'FUTBOL', 'BALONCESTO', 'TENIS', 'NATACION', 'ATLETISMO', 'GIMNASIA', 'BOXEO', 'LUCHA', 'CICLISMO',
  'JUGADOR', 'EQUIPO', 'PARTIDO', 'CAMPEONATO', 'TORNEO', 'LIGA', 'COPA', 'MEDALLA', 'TROFEO', 'PREMIO',
  'PELOTA', 'BALON', 'RAQUETA', 'BATE', 'GUANTE', 'CASCO', 'RED', 'CANCHA', 'CAMPO', 'PISTA',
  'ANIMAL', 'MAMIFERO', 'AVE', 'PAJARO', 'PEZ', 'REPTIL', 'ANFIBIO', 'INSECTO', 'ARACNIDO', 'MOLUSCO',
  'LEON', 'TIGRE', 'OSO', 'LOBO', 'ZORRO', 'CONEJO', 'RATON', 'RATA', 'ARDILLA', 'CASTOR',
  'ELEFANTE', 'JIRAFA', 'CEBRA', 'HIPOPOTAMO', 'RINOCERONTE', 'CAMELLO', 'LLAMA', 'ALPACA', 'CANGURO', 'KOALA',
  'MONO', 'GORILA', 'CHIMPANCE', 'ORANGUTAN', 'LEMUR', 'PEREZOSO', 'ARMADILLO', 'HORMIGUERO', 'MURCIELAGO', 'TOPO',
  'CABALLO', 'BURRO', 'MULA', 'VACA', 'TORO', 'BUEY', 'CERDO', 'OVEJA', 'CABRA', 'GALLINA',
  'PATO', 'GANSO', 'CISNE', 'PALOMA', 'LORO', 'AGUILA', 'HALCON', 'BUHO', 'LECHUZA', 'CUERVO',
  'TIBURON', 'BALLENA', 'DELFIN', 'FOCA', 'MORSA', 'PULPO', 'CALAMAR', 'MEDUSA', 'ESTRELLA DE MAR', 'CANGREJO',
  'SERPIENTE', 'LAGARTO', 'COCODRILO', 'CAIMAN', 'TORTUGA', 'IGUANA', 'CAMALEON', 'SALAMANDRA', 'RANA', 'SAPO',
  'ABEJA', 'AVISPA', 'HORMIGA', 'MOSCA', 'MOSQUITO', 'MARIPOSA', 'POLILLA', 'LIBÃƒâ€°LULA', 'GRILLO', 'SALTAMONTES',
  'ARAÃƒâ€˜A', 'ESCORPION', 'CIEMPIES', 'MILPIES', 'CARACOL', 'BABOSA', 'LOMBRIZ', 'SANGUIJUELA', 'GARRAPATA', 'PULGA',
  'PLANTA', 'ARBOL', 'FLOR', 'HIERBA', 'PASTO', 'CESPED', 'HOJA', 'RAMA', 'TRONCO', 'RAIZ',
  'ROSA', 'TULIPAN', 'MARGARITA', 'GIRASOL', 'ORQUIDEA', 'LIRIO', 'CLAVEL', 'JAZMIN', 'VIOLETA', 'AMAPOLA',
  'PINO', 'ROBLE', 'SAUCE', 'OLMO', 'HAYA', 'ABEDUL', 'CEREZO', 'MANZANO', 'NARANJO', 'LIMONERO',
  'FRUTA', 'MANZANA', 'PERA', 'NARANJA', 'LIMON', 'PLATANO', 'UVA', 'FRESA', 'CEREZA', 'MELOCOTON',
  'SANDIA', 'MELON', 'PIÃƒâ€˜A', 'MANGO', 'PAPAYA', 'KIWI', 'COCO', 'AGUACATE', 'TOMATE', 'PEPINO',
  'ZANAHORIA', 'PAPA', 'CEBOLLA', 'AJO', 'LECHUGA', 'REPOLLO', 'BROCOLI', 'COLIFLOR', 'ESPARRAGO', 'APIO',
  'PIMIENTO', 'CHILE', 'BERENJENA', 'CALABAZA', 'CALABACIN', 'RABANO', 'NABO', 'REMOLACHA', 'ESPINACA', 'ACELGA',
  // MÃƒÂ¡s palabras comunes
  'COSA', 'OBJETO', 'ARTICULO', 'ELEMENTO', 'PARTE', 'PIEZA', 'TROZO', 'PEDAZO', 'FRAGMENTO', 'PORCION',
  'TODO', 'NADA', 'ALGO', 'ALGUIEN', 'NADIE', 'TODOS', 'ALGUNOS', 'VARIOS', 'MUCHOS', 'POCOS',
  'MAS', 'MENOS', 'MUCHO', 'POCO', 'BASTANTE', 'DEMASIADO', 'SUFICIENTE', 'INSUFICIENTE', 'EXCESO', 'FALTA',
  'BIEN', 'MAL', 'MEJOR', 'PEOR', 'IGUAL', 'DIFERENTE', 'MISMO', 'OTRO', 'DISTINTO', 'SIMILAR',
  'AQUI', 'ALLI', 'AHI', 'CERCA', 'LEJOS', 'JUNTO', 'SEPARADO', 'UNIDO', 'DIVIDIDO', 'ROTO',
  'AHORA', 'ANTES', 'DESPUES', 'LUEGO', 'PRONTO', 'TARDE', 'TEMPRANO', 'SIEMPRE', 'NUNCA', 'JAMAS',
  'HOY', 'AYER', 'MAÃƒâ€˜ANA', 'ANTEAYER', 'PASADO MAÃƒâ€˜ANA', 'SEMANA', 'MES', 'AÃƒâ€˜O', 'SIGLO', 'MILENIO',
  'MOMENTO', 'INSTANTE', 'SEGUNDO', 'MINUTO', 'HORA', 'DIA', 'NOCHE', 'MAÃƒâ€˜ANA', 'TARDE', 'MEDIODIA',
  'AMANECER', 'ATARDECER', 'ANOCHECER', 'MEDIANOCHE', 'ALBA', 'OCASO', 'CREPUSCULO', 'AURORA', 'PENUMBRA', 'SOMBRA',
  'LUZ', 'OSCURIDAD', 'BRILLO', 'RESPLANDOR', 'FULGOR', 'DESTELLO', 'RAYO', 'RELAMPAGO', 'TRUENO', 'TORMENTA',
  'LLUVIA', 'NIEVE', 'GRANIZO', 'NIEBLA', 'NEBLINA', 'ROCIO', 'ESCARCHA', 'HIELO', 'VAPOR', 'HUMO',
  'VIENTO', 'BRISA', 'HURACAN', 'TORNADO', 'CICLON', 'TIFON', 'TEMPESTAD', 'VENDAVAL', 'RAFAGA', 'SOPLO',
  'CALOR', 'FRIO', 'TEMPERATURA', 'CLIMA', 'TIEMPO', 'ESTACION', 'EPOCA', 'ERA', 'PERIODO', 'FASE',
  'PRINCIPIO', 'FIN', 'INICIO', 'FINAL', 'COMIENZO', 'TERMINO', 'ORIGEN', 'DESTINO', 'CAUSA', 'EFECTO',
  'RAZON', 'MOTIVO', 'PROPOSITO', 'OBJETIVO', 'META', 'FIN', 'INTENCION', 'DESEO', 'VOLUNTAD', 'DECISION',
  'IDEA', 'PENSAMIENTO', 'CONCEPTO', 'NOCION', 'OPINION', 'JUICIO', 'CRITERIO', 'PUNTO DE VISTA', 'PERSPECTIVA', 'ENFOQUE',
  'VERDAD', 'MENTIRA', 'REALIDAD', 'FICCION', 'FANTASIA', 'ILUSION', 'SUEÃƒâ€˜O', 'PESADILLA', 'VISION', 'ALUCINACION',
  'PROBLEMA', 'SOLUCION', 'PREGUNTA', 'RESPUESTA', 'DUDA', 'CERTEZA', 'SEGURIDAD', 'INSEGURIDAD', 'CONFIANZA', 'DESCONFIANZA',
  'MIEDO', 'VALOR', 'VALENTIA', 'COBARDIA', 'CORAJE', 'AUDACIA', 'TEMERIDAD', 'PRUDENCIA', 'CAUTELA', 'PRECAUCION',
  'FUERZA', 'DEBILIDAD', 'PODER', 'IMPOTENCIA', 'CAPACIDAD', 'INCAPACIDAD', 'HABILIDAD', 'TORPEZA', 'DESTREZA', 'MAÃƒâ€˜A',
  'INTELIGENCIA', 'ESTUPIDEZ', 'SABIDURIA', 'IGNORANCIA', 'CONOCIMIENTO', 'DESCONOCIMIENTO', 'CIENCIA', 'ARTE', 'TECNICA', 'METODO',
  'ORDEN', 'DESORDEN', 'ORGANIZACION', 'CAOS', 'ESTRUCTURA', 'SISTEMA', 'ESQUEMA', 'PLAN', 'PROYECTO', 'PROGRAMA',
  'LEY', 'REGLA', 'NORMA', 'PRINCIPIO', 'VALOR', 'MORAL', 'ETICA', 'JUSTICIA', 'INJUSTICIA', 'DERECHO',
  'LIBERTAD', 'ESCLAVITUD', 'INDEPENDENCIA', 'DEPENDENCIA', 'AUTONOMIA', 'SOBERANIA', 'AUTORIDAD', 'PODER', 'DOMINIO', 'CONTROL',
  'GOBIERNO', 'ESTADO', 'NACION', 'PAIS', 'PATRIA', 'TIERRA', 'TERRITORIO', 'REGION', 'PROVINCIA', 'MUNICIPIO',
  'PUEBLO', 'ALDEA', 'VILLA', 'CIUDAD', 'CAPITAL', 'METROPOLI', 'URBE', 'POBLACION', 'COMUNIDAD', 'SOCIEDAD',
  'GRUPO', 'CONJUNTO', 'COLECCION', 'SERIE', 'SECUENCIA', 'SUCESION', 'CADENA', 'LINEA', 'FILA', 'COLA',
  'CIRCULO', 'CUADRADO', 'TRIANGULO', 'RECTANGULO', 'ROMBO', 'TRAPECIO', 'PENTAGONO', 'HEXAGONO', 'OCTAGONO', 'POLIGONO',
  'ESFERA', 'CUBO', 'CILINDRO', 'CONO', 'PIRAMIDE', 'PRISMA', 'TOROIDE', 'ELIPSOIDE', 'PARABOLOIDE', 'HIPERBOLOIDE',
  'PUNTO', 'LINEA', 'PLANO', 'VOLUMEN', 'SUPERFICIE', 'AREA', 'PERIMETRO', 'DIAMETRO', 'RADIO', 'CIRCUNFERENCIA',
  'ANGULO', 'GRADO', 'RADIAN', 'PARALELO', 'PERPENDICULAR', 'HORIZONTAL', 'VERTICAL', 'DIAGONAL', 'TANGENTE', 'SECANTE',
  'SUMA', 'RESTA', 'MULTIPLICACION', 'DIVISION', 'POTENCIA', 'RAIZ', 'LOGARITMO', 'EXPONENTE', 'FRACCION', 'DECIMAL',
  'ENTERO', 'NATURAL', 'RACIONAL', 'IRRACIONAL', 'REAL', 'COMPLEJO', 'IMAGINARIO', 'INFINITO', 'CERO', 'UNIDAD'
]);

// Tabla para guardar partidas, salas y recompensas
async function ensureWordBattleTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS word_battle_rooms (
      id SERIAL PRIMARY KEY,
      room_code TEXT UNIQUE NOT NULL,
      host_id TEXT NOT NULL,
      players JSONB NOT NULL DEFAULT '[]',
      game_state JSONB,
      status TEXT NOT NULL DEFAULT 'waiting',
      created_at TIMESTAMP DEFAULT NOW(),
      started_at TIMESTAMP,
      ended_at TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS word_battle_games (
      id SERIAL PRIMARY KEY,
      room_code TEXT NOT NULL,
      user_id TEXT NOT NULL,
      players JSONB NOT NULL,
      winner TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS word_battle_rewards (
      id SERIAL PRIMARY KEY,
      user_id TEXT NOT NULL,
      player_name TEXT NOT NULL,
      position INTEGER NOT NULL,
      reward INTEGER NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`CREATE INDEX IF NOT EXISTS idx_wb_rooms_code ON word_battle_rooms(room_code)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_wb_rooms_status ON word_battle_rooms(status)`);
}

// Generar cÃƒÂ³digo de sala ÃƒÂºnico
function generateRoomCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 6; i++) {
    code += chars[Math.floor(Math.random() * chars.length)];
  }
  return code;
}

// Crear sala de juego
app.post('/api/word-battle/room/create', async (req, res) => {
  try {
    await ensureWordBattleTables();

    const { userId, playerName } = req.body;

    if (!userId || !playerName) {
      return res.status(400).json({ error: 'Faltan datos' });
    }

    let roomCode;
    let attempts = 0;

    // Intentar generar un cÃƒÂ³digo ÃƒÂºnico
    while (attempts < 10) {
      roomCode = generateRoomCode();
      const { rows } = await pool.query(
        'SELECT id FROM word_battle_rooms WHERE room_code = $1',
        [roomCode]
      );

      if (rows.length === 0) break;
      attempts++;
    }

    if (attempts >= 10) {
      return res.status(500).json({ error: 'No se pudo generar cÃƒÂ³digo ÃƒÂºnico' });
    }

    const players = [{ userId, name: playerName, lives: 3, attempts: 0, eliminated: false, isHost: true }];

    const { rows } = await pool.query(
      `INSERT INTO word_battle_rooms (room_code, host_id, players, status)
       VALUES ($1, $2, $3, 'waiting')
       RETURNING *`,
      [roomCode, userId, JSON.stringify(players)]
    );

    res.json({ success: true, room: rows[0] });
  } catch (err) {
    console.error('Error en /api/word-battle/room/create:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Unirse a sala
app.post('/api/word-battle/room/join', async (req, res) => {
  try {
    await ensureWordBattleTables();

    const { roomCode, userId, playerName } = req.body;

    if (!roomCode || !userId || !playerName) {
      return res.status(400).json({ error: 'Faltan datos' });
    }

    const { rows } = await pool.query(
      'SELECT * FROM word_battle_rooms WHERE room_code = $1 AND status = $2',
      [roomCode.toUpperCase(), 'waiting']
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Sala no encontrada o ya iniciada' });
    }

    const room = rows[0];
    const players = room.players || [];

    if (players.length >= 6) {
      return res.status(400).json({ error: 'Sala llena (mÃƒÂ¡ximo 6 jugadores)' });
    }

    if (players.some(p => p.userId === userId)) {
      return res.status(400).json({ error: 'Ya estÃƒÂ¡s en esta sala' });
    }

    if (players.some(p => p.name === playerName)) {
      return res.status(400).json({ error: 'Este nombre ya estÃƒÂ¡ en uso' });
    }

    players.push({ userId, name: playerName, lives: 3, attempts: 0, eliminated: false, isHost: false });

    await pool.query(
      'UPDATE word_battle_rooms SET players = $1 WHERE room_code = $2',
      [JSON.stringify(players), roomCode.toUpperCase()]
    );

    res.json({ success: true, room: { ...room, players } });
  } catch (err) {
    console.error('Error en /api/word-battle/room/join:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Obtener estado de sala
app.get('/api/word-battle/room/:roomCode', async (req, res) => {
  try {
    await ensureWordBattleTables();

    const { roomCode } = req.params;

    const { rows } = await pool.query(
      'SELECT * FROM word_battle_rooms WHERE room_code = $1',
      [roomCode.toUpperCase()]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Sala no encontrada' });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error('Error en /api/word-battle/room/:roomCode:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Iniciar juego (solo host)
app.post('/api/word-battle/room/:roomCode/start', async (req, res) => {
  try {
    await ensureWordBattleTables();

    const { roomCode } = req.params;
    const { userId } = req.body;

    const { rows } = await pool.query(
      'SELECT * FROM word_battle_rooms WHERE room_code = $1',
      [roomCode.toUpperCase()]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Sala no encontrada' });
    }

    const room = rows[0];

    if (room.host_id !== userId) {
      return res.status(403).json({ error: 'Solo el host puede iniciar el juego' });
    }

    if (room.players.length < 2) {
      return res.status(400).json({ error: 'Se necesitan al menos 2 jugadores' });
    }

    await pool.query(
      'UPDATE word_battle_rooms SET status = $1, started_at = NOW() WHERE room_code = $2',
      ['playing', roomCode.toUpperCase()]
    );

    res.json({ success: true });
  } catch (err) {
    console.error('Error en /api/word-battle/room/:roomCode/start:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Actualizar estado del juego
app.post('/api/word-battle/room/:roomCode/update', async (req, res) => {
  try {
    await ensureWordBattleTables();

    const { roomCode } = req.params;
    const { gameState } = req.body;

    await pool.query(
      'UPDATE word_battle_rooms SET game_state = $1 WHERE room_code = $2',
      [JSON.stringify(gameState), roomCode.toUpperCase()]
    );

    res.json({ success: true });
  } catch (err) {
    console.error('Error en /api/word-battle/room/:roomCode/update:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Salir de sala
app.post('/api/word-battle/room/:roomCode/leave', async (req, res) => {
  try {
    await ensureWordBattleTables();

    const { roomCode } = req.params;
    const { userId } = req.body;

    const { rows } = await pool.query(
      'SELECT * FROM word_battle_rooms WHERE room_code = $1',
      [roomCode.toUpperCase()]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Sala no encontrada' });
    }

    const room = rows[0];
    let players = room.players || [];

    players = players.filter(p => p.userId !== userId);

    if (players.length === 0) {
      // Si no quedan jugadores, eliminar la sala
      await pool.query('DELETE FROM word_battle_rooms WHERE room_code = $1', [roomCode.toUpperCase()]);
    } else {
      // Si el host se va, asignar nuevo host
      if (room.host_id === userId && players.length > 0) {
        players[0].isHost = true;
        await pool.query(
          'UPDATE word_battle_rooms SET players = $1, host_id = $2 WHERE room_code = $3',
          [JSON.stringify(players), players[0].userId, roomCode.toUpperCase()]
        );
      } else {
        await pool.query(
          'UPDATE word_battle_rooms SET players = $1 WHERE room_code = $2',
          [JSON.stringify(players), roomCode.toUpperCase()]
        );
      }
    }

    res.json({ success: true });
  } catch (err) {
    console.error('Error en /api/word-battle/room/:roomCode/leave:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Verificar si una palabra es vÃƒÂ¡lida
app.post('/api/word-battle/verify', async (req, res) => {
  try {
    const { word } = req.body;

    if (!word || typeof word !== 'string') {
      return res.json({ valid: false });
    }

    const upperWord = word.toUpperCase().trim();

    // Verificar si la palabra estÃƒÂ¡ en el diccionario
    const valid = SPANISH_WORDS.has(upperWord);

    res.json({ valid });
  } catch (err) {
    console.error('Error en /api/word-battle/verify:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Guardar recompensa
app.post('/api/word-battle/reward', async (req, res) => {
  try {
    await ensureWordBattleTables();

    const { userId, playerName, position, reward } = req.body;

    if (!userId || !playerName || !position || !reward) {
      return res.status(400).json({ error: 'Faltan datos' });
    }

    // Guardar recompensa
    await pool.query(
      `INSERT INTO word_battle_rewards (user_id, player_name, position, reward)
       VALUES ($1, $2, $3, $4)`,
      [userId, playerName, position, reward]
    );

    // Actualizar Ecoxionums del usuario si existe en la base de datos
    try {
      await pool.query(
        `UPDATE ocean_pay_users 
         SET ecoxionums = COALESCE(ecoxionums, 0) + $1
         WHERE username = $2`,
        [reward, userId]
      );
    } catch (e) {
      // Si el usuario no existe en ocean_pay_users, solo guardamos la recompensa
      console.log('Usuario no encontrado en ocean_pay_users, solo se guarda la recompensa');
    }

    res.json({ success: true });
  } catch (err) {
    console.error('Error en /api/word-battle/reward:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Obtener historial de recompensas
app.get('/api/word-battle/rewards/:userId', async (req, res) => {
  try {
    await ensureWordBattleTables();

    const { userId } = req.params;

    const { rows } = await pool.query(
      `SELECT * FROM word_battle_rewards 
       WHERE user_id = $1 
       ORDER BY created_at DESC 
       LIMIT 50`,
      [userId]
    );

    res.json(rows);
  } catch (err) {
    console.error('Error en /api/word-battle/rewards/:userId:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// ... (AquÃƒÂ­ terminan todas tus rutas de app.get/app.post) ...

/* =========================================
   ECOCONSOLE API ENDPOINTS
   ========================================= */

// Middleware para verificar JWT de EcoConsole
const verifyEcoConsoleToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  try {
    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    req.userId = parseInt((decoded.id || decoded.uid)) || (decoded.id || decoded.uid);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }
};

// Asegurar tabla de cuota de comandos
async function ensureEcoConsoleTable() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ecoconsole_quota (
        user_id INTEGER PRIMARY KEY REFERENCES ocean_pay_users(id) ON DELETE CASCADE,
        daily_limit INTEGER DEFAULT 50,
        remaining INTEGER DEFAULT 50,
        bonus_quota INTEGER DEFAULT 0,
        last_reset TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        total_commands_executed BIGINT DEFAULT 0,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS ecoconsole_transactions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES ocean_pay_users(id) ON DELETE CASCADE,
        type VARCHAR(50) NOT NULL,
        command_name VARCHAR(100),
        cost INTEGER DEFAULT 0,
        description TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log('Ã¢Å“â€¦ Tablas de EcoConsole aseguradas');
  } catch (err) {
    console.error('Ã¢ÂÅ’ Error creando tablas EcoConsole:', err);
  }
}

// Obtener cuota de comandos del usuario
app.get('/ecoconsole/quota', verifyEcoConsoleToken, async (req, res) => {
  try {
    const userId = req.userId;

    // Verificar si necesita reset diario (cada 24 horas)
    let { rows } = await pool.query(
      'SELECT * FROM ecoconsole_quota WHERE user_id = $1',
      [userId]
    );

    if (rows.length === 0) {
      // Crear registro inicial
      await pool.query(
        `INSERT INTO ecoconsole_quota (user_id, daily_limit, remaining, bonus_quota, last_reset) 
         VALUES ($1, 50, 50, 0, NOW())`,
        [userId]
      );
      rows = [{ daily_limit: 50, remaining: 50, bonus_quota: 0, last_reset: new Date(), total_commands_executed: 0 }];
    } else {
      const lastReset = new Date(rows[0].last_reset);
      const now = new Date();
      const hoursSinceReset = (now - lastReset) / (1000 * 60 * 60);

      // Reset diario despuÃƒÂ©s de 24 horas
      if (hoursSinceReset >= 24) {
        await pool.query(
          `UPDATE ecoconsole_quota 
           SET remaining = daily_limit, last_reset = NOW() 
           WHERE user_id = $1`,
          [userId]
        );
        rows[0].remaining = rows[0].daily_limit;
        rows[0].last_reset = now;
      }
    }

    const quota = rows[0];
    const nextReset = new Date(quota.last_reset);
    nextReset.setHours(nextReset.getHours() + 24);

    res.json({
      dailyLimit: quota.daily_limit,
      remaining: quota.remaining + (quota.bonus_quota || 0),
      bonusQuota: quota.bonus_quota || 0,
      totalExecuted: quota.total_commands_executed || 0,
      nextReset: nextReset.toISOString()
    });
  } catch (err) {
    console.error('Error en /ecoconsole/quota:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Usar un comando (decrementar cuota)
app.post('/ecoconsole/use-command', verifyEcoConsoleToken, async (req, res) => {
  const { commandName } = req.body;
  const userId = req.userId;

  try {
    // Verificar cuota disponible
    const { rows } = await pool.query(
      'SELECT remaining, bonus_quota FROM ecoconsole_quota WHERE user_id = $1 FOR UPDATE',
      [userId]
    );

    if (rows.length === 0 || (rows[0].remaining + (rows[0].bonus_quota || 0)) <= 0) {
      return res.status(403).json({ error: 'Sin cuota de comandos disponible', needsQuota: true });
    }

    // Usar primero el bonus, luego el remaining
    if (rows[0].bonus_quota > 0) {
      await pool.query(
        `UPDATE ecoconsole_quota 
         SET bonus_quota = bonus_quota - 1, total_commands_executed = total_commands_executed + 1 
         WHERE user_id = $1`,
        [userId]
      );
    } else {
      await pool.query(
        `UPDATE ecoconsole_quota 
         SET remaining = remaining - 1, total_commands_executed = total_commands_executed + 1 
         WHERE user_id = $1`,
        [userId]
      );
    }

    // Registrar transacciÃƒÂ³n
    await pool.query(
      `INSERT INTO ecoconsole_transactions (user_id, type, command_name, description) 
       VALUES ($1, 'command_use', $2, 'Uso de comando')`,
      [userId, commandName]
    );

    res.json({ success: true });
  } catch (err) {
    console.error('Error en /ecoconsole/use-command:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Comprar mÃƒÂ¡s cuota con EcoCoreBits
app.post('/ecoconsole/purchase-quota', verifyEcoConsoleToken, async (req, res) => {
  const { pack } = req.body; // 'small' (25 por 100 ECB), 'large' (100 por 350 ECB)
  const userId = req.userId;

  const packs = {
    small: { quota: 25, cost: 100 },
    large: { quota: 100, cost: 350 }
  };

  const selectedPack = packs[pack];
  if (!selectedPack) {
    return res.status(400).json({ error: 'Pack invÃƒÂ¡lido' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Verificar saldo de EcoCoreBits (aquabux en ocean_pay_users)
    const { rows: userRows } = await client.query(
      'SELECT aquabux FROM ocean_pay_users WHERE id = $1 FOR UPDATE',
      [userId]
    );

    if (userRows.length === 0) {
      throw new Error('Usuario no encontrado');
    }

    const currentBalance = userRows[0].aquabux || 0;
    if (currentBalance < selectedPack.cost) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        error: 'EcoCoreBits insuficientes',
        required: selectedPack.cost,
        current: currentBalance
      });
    }

    // Descontar EcoCoreBits
    await client.query(
      'UPDATE ocean_pay_users SET aquabux = aquabux - $1 WHERE id = $2',
      [selectedPack.cost, userId]
    );

    // AÃƒÂ±adir cuota bonus
    await client.query(
      `INSERT INTO ecoconsole_quota (user_id, bonus_quota) 
       VALUES ($1, $2)
       ON CONFLICT (user_id) 
       DO UPDATE SET bonus_quota = ecoconsole_quota.bonus_quota + $2`,
      [userId, selectedPack.quota]
    );

    // Registrar transacciÃƒÂ³n
    await client.query(
      `INSERT INTO ecoconsole_transactions (user_id, type, cost, description) 
       VALUES ($1, 'quota_purchase', $2, $3)`,
      [userId, selectedPack.cost, `Compra de ${selectedPack.quota} comandos extra`]
    );

    await client.query('COMMIT');

    // Obtener nuevo saldo
    const { rows: newBalance } = await client.query(
      'SELECT aquabux FROM ocean_pay_users WHERE id = $1',
      [userId]
    );

    res.json({
      success: true,
      quotaAdded: selectedPack.quota,
      newBalance: newBalance[0].aquabux
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error en /ecoconsole/purchase-quota:', err);
    res.status(500).json({ error: err.message || 'Error interno' });
  } finally {
    client.release();
  }
});

// Ejecutar comando de pago
app.post('/ecoconsole/paid-command', verifyEcoConsoleToken, async (req, res) => {
  const { commandName, cost } = req.body;
  const userId = req.userId;

  if (!commandName || !cost || cost <= 0) {
    return res.status(400).json({ error: 'Datos invÃƒÂ¡lidos' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Verificar saldo
    const { rows } = await client.query(
      'SELECT aquabux FROM ocean_pay_users WHERE id = $1 FOR UPDATE',
      [userId]
    );

    if (rows.length === 0 || rows[0].aquabux < cost) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        error: 'EcoCoreBits insuficientes',
        required: cost,
        current: rows[0]?.aquabux || 0
      });
    }

    // Descontar EcoCoreBits
    await client.query(
      'UPDATE ocean_pay_users SET aquabux = aquabux - $1 WHERE id = $2',
      [cost, userId]
    );

    // Registrar transacciÃƒÂ³n
    await client.query(
      `INSERT INTO ecoconsole_transactions (user_id, type, command_name, cost, description) 
       VALUES ($1, 'paid_command', $2, $3, $4)`,
      [userId, commandName, cost, `Comando de pago: ${commandName}`]
    );

    // Actualizar contador de comandos
    await client.query(
      `UPDATE ecoconsole_quota 
       SET total_commands_executed = total_commands_executed + 1 
       WHERE user_id = $1`,
      [userId]
    );

    await client.query('COMMIT');

    // Obtener nuevo saldo
    const { rows: newBalance } = await client.query(
      'SELECT aquabux FROM ocean_pay_users WHERE id = $1',
      [userId]
    );

    res.json({
      success: true,
      newBalance: newBalance[0].aquabux
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error en /ecoconsole/paid-command:', err);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

// Obtener historial de transacciones de EcoConsole
app.get('/ecoconsole/transactions', verifyEcoConsoleToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM ecoconsole_transactions 
       WHERE user_id = $1 
       ORDER BY created_at DESC 
       LIMIT 50`,
      [req.userId]
    );
    res.json(rows);
  } catch (err) {
    console.error('Error en /ecoconsole/transactions:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Health check de EcoConsole
app.get('/ecoconsole/health', (_req, res) => {
  res.json({ status: 'up', service: 'EcoConsole', version: '2.0' });
});

// =================================================================
// FUNCIÃƒâ€œN PARA ASEGURAR TABLA DE MONEDAS DEL USUARIO (user_currency)
// =================================================================
async function ensureUserCurrencyTable() {
  try {
    console.log("Asegurando que la tabla 'user_currency' exista...");

    const client = await pool.connect();
    await client.query(`
      CREATE TABLE IF NOT EXISTS user_currency (
        id SERIAL PRIMARY KEY,
        
        -- Clave forÃƒÂ¡nea para relacionarla con tu tabla de usuarios (ocean_pay_users)
        user_id INT NOT NULL REFERENCES ocean_pay_users(id) ON DELETE CASCADE, 
        
        currency_type VARCHAR(50) NOT NULL,
        amount BIGINT NOT NULL DEFAULT 0,
        
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        
        -- Clave ÃƒÂºnica: Un usuario solo puede tener un registro por tipo de moneda.
        UNIQUE(user_id, currency_type) 
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS ocean_pay_user_balances (
        user_id INT PRIMARY KEY REFERENCES ocean_pay_users(id) ON DELETE CASCADE,
        balances JSONB NOT NULL DEFAULT '{}'::jsonb,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await client.query(`
      INSERT INTO ocean_pay_user_balances (user_id, balances)
      SELECT uc.user_id, jsonb_object_agg(LOWER(uc.currency_type), GREATEST(COALESCE(uc.amount, 0), 0))
      FROM user_currency uc
      GROUP BY uc.user_id
      ON CONFLICT (user_id) DO NOTHING
    `).catch(() => {});

    await client.query(`
      INSERT INTO ocean_pay_user_balances (user_id, balances)
      SELECT c.user_id,
             COALESCE(
               jsonb_object_agg(LOWER(cb.currency_type), GREATEST(COALESCE(cb.amount, 0), 0))
               FILTER (WHERE cb.currency_type IS NOT NULL),
               '{}'::jsonb
             ) AS balances
      FROM ocean_pay_cards c
      LEFT JOIN ocean_pay_card_balances cb ON cb.card_id = c.id
      WHERE c.is_primary = true
      GROUP BY c.user_id
      ON CONFLICT (user_id) DO NOTHING
    `).catch(() => {});

    // Backfill seguro (solo claves faltantes) para evitar reescrituras que restauren saldos gastados.
    // Fuente prioritaria final:
    //   1) wallet actual (si ya existe una clave, NO se toca)
    //   2) user_currency
    //   3) suma de ocean_pay_card_balances por usuario
    //   4) columnas legacy directas (aquabux/appbux/ecoxionums)
    const { rows: users } = await client.query(
      'SELECT id, aquabux, appbux, ecoxionums FROM ocean_pay_users'
    );

    for (const user of users) {
      const userId = Number(user.id);
      if (!userId) continue;

      await ensureUserWalletRow(client, userId);

      const { rows: walletRows } = await client.query(
        `SELECT balances FROM ${USER_WALLET_TABLE} WHERE user_id = $1 LIMIT 1`,
        [userId]
      );
      const currentWallet = (walletRows[0]?.balances && typeof walletRows[0].balances === 'object')
        ? walletRows[0].balances
        : {};

      const { rows: ucRows } = await client.query(
        `SELECT LOWER(currency_type) AS currency, amount
         FROM user_currency
         WHERE user_id = $1`,
        [userId]
      );
      const userCurrencyMap = {};
      for (const row of ucRows) {
        const key = String(row.currency || '').toLowerCase();
        if (!key) continue;
        userCurrencyMap[key] = Math.max(0, Number(row.amount || 0));
      }

      const { rows: cardRows } = await client.query(
        `SELECT LOWER(b.currency_type) AS currency, SUM(b.amount) AS total
         FROM ocean_pay_card_balances b
         JOIN ocean_pay_cards c ON c.id = b.card_id
         WHERE c.user_id = $1
         GROUP BY LOWER(b.currency_type)`,
        [userId]
      );
      const cardMap = {};
      for (const row of cardRows) {
        const key = String(row.currency || '').toLowerCase();
        if (!key) continue;
        cardMap[key] = Math.max(0, Number(row.total || 0));
      }

      const directMap = {
        aquabux: Math.max(0, Number(user.aquabux || 0)),
        appbux: Math.max(0, Number(user.appbux || 0)),
        ecoxionums: Math.max(0, Number(user.ecoxionums || 0))
      };

      const sourceMap = { ...directMap, ...cardMap, ...userCurrencyMap };
      const nextWallet = { ...(currentWallet || {}) };
      let changed = false;

      // Backfill de divisas conocidas sin tocar valores ya existentes.
      for (const currency of UNIFIED_WALLET_CURRENCIES) {
        if (nextWallet[currency] === undefined || nextWallet[currency] === null) {
          nextWallet[currency] = Math.max(0, Number(sourceMap[currency] || 0));
          changed = true;
        }
      }

      // Backfill de cualquier divisa extra que exista en tablas legacy.
      for (const [currency, value] of Object.entries(sourceMap)) {
        if (nextWallet[currency] === undefined || nextWallet[currency] === null) {
          nextWallet[currency] = Math.max(0, Number(value || 0));
          changed = true;
        }
      }

      if (changed) {
        await client.query(
          `UPDATE ${USER_WALLET_TABLE}
           SET balances = $1::jsonb,
               updated_at = NOW()
           WHERE user_id = $2`,
          [JSON.stringify(nextWallet), userId]
        );
      }
    }

    client.release();
    console.log("Tabla 'user_currency' asegurada y lista para nadar.");

  } catch (err) {
    console.error("Ã¢ÂÅ’ ERROR al asegurar la tabla 'user_currency':", err);
  }
}

// =================================================================
// CÃƒâ€œDIGO DE INICIALIZACIÃƒâ€œN (Al final de server.js)
// =================================================================

await ensureDatabase();
await ensureTables();
await ensureQuizTables();
await ensureWordBattleTables();
await ensureUserCurrencyTable();

// Crear tablas de EcoConsole
await ensureEcoConsoleTable();

// Crear tablas de NatMarket
if (typeof createNatMarketTables === 'function') {
  await createNatMarketTables();
} else {
  console.warn('[INIT] createNatMarketTables no definida, se omite sin bloquear el arranque.');
}

// Ã°Å¸â€™Â¡ CORRECCIÃƒâ€œN 1: Llama a la limpieza DESPUÃƒâ€°S de asegurar que todas las tablas existen.
console.log("Iniciando limpieza de eventos antiguos...");
if (typeof cleanupOldEvents === 'function') {
  await cleanupOldEvents();
} else {
  console.warn('[INIT] cleanupOldEvents no definida, se omite sin bloquear el arranque.');
}
console.log("Limpieza de eventos antiguos finalizada.");

// ========== FLORET SHOP TABLES ==========
// ========== FLORET SHOP TABLES ==========
await pool.query(`
  CREATE TABLE IF NOT EXISTS floret_users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100),
    password TEXT NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    power_level INTEGER DEFAULT 0, -- 0: User, 1: Sub-Admin (Malevo), 2: Super-Admin (OceanandWild)
    created_at TIMESTAMP DEFAULT NOW()
  )
`).catch(() => console.log('Ã¢Å¡Â Ã¯Â¸Â Tabla floret_users ya existe'));

// Add columns if they don't exist
await pool.query(`ALTER TABLE floret_users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE`).catch(() => { });
await pool.query(`ALTER TABLE floret_users ADD COLUMN IF NOT EXISTS power_level INTEGER DEFAULT 0`).catch(() => { });

await pool.query(`
  CREATE TABLE IF NOT EXISTS floret_products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    price DECIMAL(12,2) NOT NULL,
    stock INTEGER DEFAULT 1,
    condition VARCHAR(50) DEFAULT 'Nuevo',
    images TEXT[] DEFAULT '{}',
    requires_size BOOLEAN DEFAULT FALSE,
    sizes TEXT[] DEFAULT '{}',
    measurements VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW()
  )
`).catch(() => console.log('Ã¢Å¡Â Ã¯Â¸Â Tabla floret_products ya existe'));

await pool.query(`ALTER TABLE floret_products ADD COLUMN IF NOT EXISTS stock INTEGER DEFAULT 1`).catch(() => { });
await pool.query(`ALTER TABLE floret_products ADD COLUMN IF NOT EXISTS seller_email VARCHAR(120) DEFAULT 'karatedojor@gmail.com'`).catch(() => { });
await pool.query(
  `UPDATE floret_products
   SET seller_email = $1
   WHERE seller_email IS NULL OR TRIM(seller_email) = ''`,
  [FLORET_MAIN_SELLER_EMAIL]
).catch(() => { });

await pool.query(`
  CREATE TABLE IF NOT EXISTS floret_product_reviews (
    id SERIAL PRIMARY KEY,
    product_id INTEGER NOT NULL REFERENCES floret_products(id) ON DELETE CASCADE,
    reviewer_user_id INTEGER REFERENCES floret_users(id) ON DELETE SET NULL,
    reviewer_name VARCHAR(80),
    rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
    comment TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
  )
`).catch(() => console.log('Ã¢Å¡Â Ã¯Â¸Â Tabla floret_product_reviews ya existe'));

await pool.query(`
  CREATE TABLE IF NOT EXISTS floret_seller_reviews (
    id SERIAL PRIMARY KEY,
    seller_email VARCHAR(120) NOT NULL DEFAULT 'karatedojor@gmail.com',
    reviewer_user_id INTEGER REFERENCES floret_users(id) ON DELETE SET NULL,
    reviewer_name VARCHAR(80),
    rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
    comment TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
  )
`).catch(() => console.log('Ã¢Å¡Â Ã¯Â¸Â Tabla floret_seller_reviews ya existe'));

await pool.query(`
  CREATE TABLE IF NOT EXISTS floret_notifications (
    id SERIAL PRIMARY KEY,
    target_user_id INTEGER REFERENCES floret_users(id) ON DELETE CASCADE,
    target_email VARCHAR(120),
    type VARCHAR(40) NOT NULL,
    title VARCHAR(180) NOT NULL,
    message TEXT,
    product_id INTEGER REFERENCES floret_products(id) ON DELETE SET NULL,
    review_id INTEGER NOT NULL,
    review_scope VARCHAR(20) NOT NULL DEFAULT 'product',
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
  )
`).catch(() => console.log('Ã¢Å¡Â Ã¯Â¸Â Tabla floret_notifications ya existe'));

await pool.query(`ALTER TABLE floret_notifications ALTER COLUMN review_id DROP NOT NULL`).catch(() => { });
await pool.query(`ALTER TABLE floret_notifications ADD COLUMN IF NOT EXISTS order_id INTEGER`).catch(() => { });
await pool.query(`ALTER TABLE floret_notifications ADD COLUMN IF NOT EXISTS meta JSONB DEFAULT '{}'::jsonb`).catch(() => { });
await pool.query(`ALTER TABLE floret_notifications ADD COLUMN IF NOT EXISTS review_scope VARCHAR(20) NOT NULL DEFAULT 'product'`).catch(() => { });

await pool.query(`
  CREATE TABLE IF NOT EXISTS floret_orders (
    id SERIAL PRIMARY KEY,
    buyer_name VARCHAR(120) NOT NULL,
    buyer_email VARCHAR(140) NOT NULL,
    buyer_phone VARCHAR(60),
    shipping_address TEXT,
    shipping_city VARCHAR(100),
    payment_method VARCHAR(40) DEFAULT 'mercado_pago',
    payment_ref VARCHAR(140),
    total DECIMAL(12,2) NOT NULL DEFAULT 0,
    status VARCHAR(20) NOT NULL DEFAULT 'new',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
  )
`).catch(() => console.log('Tabla floret_orders ya existe'));

await pool.query(`
  CREATE TABLE IF NOT EXISTS floret_order_items (
    id SERIAL PRIMARY KEY,
    order_id INTEGER NOT NULL REFERENCES floret_orders(id) ON DELETE CASCADE,
    product_id INTEGER REFERENCES floret_products(id) ON DELETE SET NULL,
    product_name VARCHAR(200) NOT NULL,
    unit_price DECIMAL(12,2) NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 1,
    size VARCHAR(32),
    line_total DECIMAL(12,2) NOT NULL DEFAULT 0
  )
`).catch(() => console.log('Tabla floret_order_items ya existe'));


await pool.query(`CREATE INDEX IF NOT EXISTS idx_floret_product_reviews_product ON floret_product_reviews(product_id, created_at DESC)`).catch(() => { });
await pool.query(`CREATE INDEX IF NOT EXISTS idx_floret_seller_reviews_email ON floret_seller_reviews(seller_email, created_at DESC)`).catch(() => { });
await pool.query(`CREATE INDEX IF NOT EXISTS idx_floret_notifications_target ON floret_notifications(target_user_id, created_at DESC)`).catch(() => { });
await pool.query(`CREATE INDEX IF NOT EXISTS idx_floret_notifications_email ON floret_notifications(target_email, created_at DESC)`).catch(() => { });
await pool.query(`CREATE INDEX IF NOT EXISTS idx_floret_notifications_order ON floret_notifications(order_id, created_at DESC)`).catch(() => { });
await pool.query(`CREATE INDEX IF NOT EXISTS idx_floret_orders_created ON floret_orders(created_at DESC)`).catch(() => { });
await pool.query(`CREATE INDEX IF NOT EXISTS idx_floret_orders_status ON floret_orders(status, created_at DESC)`).catch(() => { });
await pool.query(`CREATE INDEX IF NOT EXISTS idx_floret_order_items_order ON floret_order_items(order_id, id ASC)`).catch(() => { });

await pool.query(`
  CREATE TABLE IF NOT EXISTS floret_admin_quotas (
    id SERIAL PRIMARY KEY,
    user_id INTEGER UNIQUE REFERENCES floret_users(id) ON DELETE CASCADE,
    uploads_today INTEGER DEFAULT 0,
    max_daily INTEGER DEFAULT 4,
    last_upload_time TIMESTAMP,
    cycle_active BOOLEAN DEFAULT FALSE
  )
`).catch(() => console.log('Ã¢Å¡Â Ã¯Â¸Â Tabla floret_admin_quotas ya existe'));

// Ensure Malevo and OceanandWild are set up correctly if they exist
try {
  await pool.query(`
    UPDATE floret_users SET is_admin = true, power_level = 2 WHERE LOWER(COALESCE(username, '')) = 'oceanandwild';
    UPDATE floret_users SET is_admin = true, power_level = 1 WHERE LOWER(COALESCE(username, '')) = 'malevo' OR LOWER(COALESCE(email, '')) = 'karatedojor@gmail.com';
  `);
} catch (e) {
  console.log('Ã¢Å¡Â Ã¯Â¸Â Error updating floret admin roles:', e.message);
}

console.log('Ã°Å¸Å’Â¸ Tablas de Floret Shop verificadas');

// ==========================================
// OCEAN PAY - NEW FEATURES (POS, CARDS, STATS)
// ==========================================

// Ensure tables for Ocean Pay stats and POS if not exist
// Ensure tables for Ocean Pay stats, POS, and Subscriptions
async function ensureOceanPayTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ocean_pay_pos (
      id SERIAL PRIMARY KEY,
      code VARCHAR(10) UNIQUE NOT NULL,
      sender_id INTEGER NOT NULL REFERENCES ocean_pay_users(id) ON DELETE CASCADE,
      sender_card_id INTEGER REFERENCES ocean_pay_cards(id) ON DELETE CASCADE,
      receiver_id INTEGER REFERENCES ocean_pay_users(id) ON DELETE CASCADE,
      receiver_card_id INTEGER REFERENCES ocean_pay_cards(id) ON DELETE CASCADE,
      amount DECIMAL(20, 2) NOT NULL,
      currency VARCHAR(50) NOT NULL,
      status VARCHAR(20) DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT NOW(),
      completed_at TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS ocean_pay_subscriptions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES ocean_pay_users(id) ON DELETE CASCADE,
      card_id INTEGER REFERENCES ocean_pay_cards(id) ON DELETE CASCADE,
      project_id VARCHAR(50),
      plan_name VARCHAR(50),
      price DECIMAL(20, 2) NOT NULL,
      currency VARCHAR(50) DEFAULT 'wildgems',
      status VARCHAR(20) DEFAULT 'active',
      start_date TIMESTAMP DEFAULT NOW(),
      end_date TIMESTAMP,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `).catch(e => console.log('Ã¢Å¡Â Ã¯Â¸Â Error base:', e.message));

  // Migraciones rÃƒÂ¡pidas para asegurar columnas nuevas y flexibilizar antiguas
  await pool.query(`
    ALTER TABLE ocean_pay_subscriptions ADD COLUMN IF NOT EXISTS plan_name VARCHAR(50);
    ALTER TABLE ocean_pay_subscriptions ADD COLUMN IF NOT EXISTS end_date TIMESTAMP;
    ALTER TABLE ocean_pay_subscriptions ALTER COLUMN card_id DROP NOT NULL;
    ALTER TABLE ocean_pay_subscriptions ALTER COLUMN project_id DROP NOT NULL;
    ALTER TABLE ocean_pay_subscriptions ALTER COLUMN sub_name DROP NOT NULL;
    ALTER TABLE ocean_pay_subscriptions ALTER COLUMN next_payment DROP NOT NULL;
    ALTER TABLE ocean_pay_subscriptions ALTER COLUMN next_payment SET DEFAULT NOW();
  `).catch((e) => console.log('Ã¢Å¡Â Ã¯Â¸Â Error migraciÃƒÂ³n:', e.message));

  await pool.query(`
    CREATE TABLE IF NOT EXISTS ocean_pay_notifications (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES ocean_pay_users(id) ON DELETE CASCADE,
        type VARCHAR(20) NOT NULL, -- 'success', 'error', 'info', 'warning'
        title VARCHAR(100) NOT NULL,
        message TEXT,
        is_read BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT NOW()
    );
  `).catch(e => console.log('Ã¢Å¡Â Ã¯Â¸Â Error notificaciones:', e.message));

  await pool.query(`
    CREATE TABLE IF NOT EXISTS tiger_tasks_reward_claims (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES ocean_pay_users(id) ON DELETE CASCADE,
      claim_type VARCHAR(40) NOT NULL,
      claim_key VARCHAR(120) NOT NULL,
      amount INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW(),
      UNIQUE(user_id, claim_type, claim_key)
    );
  `).catch(e => console.log('Ã¢Å¡Â Ã¯Â¸Â Error tiger_tasks_reward_claims:', e.message));

  await pool.query(`
    CREATE TABLE IF NOT EXISTS tiger_tasks_users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(60) UNIQUE NOT NULL,
      pwd_hash TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `).catch(e => console.log('Ã¢Å¡Â Ã¯Â¸Â Error tiger_tasks_users:', e.message));

  await pool.query(`
    CREATE TABLE IF NOT EXISTS tiger_tasks_oceanpay_links (
      id SERIAL PRIMARY KEY,
      tiger_user_id INTEGER NOT NULL UNIQUE REFERENCES tiger_tasks_users(id) ON DELETE CASCADE,
      ocean_pay_user_id INTEGER NOT NULL REFERENCES ocean_pay_users(id) ON DELETE CASCADE,
      linked_at TIMESTAMP DEFAULT NOW()
    );
  `).catch(e => console.log('Ã¢Å¡Â Ã¯Â¸Â Error tiger_tasks_oceanpay_links:', e.message));
}
await ensureOceanPayTables();
cancelLegacyWildTransferSubscriptions()
  .then((result) => {
    if (Number(result?.migrated || 0) > 0) {
      console.log(`Ã¢Å“â€¦ WildTransfer migration: ${result.migrated} suscripciones legacy canceladas (RelayShards).`);
    } else {
      console.log('Ã¢â€žÂ¹Ã¯Â¸Â WildTransfer migration: sin suscripciones legacy para cancelar.');
    }
  })
  .catch((err) => {
    console.error('Ã¢Å¡Â Ã¯Â¸Â WildTransfer migration error:', err.message);
  });

const POS_EXCHANGE_RATES = {
  wildgems: { aquabux: 10, ecoxionums: 50, ecorebits: 100, ecocorebits: 100, wildcredits: 5, nxb: 2 },
  nxb: { amber: 25, ecotokens: 5, appbux: 15, wildcredits: 10, aquabux: 5 }
};

function normalizePosCurrency(value) {
  const key = String(value || '').trim().toLowerCase();
  if (!key) return '';
  if (key === 'ecobits' || key === 'ecorebits') return 'ecocorebits';
  if (key === 'voltbit') return 'voltbits';
  return key;
}

function resolvePosExchangeAmount(amount, fromCurrency, targetCurrency) {
  const safeAmount = Number(amount || 0);
  if (!Number.isFinite(safeAmount) || safeAmount <= 0) return 0;
  const from = normalizePosCurrency(fromCurrency);
  const target = normalizePosCurrency(targetCurrency);
  const rate = Number(POS_EXCHANGE_RATES[target]?.[from] || 1);
  return Math.floor(safeAmount * (Number.isFinite(rate) && rate > 0 ? rate : 1));
}

// POS Virtual: crear cobro
app.post('/pos/create', async (req, res) => {
  const client = await pool.connect();
  try {
    const userId = Number(req.body?.userId);
    const cardId = Number(req.body?.cardId);
    const amount = Number(req.body?.amount);
    const currency = normalizePosCurrency(req.body?.currency || 'aquabux');
    const isExchange = Boolean(req.body?.isExchange || false);
    const targetCurrency = normalizePosCurrency(req.body?.targetCurrency || '');

    if (!Number.isFinite(userId) || userId <= 0) return res.status(400).json({ success: false, error: 'Usuario inválido' });
    if (!Number.isFinite(cardId) || cardId <= 0) return res.status(400).json({ success: false, error: 'Tarjeta inválida' });
    if (!Number.isFinite(amount) || amount <= 0) return res.status(400).json({ success: false, error: 'Monto inválido' });
    if (!currency) return res.status(400).json({ success: false, error: 'Divisa inválida' });

    await client.query('BEGIN');

    const { rows: cardRows } = await client.query(
      'SELECT id, user_id FROM ocean_pay_cards WHERE id = $1 AND user_id = $2 LIMIT 1',
      [cardId, userId]
    );
    if (!cardRows.length) {
      await client.query('ROLLBACK');
      return res.status(403).json({ success: false, error: 'Tarjeta no válida para este usuario' });
    }

    const currentBalance = await getUnifiedCardCurrencyBalance(client, cardId, currency, true);
    if (currentBalance < amount) {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, error: 'Fondos insuficientes en la tarjeta seleccionada' });
    }

    const code = Math.random().toString(36).slice(2, 8).toUpperCase();
    const safeTargetCurrency = isExchange ? (targetCurrency || 'wildgems') : null;

    const { rows: inserted } = await client.query(
      `INSERT INTO ocean_pay_pos (code, sender_id, sender_card_id, amount, currency, status, is_exchange, target_currency)
       VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7)
       RETURNING id, code, sender_id, sender_card_id, amount, currency, status, is_exchange, target_currency, created_at`,
      [code, userId, cardId, amount, currency, isExchange, safeTargetCurrency]
    );

    await client.query('COMMIT');
    return res.json({ success: true, pos: inserted[0] });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error en POST /pos/create:', err);
    return res.status(500).json({ success: false, error: 'Error interno al crear código POS' });
  } finally {
    client.release();
  }
});

// Catalogo de recargas Tides (Moneda premium)
app.get(['/ocean-pay/tides/packages', '/ocean-pay/aurex/packages'], async (_req, res) => {
  return res.json({
    success: true,
    currency: 'tides',
    packages: AUREX_PACKAGES
  });
});

// Crear checkout de Mercado Pago para recarga Tides
app.post(['/ocean-pay/tides/checkout', '/ocean-pay/aurex/checkout'], async (req, res) => {
  const userId = getAuthenticatedOceanPayUserId(req);
  if (!userId) return res.status(401).json({ error: 'Token invalido' });

  const packageId = String(req.body?.packageId || '').trim().toLowerCase();
  const pkg = getAurexPackageById(packageId);
  if (!pkg) return res.status(400).json({ error: 'Paquete Tides invalido' });

  const rawReturnUrl = String(req.body?.returnUrl || '').trim();
  const safeReturnUrl = /^https?:\/\//i.test(rawReturnUrl)
    ? rawReturnUrl
    : 'https://owsdatabase.onrender.com';

  try {
    const externalReference = `op-tides:${userId}:${pkg.id}:${Date.now()}`;
    const preference = new Preference(mpClient);
    const result = await preference.create({
      body: {
        external_reference: externalReference,
        statement_descriptor: 'OCEANWILD',
        items: [
          {
            title: `Ocean Pay - ${pkg.title}`,
            quantity: 1,
            unit_price: Number(pkg.priceUyu),
            currency_id: 'UYU'
          }
        ],
        back_urls: {
          success: safeReturnUrl,
          failure: safeReturnUrl,
          pending: safeReturnUrl
        },
        auto_return: 'approved'
      }
    });

    return res.json({
      success: true,
      package: pkg,
      externalReference,
      preferenceId: result?.id || null,
      initPoint: result?.init_point || result?.sandbox_init_point || null
    });
  } catch (err) {
    console.error('Error en POST /ocean-pay/tides/checkout:', err);
    return res.status(500).json({ error: 'No se pudo iniciar el checkout de Tides' });
  }
});

// Confirmar pago aprobado de Mercado Pago y acreditar Tides
app.post(['/ocean-pay/tides/confirm', '/ocean-pay/aurex/confirm'], async (req, res) => {
  const userId = getAuthenticatedOceanPayUserId(req);
  if (!userId) return res.status(401).json({ error: 'Token invalido' });

  const paymentId = Number(req.body?.paymentId || 0);
  const externalReference = String(req.body?.externalReference || '').trim();
  if (!paymentId || !externalReference) {
    return res.status(400).json({ error: 'paymentId y externalReference son requeridos' });
  }

  if (!externalReference.startsWith(`op-tides:${userId}:`) && !externalReference.startsWith(`op-aurex:${userId}:`)) {
    return res.status(403).json({ error: 'externalReference no coincide con el usuario autenticado' });
  }

  const segments = externalReference.split(':');
  const packageId = String(segments[2] || '').trim().toLowerCase();
  const pkg = getAurexPackageById(packageId);
  if (!pkg) return res.status(400).json({ error: 'Paquete de Tides no reconocido' });

  try {
    const mpResp = await fetch(`https://api.mercadopago.com/v1/payments/${paymentId}`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${MP_ACCESS_TOKEN}` }
    });
    const paymentData = await mpResp.json().catch(() => ({}));
    if (!mpResp.ok) {
      return res.status(400).json({ error: 'No se pudo validar el pago en Mercado Pago', details: paymentData?.message || null });
    }
    if (String(paymentData?.status || '').toLowerCase() !== 'approved') {
      return res.status(400).json({ error: 'El pago aun no figura como aprobado', status: paymentData?.status || 'unknown' });
    }
    if (String(paymentData?.external_reference || '') !== externalReference) {
      return res.status(400).json({ error: 'El pago validado no corresponde a esta orden' });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const creditConcept = `Tides Pack ${pkg.id} - payment:${paymentId} - ref:${externalReference}`;
      const { rows: existingTx } = await client.query(
        `SELECT id FROM ocean_pay_txs
          WHERE user_id = $1
            AND origen = 'Mercado Pago Tides'
            AND concepto = $2
          LIMIT 1`,
        [userId, creditConcept]
      );

      if (existingTx.length) {
        const currentBalance = await getUnifiedBalance(client, userId, 'tides');
        await client.query('COMMIT');
        return res.json({
          success: true,
          alreadyApplied: true,
          credited: 0,
          package: pkg,
          newBalance: currentBalance
        });
      }

      const currentBalance = await getUnifiedBalance(client, userId, 'tides');
      const credited = Number(pkg.tidesAmount || 0) + Number(pkg.bonus || 0);
      const newBalance = currentBalance + credited;
      await setUnifiedBalance(client, userId, 'tides', newBalance);

      await client.query(
        `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
         VALUES ($1, $2, $3, $4, $5)`,
        [userId, creditConcept, credited, 'Mercado Pago Tides', 'tides']
      );

      await client.query('COMMIT');
      return res.json({
        success: true,
        credited,
        package: pkg,
        newBalance
      });
    } catch (err) {
      await client.query('ROLLBACK');
      console.error('Error interno en confirmacion Tides:', err);
      return res.status(500).json({ error: 'No se pudo acreditar Tides' });
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('Error en POST /ocean-pay/tides/confirm:', err);
    return res.status(500).json({ error: 'Error interno al confirmar compra Tides' });
  }
});

// Meta Global activa (via API, no hardcodeada)
app.get('/ocean-pay/global-goal/current', async (req, res) => {
  const userId = getAuthenticatedOceanPayUserId(req);
  if (!userId) return res.status(401).json({ error: 'Token invalido' });

  const client = await pool.connect();
  try {
    const goal = await getActiveGlobalGoal(client);
    if (!goal) {
      return res.json({ success: true, goal: null, canClaim: false });
    }

    const progress = await computeGlobalGoalProgress(client, goal);
    const target = Number(goal.target_amount || 0);
    const progressPct = target > 0 ? Math.min(100, (progress / target) * 100) : 0;
    const completed = target > 0 && progress >= target;
    const eligibleCurrencies = parseGoalCurrencies(goal.eligible_currencies);

    const { rows: claimRows } = await client.query(
      `SELECT 1 FROM ocean_pay_global_goal_claims
        WHERE goal_id = $1 AND user_id = $2
        LIMIT 1`,
      [goal.id, userId]
    );

    return res.json({
      success: true,
      goal: {
        id: goal.id,
        slug: goal.slug,
        title: goal.title,
        description: goal.description || '',
        goalType: goal.goal_type,
        targetAmount: target,
        progressAmount: progress,
        progressPct,
        rewardCurrency: String(goal.reward_currency || 'tides').toLowerCase(),
        rewardAmount: Number(goal.reward_amount || 0),
        eligibleCurrencies,
        startsAt: goal.starts_at,
        endsAt: goal.ends_at
      },
      completed,
      alreadyClaimed: claimRows.length > 0,
      canClaim: completed && claimRows.length === 0
    });
  } catch (err) {
    console.error('Error en GET /ocean-pay/global-goal/current:', err);
    return res.status(500).json({ error: 'No se pudo consultar la meta global' });
  } finally {
    client.release();
  }
});

// Reclamar recompensa de Meta Global
app.post('/ocean-pay/global-goal/claim', async (req, res) => {
  const userId = getAuthenticatedOceanPayUserId(req);
  if (!userId) return res.status(401).json({ error: 'Token invalido' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const goal = await getActiveGlobalGoal(client);
    if (!goal) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'No hay meta global activa en este momento' });
    }

    const progress = await computeGlobalGoalProgress(client, goal);
    const target = Number(goal.target_amount || 0);
    if (!(target > 0 && progress >= target)) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'La meta global aun no fue completada' });
    }

    const { rows: claimedRows } = await client.query(
      `SELECT 1 FROM ocean_pay_global_goal_claims
        WHERE goal_id = $1 AND user_id = $2
        FOR UPDATE`,
      [goal.id, userId]
    );
    if (claimedRows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Ya reclamaste esta meta global' });
    }

    const rewardCurrency = String(goal.reward_currency || 'tides').toLowerCase();
    const rewardAmount = Math.max(0, Number(goal.reward_amount || 0));
    const currentRewardBalance = await getUnifiedBalance(client, userId, rewardCurrency);
    const newBalance = currentRewardBalance + rewardAmount;
    await setUnifiedBalance(client, userId, rewardCurrency, newBalance);

    await client.query(
      `INSERT INTO ocean_pay_global_goal_claims (goal_id, user_id)
       VALUES ($1, $2)`,
      [goal.id, userId]
    );

    await client.query(
      `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
       VALUES ($1, $2, $3, $4, $5)`,
      [userId, `Meta Global completada: ${goal.title}`, rewardAmount, 'Global Goal Reward', rewardCurrency]
    );

    await client.query('COMMIT');
    return res.json({
      success: true,
      goalId: goal.id,
      rewardCurrency,
      reward: rewardAmount,
      newBalance
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error en POST /ocean-pay/global-goal/claim:', err);
    return res.status(500).json({ error: 'No se pudo reclamar la recompensa de meta global' });
  } finally {
    client.release();
  }
});

// Admin: crear/actualizar Meta Global via API (no hardcode)
app.post('/ocean-pay/admin/global-goal/upsert', async (req, res) => {
  if (!requireOwsStoreAdmin(req, res)) return;
  const client = await pool.connect();
  try {
    await ensureOceanPayGlobalGoalTables(client);
    const slug = String(req.body?.slug || 'meta-global-tides-176k').trim().toLowerCase();
    const title = String(req.body?.title || 'Meta Global: Marea 176K').trim();
    const description = String(req.body?.description || '').trim();
    const goalType = String(req.body?.goalType || req.body?.goal_type || 'spend').trim().toLowerCase();
    const targetAmount = Math.max(1, Number(req.body?.targetAmount || req.body?.target_amount || 176000));
    const rewardAmount = Math.max(0, Number(req.body?.rewardAmount || req.body?.reward_amount || 45));
    const rewardCurrency = String(req.body?.rewardCurrency || req.body?.reward_currency || 'tides').trim().toLowerCase();
    const eligibleCurrencies = normalizeGoalCurrencies(req.body?.eligibleCurrencies || req.body?.eligible_currencies || ['aquabux', 'wildgems']).join(',');
    const status = String(req.body?.status || 'active').trim().toLowerCase();
    const startsAt = req.body?.startsAt || req.body?.starts_at || null;
    const endsAt = req.body?.endsAt || req.body?.ends_at || null;

    if (!slug || !title) return res.status(400).json({ error: 'slug y title son requeridos' });
    if (!['spend', 'earn'].includes(goalType)) return res.status(400).json({ error: 'goalType debe ser spend o earn' });
    if (!eligibleCurrencies) return res.status(400).json({ error: 'eligibleCurrencies es requerido' });
    if (!UNIFIED_WALLET_CURRENCIES.includes(rewardCurrency)) {
      return res.status(400).json({ error: 'rewardCurrency no es valido' });
    }

    const { rows } = await client.query(
      `INSERT INTO ocean_pay_global_goals
       (slug, title, description, goal_type, target_amount, reward_currency, reward_amount, eligible_currencies, status, starts_at, ends_at, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,COALESCE($10::timestamp, NOW()),$11::timestamp,NOW())
       ON CONFLICT (slug) DO UPDATE SET
         title = EXCLUDED.title,
         description = EXCLUDED.description,
         goal_type = EXCLUDED.goal_type,
         target_amount = EXCLUDED.target_amount,
         reward_currency = EXCLUDED.reward_currency,
         reward_amount = EXCLUDED.reward_amount,
         eligible_currencies = EXCLUDED.eligible_currencies,
         status = EXCLUDED.status,
         starts_at = EXCLUDED.starts_at,
         ends_at = EXCLUDED.ends_at,
         updated_at = NOW()
       RETURNING *`,
      [slug, title, description, goalType, targetAmount, rewardCurrency, rewardAmount, eligibleCurrencies, status, startsAt, endsAt]
    );

    return res.json({
      success: true,
      goal: rows[0] || null
    });
  } catch (err) {
    console.error('Error en POST /ocean-pay/admin/global-goal/upsert:', err);
    return res.status(500).json({ error: 'No se pudo guardar la meta global' });
  } finally {
    client.release();
  }
});

// POS Virtual: swaps pendientes (compat)
app.get(['/pos/pending-swaps/:userId', '/ocean-pay/pos/pending-swaps/:userId'], async (req, res) => {
  try {
    const userId = Number(req.params.userId);
    if (!Number.isFinite(userId) || userId <= 0) {
      return res.status(400).json({ success: false, error: 'Usuario inválido' });
    }

    const { rows } = await pool.query(
      `SELECT p.code, p.amount, p.currency, p.target_currency, p.created_at, c.card_name
         FROM ocean_pay_pos p
         LEFT JOIN ocean_pay_cards c ON c.id = p.sender_card_id
        WHERE p.sender_id = $1
          AND p.status = 'pending'
          AND COALESCE(p.is_exchange, false) = true
        ORDER BY p.created_at DESC`,
      [userId]
    );

    return res.json({ success: true, swaps: rows });
  } catch (err) {
    console.error('Error en GET /pos/pending-swaps/:userId:', err);
    return res.status(500).json({ success: false, error: 'Error interno al cargar intercambios pendientes' });
  }
});

// POS Virtual: consultar código
app.get('/pos/:code', async (req, res) => {
  try {
    const code = String(req.params.code || '').trim().toUpperCase();
    if (!code) return res.status(400).json({ success: false, error: 'Código inválido' });

    const { rows } = await pool.query(
      `SELECT p.*, u.username AS sender_name
         FROM ocean_pay_pos p
         LEFT JOIN ocean_pay_users u ON u.id = p.sender_id
        WHERE p.code = $1
        LIMIT 1`,
      [code]
    );

    if (!rows.length) return res.status(404).json({ success: false, error: 'Código no encontrado' });
    const pos = rows[0];
    if (String(pos.status || '').toLowerCase() !== 'pending') {
      return res.status(400).json({ success: false, error: 'Este código ya fue utilizado o cancelado' });
    }

    return res.json({
      success: true,
      pos: {
        code: pos.code,
        amount: Number(pos.amount || 0),
        currency: normalizePosCurrency(pos.currency),
        sender_name: pos.sender_name || 'Usuario',
        is_exchange: Boolean(pos.is_exchange),
        target_currency: normalizePosCurrency(pos.target_currency || '')
      }
    });
  } catch (err) {
    console.error('Error en GET /pos/:code:', err);
    return res.status(500).json({ success: false, error: 'Error interno al consultar código POS' });
  }
});

// POS Virtual: completar cobro/intercambio
app.post('/pos/complete', async (req, res) => {
  const client = await pool.connect();
  try {
    const code = String(req.body?.code || '').trim().toUpperCase();
    const receiverId = Number(req.body?.receiverId);
    const receiverCardId = Number(req.body?.receiverCardId || 0);

    if (!code) return res.status(400).json({ success: false, error: 'Código inválido' });
    if (!Number.isFinite(receiverId) || receiverId <= 0) {
      return res.status(400).json({ success: false, error: 'Receptor inválido' });
    }

    await client.query('BEGIN');

    const { rows } = await client.query(
      `SELECT *
         FROM ocean_pay_pos
        WHERE code = $1
        LIMIT 1
        FOR UPDATE`,
      [code]
    );
    if (!rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ success: false, error: 'Código POS no encontrado' });
    }

    const pos = rows[0];
    if (String(pos.status || '').toLowerCase() !== 'pending') {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, error: 'Este código ya no está disponible' });
    }

    const senderId = Number(pos.sender_id);
    const senderCardId = Number(pos.sender_card_id);
    const amount = Number(pos.amount || 0);
    const currency = normalizePosCurrency(pos.currency);
    const isExchange = Boolean(pos.is_exchange);

    if (!Number.isFinite(senderId) || !Number.isFinite(senderCardId) || amount <= 0 || !currency) {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, error: 'Transacción POS inválida' });
    }

    const senderBalance = await getUnifiedCardCurrencyBalance(client, senderCardId, currency, true);
    if (senderBalance < amount) {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, error: 'Fondos insuficientes en la tarjeta de origen' });
    }

    if (isExchange) {
      if (receiverId !== senderId) {
        await client.query('ROLLBACK');
        return res.status(403).json({ success: false, error: 'Intercambio no autorizado para este usuario' });
      }

      const targetCurrency = normalizePosCurrency(pos.target_currency || 'wildgems');
      const targetAmount = resolvePosExchangeAmount(amount, currency, targetCurrency);
      const destinationCardId = Number.isFinite(receiverCardId) && receiverCardId > 0 ? receiverCardId : senderCardId;

      const { rows: ownCard } = await client.query(
        'SELECT id FROM ocean_pay_cards WHERE id = $1 AND user_id = $2 LIMIT 1',
        [destinationCardId, senderId]
      );
      if (!ownCard.length) {
        await client.query('ROLLBACK');
        return res.status(403).json({ success: false, error: 'Tarjeta destino inválida para el intercambio' });
      }

      await setUnifiedCardCurrencyBalance(client, {
        userId: senderId,
        cardId: senderCardId,
        currency,
        newBalance: senderBalance - amount
      });

      const currentTargetBalance = await getUnifiedCardCurrencyBalance(client, destinationCardId, targetCurrency, true);
      await setUnifiedCardCurrencyBalance(client, {
        userId: senderId,
        cardId: destinationCardId,
        currency: targetCurrency,
        newBalance: currentTargetBalance + targetAmount
      });

      await client.query(
        `UPDATE ocean_pay_pos
            SET status = 'completed',
                receiver_id = $1,
                receiver_card_id = $2,
                completed_at = NOW()
          WHERE id = $3`,
        [senderId, destinationCardId, pos.id]
      );
    } else {
      if (!Number.isFinite(receiverCardId) || receiverCardId <= 0) {
        await client.query('ROLLBACK');
        return res.status(400).json({ success: false, error: 'Selecciona una tarjeta destino válida' });
      }

      const { rows: receiverCardRows } = await client.query(
        'SELECT id FROM ocean_pay_cards WHERE id = $1 AND user_id = $2 LIMIT 1',
        [receiverCardId, receiverId]
      );
      if (!receiverCardRows.length) {
        await client.query('ROLLBACK');
        return res.status(403).json({ success: false, error: 'La tarjeta destino no pertenece al receptor' });
      }

      await setUnifiedCardCurrencyBalance(client, {
        userId: senderId,
        cardId: senderCardId,
        currency,
        newBalance: senderBalance - amount
      });

      const receiverBalance = await getUnifiedCardCurrencyBalance(client, receiverCardId, currency, true);
      await setUnifiedCardCurrencyBalance(client, {
        userId: receiverId,
        cardId: receiverCardId,
        currency,
        newBalance: receiverBalance + amount
      });

      await client.query(
        `UPDATE ocean_pay_pos
            SET status = 'completed',
                receiver_id = $1,
                receiver_card_id = $2,
                completed_at = NOW()
          WHERE id = $3`,
        [receiverId, receiverCardId, pos.id]
      );
    }

    await client.query('COMMIT');
    return res.json({ success: true });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error en POST /pos/complete:', err);
    return res.status(500).json({ success: false, error: 'Error interno al completar transacción POS' });
  } finally {
    client.release();
  }
});

// Subscriptions Endpoints
app.get('/ocean-pay/subscriptions/me', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
    const token = authHeader.startsWith('Bearer ') ? authHeader.substring(7) : authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    const userId = Number(decoded.id || decoded.uid || decoded.sub);
    if (!Number.isFinite(userId) || userId <= 0) return res.status(401).json({ error: 'Token invÃ¡lido' });

    const { rows } = await pool.query(
      `SELECT *
       FROM ocean_pay_subscriptions
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [userId]
    );

    const mapped = rows.map((s) => {
      const planName = s.plan_name || s.sub_name || 'Plan';
      const renewAt = s.next_payment || s.end_date || null;
      const endsAt = s.end_date || s.next_payment || s.created_at || null;
      const status = String(s.status || 'active').toLowerCase();
      const nowTs = Date.now();
      const endsTs = endsAt ? new Date(endsAt).getTime() : 0;
      const isActive = status === 'active' && (!endsTs || endsTs > nowTs);
      return {
        ...s,
        plan_name: planName,
        end_date: endsAt,
        renew_at: renewAt,
        is_active: isActive,
        platform_scope: String(s.project_id || '').toLowerCase() === 'ecoxion' ? 'ecoxion' : 'general'
      };
    });

    res.json(mapped);
  } catch (e) {
    console.error('Error suscripciones:', e);
    if (e.name === 'TokenExpiredError') return res.status(401).json({ error: 'Token expirado' });
    res.status(500).json({ error: e.message || 'Error al cargar suscripciones' });
  }
});


// Endpoint: Get Notifications
app.get('/ocean-pay/notifications', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    const userId = decoded.id || (decoded.id || decoded.uid);

    const { rows } = await pool.query(
      'SELECT * FROM ocean_pay_notifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50',
      [userId]
    );
    res.json(rows);
  } catch (e) {
    if (e.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expirado' });
    }
    res.status(500).json({ error: e.message });
  }
});

// Helper to create notification (Internal)
async function createNotification(userId, type, title, message) {
  try {
    const client = await pool.connect(); // Use a fresh client or pool directly
    await client.query(
      'INSERT INTO ocean_pay_notifications (user_id, type, title, message) VALUES ($1, $2, $3, $4)',
      [userId, type, title, message]
    );
    client.release();
  } catch (e) {
    console.error('Error creating notification:', e);
  }
}

// Notificar usuarios Ocean Pay que aun no vincularon proyectos clave (evita duplicados diarios).
async function notifyUnlinkedUsers() {
  const client = await pool.connect();
  try {
    const { rowCount } = await client.query(`
      INSERT INTO ocean_pay_notifications (user_id, type, title, message)
      SELECT
        u.id,
        'link_reminder',
        'Vincula tus proyectos',
        'Conecta Ocean Pay con tus apps del ecosistema para sincronizar saldo, progreso y suscripciones.'
      FROM ocean_pay_users u
      WHERE NOT EXISTS (
        SELECT 1
        FROM oceanic_ethernet_user_links l
        WHERE l.external_system = 'ocean_pay'
          AND l.external_user_id = u.id::text
      )
      AND NOT EXISTS (
        SELECT 1
        FROM wildx_oceanpay_links w
        WHERE w.ocean_pay_user_id = u.id
      )
      AND NOT EXISTS (
        SELECT 1
        FROM ocean_pay_notifications n
        WHERE n.user_id = u.id
          AND n.type = 'link_reminder'
          AND n.created_at >= NOW() - INTERVAL '24 hours'
      )
    `);
    console.log(`[INIT] notifyUnlinkedUsers completado. Notificaciones nuevas: ${Number(rowCount || 0)}.`);
    return Number(rowCount || 0);
  } catch (err) {
    console.error('[INIT] Error en notifyUnlinkedUsers:', err.message || err);
    return 0;
  } finally {
    client.release();
  }
}

// Sync Ecoxionums from Client (Ecoxion App)
app.post('/ocean-pay/sync-ecoxionums', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    const userId = Number(decoded.id || (decoded.id || decoded.uid));
    const amount = Number(req.body?.amount || 0);

    if (!Number.isFinite(amount) || amount <= 0) {
      return res.json({ success: true, message: 'No amount to sync' });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const primaryCard = await getPrimaryCardForUser(client, userId, true);
      if (!primaryCard) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'No tienes una tarjeta principal activa en Ocean Pay.' });
      }

      const current = await getUnifiedCardCurrencyBalance(client, Number(primaryCard.id), ECOXION_CURRENCY, true);
      const newBalance = current + amount;

      await setUnifiedCardCurrencyBalance(client, {
        userId,
        cardId: Number(primaryCard.id),
        currency: ECOXION_CURRENCY,
        newBalance
      });

      await client.query(
        "INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda) VALUES ($1, $2, $3, $4, $5)",
        [userId, 'Sincronizacion Ecoxion (App)', amount, 'Ecoxion', ECOXION_CURRENCY]
      );

      await client.query('COMMIT');
      res.json({ success: true, newBalance });

    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});


app.post('/ocean-pay/subscriptions/purchase', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    const userId = (decoded.id || decoded.uid) || decoded.id;

    const { projectId, subName, price, currency, intervalDays, cardId } = req.body;
    const normalizedCurrency = String(currency || '').toLowerCase();
    const safePrice = Math.max(0, Number(price || 0));
    const safeCardId = Number(cardId);

    if (!projectId || !subName || !safePrice || !normalizedCurrency || !safeCardId) {
      return res.status(400).json({ error: 'Datos incompletos' });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Check balance and deduct
      const isMetadataCurrency = ['amber', 'ecotokens'].includes(normalizedCurrency);
      let current = 0;

      if (isMetadataCurrency) {
        const { rows: metaRows } = await client.query(
          "SELECT value FROM ocean_pay_metadata WHERE user_id = $1 AND key = $2 FOR UPDATE",
          [userId, normalizedCurrency]
        );
        current = parseInt(metaRows[0]?.value || '0');
        if (current < safePrice) {
          await client.query('ROLLBACK');
          return res.status(400).json({ error: `Saldo insuficiente de ${normalizedCurrency.toUpperCase()}` });
        }
        await client.query(
          "UPDATE ocean_pay_metadata SET value = $1 WHERE user_id = $2 AND key = $3",
          [(current - safePrice).toString(), userId, normalizedCurrency]
        );
      } else {
        const { rows: cardRows } = await client.query(
          'SELECT id FROM ocean_pay_cards WHERE id = $1 AND user_id = $2 LIMIT 1',
          [safeCardId, userId]
        );
        if (!cardRows.length) {
          await client.query('ROLLBACK');
          return res.status(403).json({ error: 'Tarjeta no valida' });
        }
        current = await getUnifiedCardCurrencyBalance(client, safeCardId, normalizedCurrency, true);
        if (current < safePrice) {
          await client.query('ROLLBACK');
          return res.status(400).json({ error: 'Saldo insuficiente en la tarjeta' });
        }
        await setUnifiedCardCurrencyBalance(client, {
          userId: Number(userId),
          cardId: safeCardId,
          currency: normalizedCurrency,
          newBalance: current - safePrice
        });
      }

      // Log TX
      await client.query(
        "INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda) VALUES ($1, $2, $3, $4, $5)",
        [userId, `SuscripciÃƒÂ³n: ${subName}`, -safePrice, projectId, normalizedCurrency]
      );

      // Save Sub
      const nextPayment = new Date();
      nextPayment.setDate(nextPayment.getDate() + (intervalDays || 7));

      const { rows: sub } = await client.query(`
        INSERT INTO ocean_pay_subscriptions (user_id, card_id, project_id, sub_name, plan_name, price, currency, interval_days, next_payment)
        VALUES ($1, $2, $3, $4, $4, $5, $6, $7, $8)
        RETURNING *
      `, [userId, safeCardId, projectId, subName, safePrice, normalizedCurrency, intervalDays || 7, nextPayment]);

      // If it's nature_pass or dinopass, update metadata for faster access
      if (subName === 'Nature-Pass') {
        await client.query(`
           INSERT INTO ocean_pay_metadata (user_id, key, value)
           VALUES ($1, 'nature_pass', 'true')
           ON CONFLICT (user_id, key) DO UPDATE SET value = 'true'
        `, [userId]);
      } else if (subName.includes('DinoPass')) {
        const type = subName.includes('Elite') ? 'elite' : 'premium';
        await client.query(`
           INSERT INTO ocean_pay_metadata (user_id, key, value)
           VALUES ($1, 'dinopass_type', $2)
           ON CONFLICT (user_id, key) DO UPDATE SET value = $2
        `, [userId, type]);
      }

      await client.query('COMMIT');
      res.json({ success: true, subscription: sub[0] });
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Auto-Renewal Worker
setInterval(async () => {
  const now = new Date();
  try {
    const { rows: dueSubs } = await pool.query(
      "SELECT * FROM ocean_pay_subscriptions WHERE status = 'active' AND next_payment <= $1",
      [now]
    );

    for (const sub of dueSubs) {
      const client = await pool.connect();
      const displayName = sub.plan_name || sub.sub_name || 'Plan';
      const currency = String(sub.currency || '').toLowerCase();
      const intervalDays = Number(sub.interval_days || 7);
      try {
        await client.query('BEGIN');

        if (!sub.card_id) {
          await client.query("UPDATE ocean_pay_subscriptions SET status = 'cancelled' WHERE id = $1", [sub.id]);
          await client.query('COMMIT');
          continue;
        }

        const current = await getUnifiedCardCurrencyBalance(client, Number(sub.card_id), currency, true);

        if (current >= Number(sub.price || 0)) {
          const newBal = current - Number(sub.price || 0);
          const nextDate = new Date();
          nextDate.setDate(nextDate.getDate() + intervalDays);

          await setUnifiedCardCurrencyBalance(client, {
            userId: Number(sub.user_id),
            cardId: Number(sub.card_id),
            currency,
            newBalance: newBal
          });

          await client.query(
            "UPDATE ocean_pay_subscriptions SET last_payment = NOW(), next_payment = $1, end_date = $1 WHERE id = $2",
            [nextDate, sub.id]
          );

          await client.query(
            "INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda) VALUES ($1, $2, $3, $4, $5)",
            [sub.user_id, `RenovaciÃ³n: ${displayName}`, -sub.price, sub.project_id, currency]
          );

          await createNotification(
            sub.user_id,
            'success',
            'SuscripciÃ³n Renovada',
            `Tu suscripciÃ³n a ${displayName} se renovÃ³ exitosamente por ${sub.price} ${currency}.`
          );

          console.log(`[SUBS] Renovado ${displayName} para usuario ${sub.user_id}`);
        } else {
          await client.query(
            "UPDATE ocean_pay_subscriptions SET status = 'cancelled', end_date = NOW() WHERE id = $1",
            [sub.id]
          );

          if (displayName === 'Nature-Pass') {
            await client.query("UPDATE ocean_pay_metadata SET value = 'false' WHERE user_id = $1 AND key = 'nature_pass'", [sub.user_id]);
          }

          await createNotification(
            sub.user_id,
            'error',
            'SuscripciÃ³n Cancelada',
            `No pudimos renovar tu ${displayName} por saldo insuficiente (${current} ${currency}). Tu suscripciÃ³n fue cancelada.`
          );

          console.log(`[SUBS] SuspensiÃ³n por falta de pago: ${displayName} (Usuario ${sub.user_id})`);
        }

        await client.query('COMMIT');
      } catch (e) {
        await client.query('ROLLBACK');
        console.error(`[SUBS] Error procesando renovaciÃ³n ${sub.id}:`, e.message);
      } finally {
        client.release();
      }
    }
  } catch (e) {
    console.error('[SUBS] Error en worker:', e.message);
  }
}, 3600000); // Cada 1 hora


// Rename card
app.patch('/ocean-pay/api/cards/:id/rename', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });

  let userId;
  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    userId = (decoded.id || decoded.uid) || decoded.id;
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }

  const { name } = req.body;
  const cardId = req.params.id;

  if (!name || name.trim() === '') {
    return res.status(400).json({ error: 'Nombre invÃƒÂ¡lido' });
  }

  try {
    const { rowCount } = await pool.query(
      'UPDATE ocean_pay_cards SET card_name = $1 WHERE id = $2 AND user_id = $3',
      [name.trim(), cardId, userId]
    );

    if (rowCount === 0) {
      return res.status(404).json({ error: 'Tarjeta no encontrada o no pertenece al usuario' });
    }

    res.json({ success: true, message: 'Tarjeta renombrada' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Transferir saldo entre propias tarjetas

// Transferir saldo entre propias tarjetas
app.post('/ocean-pay/api/transfer-self', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });

  let userId;
  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    if ((decoded.id || decoded.uid)) {
      userId = parseInt((decoded.id || decoded.uid));
    } else if (decoded.username || decoded.un) {
      const u = await pool.query('SELECT id FROM ocean_pay_users WHERE username=$1', [decoded.username || decoded.un]);
      if (u.rows.length) userId = u.rows[0].id;
    }
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }

  if (!userId) return res.status(404).json({ error: 'Usuario no encontrado' });

  const { sourceCardId, destCardId, currency, amount } = req.body;
  const amt = parseFloat(amount);

  if (!sourceCardId || !destCardId || !currency || amt <= 0) {
    return res.status(400).json({ error: 'Datos invÃƒÂ¡lidos' });
  }

  if (sourceCardId === destCardId) {
    return res.status(400).json({ error: 'Tarjetas deben ser diferentes' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Verificar propiedad de tarjetas
    const cardCheck = await client.query(
      'SELECT id, user_id FROM ocean_pay_cards WHERE id IN ($1, $2)',
      [sourceCardId, destCardId]
    );

    if (cardCheck.rows.length !== 2) return res.status(404).json({ error: 'Tarjetas no encontradas' });
    if (cardCheck.rows[0].user_id !== userId || cardCheck.rows[1].user_id !== userId) {
      return res.status(403).json({ error: 'No autorizado' });
    }

    // Verificar saldo origen
    const balRes = await client.query(
      'SELECT amount FROM ocean_pay_card_balances WHERE card_id = $1 AND currency_type = $2 FOR UPDATE',
      [sourceCardId, currency]
    );
    const currentBal = parseFloat(balRes.rows[0]?.amount || 0);

    if (currentBal < amt) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Saldo insuficiente' });
    }

    // Descontar
    await client.query(
      `INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount)
       VALUES ($1, $2, $3)
       ON CONFLICT (card_id, currency_type)
       DO UPDATE SET amount = ocean_pay_card_balances.amount + $3`,
      [sourceCardId, currency, -amt]
    );

    // Sumar
    await client.query(
      `INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount)
         VALUES ($1, $2, $3)
         ON CONFLICT (card_id, currency_type)
         DO UPDATE SET amount = ocean_pay_card_balances.amount + $3`,
      [destCardId, currency, amt]
    );

    // Generate internal transfer code
    const selfCode = 'SLF-' + Math.random().toString(36).substring(2, 7).toUpperCase();

    // Log transaction (Internal transfer)
    await client.query(
      `INSERT INTO ocean_pay_pos (code, sender_id, sender_card_id, receiver_id, receiver_card_id, amount, currency, status, completed_at)
         VALUES ($1, $2, $3, $2, $4, $5, $6, 'completed', NOW())`,
      [selfCode, userId, sourceCardId, destCardId, amt, currency]
    );

    await client.query('COMMIT');
    res.json({ success: true, message: 'Transferencia completada' });

  } catch (e) {
    await client.query('ROLLBACK');
    console.error(e);
    res.status(500).json({ error: 'Error del servidor' });
  } finally {
    client.release();
  }
});

// Eliminar tarjeta secundaria (Supports both paths for compatibility)
app.delete(['/ocean-pay/api/cards/:id', '/ocean-pay/cards/:id'], async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });

  // Debug Params
  const requestId = req.params.id;
  console.log(`[DELETE /ocean-pay/cards/${requestId}] Request received.`);

  let userId;
  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    if ((decoded.id || decoded.uid)) {
      userId = parseInt((decoded.id || decoded.uid));
    } else if (decoded.username || decoded.un) {
      const u = await pool.query('SELECT id FROM ocean_pay_users WHERE username=$1', [decoded.username || decoded.un]);
      if (u.rows.length) userId = u.rows[0].id;
    }
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }

  if (!userId) {
    console.log(`[DELETE /ocean-pay/cards/${requestId}] User not found.`);
    return res.status(404).json({ error: 'Usuario no encontrado' });
  }

  const cardId = parseInt(requestId);
  if (isNaN(cardId)) {
    console.log(`[DELETE /ocean-pay/cards/${requestId}] Invalid Card ID.`);
    return res.status(400).json({ error: 'ID de tarjeta invÃƒÂ¡lido' });
  }

  try {
    const cardRes = await pool.query('SELECT is_primary, user_id FROM ocean_pay_cards WHERE id = $1', [cardId]);
    if (!cardRes.rows.length) {
      console.log(`[DELETE /ocean-pay/cards/${requestId}] Card not found in DB.`);
      return res.status(404).json({ error: 'Tarjeta no encontrada' });
    }

    const card = cardRes.rows[0];
    if (card.user_id !== userId) {
      console.log(`[DELETE /ocean-pay/cards/${requestId}] Unauthorized access (User: ${userId}, Owner: ${card.user_id}).`);
      return res.status(403).json({ error: 'No autorizado' });
    }
    if (card.is_primary) {
      console.log(`[DELETE /ocean-pay/cards/${requestId}] Attempt to delete primary card.`);
      return res.status(400).json({ error: 'No puedes eliminar la tarjeta principal' });
    }

    await pool.query('DELETE FROM ocean_pay_cards WHERE id = $1', [cardId]);
    console.log(`[DELETE /ocean-pay/cards/${requestId}] Success.`);
    res.json({ success: true, message: 'Tarjeta eliminada' });
  } catch (e) {
    console.error(`[DELETE /ocean-pay/cards/${requestId}] Internal Error:`, e);
    res.status(500).json({ error: 'Error al eliminar tarjeta' });
  }
});

// Stats for charts: Ingresos y Gastos por divisa
app.get('/ocean-pay/api/stats/transactions', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });

  let userId;
  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    if ((decoded.id || decoded.uid)) {
      userId = parseInt((decoded.id || decoded.uid));
    } else if (decoded.username || decoded.un) {
      const u = await pool.query('SELECT id FROM ocean_pay_users WHERE username=$1', [decoded.username || decoded.un]);
      if (u.rows.length) userId = u.rows[0].id;
    }
  } catch (e) {
    return res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }

  if (!userId) return res.status(404).json({ error: 'Usuario no encontrado' });

  try {
    // 1. POS Data
    // Ingresos (POS): Recibido por mi (receiver_id = userId)
    const posIncomes = await pool.query(`
      SELECT currency, SUM(amount) as total
      FROM ocean_pay_pos
      WHERE receiver_id = $1 AND status = 'completed' AND sender_id != $1
      GROUP BY currency
    `, [userId]);

    // Gastos (POS): Enviado por mi (sender_id = userId)
    const posExpenses = await pool.query(`
      SELECT currency, SUM(amount) as total
      FROM ocean_pay_pos
      WHERE sender_id = $1 AND status = 'completed' AND receiver_id != $1
      GROUP BY currency
    `, [userId]);

    // 2. Legacy Data (ocean_pay_txs)
    let legacyStats = { rows: [] };
    try {
      legacyStats = await pool.query(`
          SELECT moneda as currency, SUM(monto) as total
          FROM ocean_pay_txs
          WHERE user_id = $1
          GROUP BY moneda
        `, [userId]);
    } catch (e) {
      console.warn('Legacy stats table missing or error');
    }

    // 3. EcoCore Transactions (ecocore_txs)
    let ecoStats = { rows: [] };
    try {
      // ecocore_txs usually uses TEXT userId. We cast consistent with other queries.
      // Also assuming currency is 'ecocorebits' if not specified.
      ecoStats = await pool.query(`
          SELECT SUM(monto) as total
          FROM ecocore_txs
          WHERE user_id = $1::text
        `, [userId]);
    } catch (e) {
      console.warn('EcoCore stats error', e.message);
    }

    const incomeMap = {};
    const expenseMap = {};

    const addToMap = (map, currency, amount) => {
      if (!amount) return;
      const c = (currency || 'unknown').toLowerCase();
      const val = parseFloat(amount);
      if (val === 0) return;
      map[c] = (map[c] || 0) + val;
    };

    posIncomes.rows.forEach(r => addToMap(incomeMap, r.currency, r.total));
    posExpenses.rows.forEach(r => addToMap(expenseMap, r.currency, r.total));

    // Legacy Merge
    legacyStats.rows.forEach(r => {
      const val = parseFloat(r.total);
      if (val >= 0) addToMap(incomeMap, r.currency, val);
      else addToMap(expenseMap, r.currency, Math.abs(val));
    });

    // EcoCore Merge
    if (ecoStats.rows.length > 0 && ecoStats.rows[0].total) {
      const val = parseFloat(ecoStats.rows[0].total);
      if (val >= 0) addToMap(incomeMap, 'ecocorebits', val);
      else addToMap(expenseMap, 'ecocorebits', Math.abs(val));
    }

    const incomes = Object.keys(incomeMap).map(k => ({ currency: k, total: incomeMap[k] }));
    const expenses = Object.keys(expenseMap).map(k => ({ currency: k, total: expenseMap[k] }));

    res.json({ incomes, expenses });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Error obteniendo estadisticas' });
  }
});

// Global analytics for Misc dashboard (all users, all projects)
app.get('/ocean-pay/api/stats/global-overview', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  try {
    const token = authHeader.substring(7);
    jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');

    const normalizeCurrency = (value) => {
      const key = String(value || '').toLowerCase().trim();
      if (!key) return 'unknown';
      if (key === 'ecorebits' || key === 'ecobits') return 'ecocorebits';
      if (key === 'voltbit') return 'voltbits';
      return key;
    };

    const [usersRes, txsRes, posRes, usageRes, flowRes, trendRes] = await Promise.all([
      pool.query('SELECT COUNT(*)::int AS total_users FROM ocean_pay_users'),
      pool.query('SELECT COUNT(*)::int AS total_txs FROM ocean_pay_txs'),
      pool.query(`
        SELECT
          COUNT(*) FILTER (WHERE status = 'completed')::int AS completed_pos,
          COUNT(*) FILTER (WHERE status = 'pending')::int AS pending_pos,
          COALESCE(SUM(amount) FILTER (WHERE status = 'completed'), 0)::numeric AS pos_completed_volume
        FROM ocean_pay_pos
      `),
      pool.query(`
        WITH tx_usage AS (
          SELECT LOWER(COALESCE(moneda, 'unknown')) AS currency, COUNT(*)::int AS ops
          FROM ocean_pay_txs
          GROUP BY 1
        ),
        pos_usage AS (
          SELECT LOWER(COALESCE(currency, 'unknown')) AS currency, COUNT(*)::int AS ops
          FROM ocean_pay_pos
          GROUP BY 1
        ),
        merged AS (
          SELECT currency, SUM(ops)::int AS total_ops
          FROM (
            SELECT * FROM tx_usage
            UNION ALL
            SELECT * FROM pos_usage
          ) x
          GROUP BY currency
        )
        SELECT currency, total_ops
        FROM merged
        ORDER BY total_ops DESC, currency ASC
      `),
      pool.query(`
        SELECT
          LOWER(COALESCE(moneda, 'unknown')) AS currency,
          COALESCE(SUM(CASE WHEN monto > 0 THEN monto ELSE 0 END), 0)::numeric AS incoming,
          COALESCE(SUM(CASE WHEN monto < 0 THEN ABS(monto) ELSE 0 END), 0)::numeric AS outgoing,
          COUNT(*)::int AS operations
        FROM ocean_pay_txs
        GROUP BY 1
        ORDER BY operations DESC, currency ASC
      `),
      pool.query(`
        WITH timeline AS (
          SELECT DATE(created_at) AS d, user_id::text AS uid FROM ocean_pay_txs
          UNION ALL
          SELECT DATE(created_at) AS d, sender_id::text AS uid FROM ocean_pay_pos
        )
        SELECT
          d::text AS day,
          COUNT(*)::int AS operations,
          COUNT(DISTINCT uid)::int AS active_users
        FROM timeline
        WHERE d >= CURRENT_DATE - INTERVAL '14 days'
        GROUP BY d
        ORDER BY d ASC
      `)
    ]);

    const usage = (usageRes.rows || []).map((row) => ({
      currency: normalizeCurrency(row.currency),
      operations: Number(row.total_ops || 0)
    }));
    const mostUsed = usage.slice(0, 10);
    const leastUsed = usage
      .filter((row) => row.operations > 0)
      .slice()
      .sort((a, b) => a.operations - b.operations || a.currency.localeCompare(b.currency))
      .slice(0, 10);

    const flow = (flowRes.rows || []).map((row) => ({
      currency: normalizeCurrency(row.currency),
      incoming: Number(row.incoming || 0),
      outgoing: Number(row.outgoing || 0),
      operations: Number(row.operations || 0)
    }));

    const trend = (trendRes.rows || []).map((row) => ({
      day: row.day,
      operations: Number(row.operations || 0),
      activeUsers: Number(row.active_users || 0)
    }));

    const totalVolumeTx = flow.reduce((acc, row) => acc + Math.abs(row.incoming) + Math.abs(row.outgoing), 0);
    const totalVolumePos = Number(posRes.rows?.[0]?.pos_completed_volume || 0);

    return res.json({
      overview: {
        totalUsers: Number(usersRes.rows?.[0]?.total_users || 0),
        totalTransactions: Number(txsRes.rows?.[0]?.total_txs || 0),
        completedPos: Number(posRes.rows?.[0]?.completed_pos || 0),
        pendingPos: Number(posRes.rows?.[0]?.pending_pos || 0),
        totalVolume: totalVolumeTx + totalVolumePos
      },
      mostUsed,
      leastUsed,
      currencyFlow: flow,
      activityTrend: trend
    });
  } catch (err) {
    if (err?.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expirado' });
    }
    console.error('Error en GET /ocean-pay/api/stats/global-overview:', err);
    return res.status(500).json({ error: 'Error obteniendo analiticas globales' });
  }
});

app.get('/ocean-pay/user-info', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: 'Token requerido' });
    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    const userId = (decoded.id || decoded.uid) || decoded.id;

    const { rows } = await pool.query('SELECT id, username, email FROM ocean_pay_users WHERE id = $1', [userId]);
    if (rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

    // NATURE-PASS CHECK
    const { rows: meta } = await pool.query("SELECT value FROM ocean_pay_metadata WHERE user_id = $1 AND key = 'nature_pass'", [userId]);
    const hasNaturePass = meta.length > 0 && meta[0].value === 'true';

    res.json({ ...rows[0], hasNaturePass });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

/* =================================
   NATUREPEDIA: ECOBOOKS API (UNIFIED WALLET)
   ================================= */
app.get('/ocean-pay/ecobooks/balance', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: 'Token requerido' });
    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    const userId = (decoded.id || decoded.uid) || decoded.id;

    const { cardId } = req.query;

    if (cardId) {
      const client = await pool.connect();
      try {
        const { rows: ownershipRows } = await client.query(
          'SELECT id FROM ocean_pay_cards WHERE id = $1 AND user_id = $2 LIMIT 1',
          [cardId, userId]
        );
        if (!ownershipRows.length) return res.status(403).json({ error: 'Tarjeta no valida' });
        const balance = await getUnifiedCardCurrencyBalance(client, Number(cardId), 'ecobooks', false);
        return res.json({ balance });
      } finally {
        client.release();
      }
    }

    const client = await pool.connect();
    try {
      const { rows } = await client.query(`
        SELECT c.id, c.card_number, c.card_name, c.is_primary
        FROM ocean_pay_cards c
        WHERE c.user_id = $1 AND c.is_active = true
        ORDER BY c.is_primary DESC, c.id ASC
      `, [userId]);

      const unifiedBalance = await getUnifiedBalance(client, Number(userId), 'ecobooks');
      const cards = rows.map((card) => ({
        ...card,
        balance: unifiedBalance
      }));
      return res.json({ cards, unified: true });
    } finally {
      client.release();
    }
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.post(['/ocean-pay/ecobooks/change', '/naturepedia/ecobooks/change'], async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: 'Token requerido' });
    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    const userId = (decoded.id || decoded.uid) || decoded.id;

    const { amount, cardId, concept = 'Naturepedia', origin = 'Naturepedia' } = req.body;
    if (amount === undefined || !cardId) return res.status(400).json({ error: 'Monto y cardId requeridos' });

    const change = parseFloat(amount);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const { rows: cardVerify } = await client.query(
        "SELECT id FROM ocean_pay_cards WHERE id = $1 AND user_id = $2",
        [cardId, userId]
      );
      if (cardVerify.length === 0) {
        await client.query('ROLLBACK');
        return res.status(403).json({ error: 'Tarjeta no vÃƒÂ¡lida' });
      }

      const current = await getUnifiedCardCurrencyBalance(client, Number(cardId), 'ecobooks', true);
      const newBal = current + change;

      if (newBal < 0) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Saldo insuficiente' });
      }

      await setUnifiedCardCurrencyBalance(client, {
        userId: Number(userId),
        cardId: Number(cardId),
        currency: 'ecobooks',
        newBalance: newBal
      });

      await client.query(
        `INSERT INTO ocean_pay_txs(user_id, concepto, monto, origen, moneda)
         VALUES($1, $2, $3, $4, 'ecobooks')`,
        [userId, concept, change, origin]
      );

      await client.query('COMMIT');
      res.json({ success: true, balance: newBal, cardId });
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

/* ===== OCEAN PAY - SUBSCRIPTIONS & NOTIFICATIONS ===== */

// Obtener mis suscripciones (con compatibilidad de esquemas) - duplicado
// Comprar/Renovar SuscripciÃƒÂ³n Premium (Semanal)
app.post('/ocean-pay/subscriptions/subscribe', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No autorizado' });
  const token = authHeader.split(' ')[1];
  const { cardId, plan = 'Premium', durationDays = 7, price = 500, projectId = 'Ocean Pay', subName } = req.body;
  const safeCardId = Number(cardId);
  const safePrice = Math.max(0, Number(price || 0));

  const client = await pool.connect();
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    const userId = decoded.id || (decoded.id || decoded.uid);
    await client.query('BEGIN');

    // 1. Verificar tarjeta y saldo unificado
    const { rows: cardRows } = await client.query('SELECT id FROM ocean_pay_cards WHERE id = $1 AND user_id = $2', [safeCardId, userId]);
    if (cardRows.length === 0) throw new Error('Tarjeta no encontrada');

    let currentWildgems = await getUnifiedCardCurrencyBalance(client, safeCardId, 'wildgems', true);
    if (currentWildgems < safePrice) throw new Error('Saldo insuficiente de WildGems');

    // 2. Descontar saldo unificado (con espejos de compatibilidad)
    let newWildgems = currentWildgems - safePrice;
    await setUnifiedCardCurrencyBalance(client, {
      userId: Number(userId),
      cardId: safeCardId,
      currency: 'wildgems',
      newBalance: newWildgems
    });

    // 3. Crear suscripciÃƒÂ³n (o extender si ya existe una activa del mismo tipo)
    const endDate = new Date();
    endDate.setDate(endDate.getDate() + durationDays);

    const { rows: subRows } = await client.query(
      `INSERT INTO ocean_pay_subscriptions(user_id, plan_name, sub_name, project_id, price, end_date, currency, card_id) 
       VALUES($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [userId, plan, subName || plan, projectId, safePrice, endDate, 'wildgems', safeCardId]
    );

    // 4. Crear notificaciÃƒÂ³n de ÃƒÂ©xito
    await client.query(
      'INSERT INTO ocean_pay_notifications(user_id, title, message, type) VALUES($1, $2, $3, $4)',
      [userId, 'SuscripciÃƒÂ³n Activada', `Ã‚Â¡Felicidades! Tu plan ${plan} de ${projectId} ha sido activado correctamente por ${durationDays} dÃƒÂ­as.`, 'success']
    );

    await client.query('COMMIT');
    res.json({ success: true, subscription: subRows[0] });
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: e.message });
  } finally {
    client.release();
  }
});

// Obtener mis notificaciones
app.get('/ocean-pay/notifications/me', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No autorizado' });
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    const userId = decoded.id || (decoded.id || decoded.uid);
    const { rows } = await pool.query('SELECT * FROM ocean_pay_notifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT 20', [userId]);
    res.json(rows);
  } catch (e) {
    res.status(401).json({ error: 'Token invÃƒÂ¡lido' });
  }
});

// Marcar notificaciÃƒÂ³n como leÃƒÂ­da

// Historial de transacciones (compatibilidad de cliente)
app.get('/ocean-pay/txs/:userId', async (req, res) => {
  try {
    const authHeader = req.headers.authorization || '';
    if (!authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    const requesterId = Number(decoded.id || decoded.uid || 0);
    const targetUserId = Number(req.params.userId || 0);

    if (!requesterId || !targetUserId) {
      return res.status(400).json({ error: 'Usuario invalido' });
    }

    const requesterName = String(decoded.username || '').toLowerCase();
    const isStudioAdmin = requesterName === 'oceanandwild';
    if (!isStudioAdmin && requesterId !== targetUserId) {
      return res.status(403).json({ error: 'No autorizado para este historial' });
    }

    const { rows } = await pool.query(
      `SELECT
         id,
         user_id,
         concepto,
         monto,
         origen,
         COALESCE(moneda, '') AS moneda,
         created_at
       FROM ocean_pay_txs
       WHERE user_id = $1
       ORDER BY created_at DESC NULLS LAST, id DESC
       LIMIT 300`,
      [targetUserId]
    );

    return res.json(rows);
  } catch (err) {
    console.error('Error en GET /ocean-pay/txs/:userId:', err);
    return res.status(500).json({ error: 'Error al obtener transacciones' });
  }
});
app.post('/ocean-pay/notifications/read/:id', async (req, res) => {
  const { id } = req.params;
  await pool.query('UPDATE ocean_pay_notifications SET is_read = TRUE WHERE id = $1', [id]);
  res.json({ success: true });
});

// ══════════════════════════════════════════════════════════════════════════════
// OCEAN PAY — UNIFIED CURRENCY MIGRATION
// Consolida TODOS los saldos en user_currency (una fila por usuario+moneda).
// Fuentes migradas:
//   1. ocean_pay_users.aquabux / appbux / ecoxionums  (columnas directas)
//   2. ocean_pay_card_balances (por tarjeta -> suma por usuario)
// La tabla user_currency ya existia para ecocorebits; la extendemos para todo.
// ══════════════════════════════════════════════════════════════════════════════

const OP_ALL_CURRENCIES = UNIFIED_WALLET_CURRENCIES;

// Leer saldo unificado de un usuario para una moneda
async function getUnifiedBalance(client, userId, currency) {
  const curr = String(currency || '').trim().toLowerCase();
  const balances = await getUserWalletBalances(client, userId, false);
  let amount = Number(balances[curr] || 0);
  // Compatibilidad: migracion Aurex -> Tides
  if (curr === 'tides' && (!Number.isFinite(amount) || amount <= 0)) {
    amount = Number(balances.aurex || 0);
  }
  return Number.isFinite(amount) ? amount : 0;
}

// Escribir saldo unificado (upsert)
async function setUnifiedBalance(client, userId, currency, amount) {
  const curr = String(currency || '').trim().toLowerCase();
  const safeAmount = Math.max(0, Number(amount) || 0);
  await ensureUserWalletRow(client, userId);
  await client.query(
    `UPDATE ${USER_WALLET_TABLE}
     SET balances = jsonb_set(COALESCE(balances, '{}'::jsonb), ARRAY[$1]::text[], to_jsonb($2::numeric), true),
         updated_at = NOW()
     WHERE user_id = $3`,
    [curr, safeAmount, userId]
  );

  // Compatibilidad temporal: mantener user_currency en espejo.
  await client.query(
    `INSERT INTO user_currency (user_id, currency_type, amount)
     VALUES ($1, $2, $3)
     ON CONFLICT (user_id, currency_type) DO UPDATE SET amount = EXCLUDED.amount, updated_at = NOW()`,
    [userId, curr, safeAmount]
  ).catch(() => {});

  if (curr === 'tides') {
    // Mantener espejo legacy para clientes antiguos que aun lean "aurex"
    await client.query(
      `UPDATE ${USER_WALLET_TABLE}
       SET balances = jsonb_set(COALESCE(balances, '{}'::jsonb), ARRAY['aurex']::text[], to_jsonb($1::numeric), true),
           updated_at = NOW()
       WHERE user_id = $2`,
      [safeAmount, userId]
    ).catch(() => {});
    await client.query(
      `INSERT INTO user_currency (user_id, currency_type, amount)
       VALUES ($1, 'aurex', $2)
       ON CONFLICT (user_id, currency_type) DO UPDATE SET amount = EXCLUDED.amount, updated_at = NOW()`,
      [userId, safeAmount]
    ).catch(() => {});
  }

  // Reflejar también tarjeta principal para endpoints legacy.
  const card = await getPrimaryCardForUser(client, userId, true);
  if (card?.id) {
    await setUnifiedCardCurrencyBalance(client, {
      userId,
      cardId: Number(card.id),
      currency: curr,
      newBalance: safeAmount
    });
  }
}

async function getUnifiedBalancesMap(client, userId, forUpdate = false) {
  const balances = await getUserWalletBalances(client, userId, forUpdate);
  const normalized = {};
  for (const c of OP_ALL_CURRENCIES) {
    normalized[c] = Number(balances[c] || 0);
  }
  for (const [key, val] of Object.entries(balances)) {
    if (!(key in normalized)) normalized[key] = Number(val || 0);
  }
  return normalized;
}

async function ensureWalletBackfillFromUserCurrency(client) {
  await client.query(`
    INSERT INTO ${USER_WALLET_TABLE} (user_id, balances)
    SELECT uc.user_id, jsonb_object_agg(LOWER(uc.currency_type), GREATEST(COALESCE(uc.amount, 0), 0))
    FROM user_currency uc
    GROUP BY uc.user_id
    ON CONFLICT (user_id) DO NOTHING
  `).catch(() => {});
}

async function ensureWalletRowForUser(client, userId) {
  await ensureUserWalletRow(client, userId);
  await ensureWalletBackfillFromUserCurrency(client);
}

async function getAllUnifiedBalances(client, userId) {
  await ensureWalletRowForUser(client, userId);
  return getUnifiedBalancesMap(client, userId, false);
}

// Leer TODOS los saldos de un usuario como objeto { currency: amount }
async function getAllUnifiedBalancesLegacy(client, userId) {
  const { rows } = await client.query(
    `SELECT currency_type, amount FROM user_currency WHERE user_id = $1`,
    [userId]
  );
  const result = {};
  for (const c of OP_ALL_CURRENCIES) result[c] = 0;
  for (const row of rows) result[row.currency_type] = Number(row.amount);
  return result;
}

// ── Admin: ejecutar migracion completa ────────────────────────────────────────
app.post('/ocean-pay/admin/migrate-currencies', async (req, res) => {
  if (!requireOwsStoreAdmin(req, res)) return;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1. Asegurar columna updated_at en user_currency (puede no existir en versiones viejas)
    await client.query(`
      ALTER TABLE user_currency
      ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    `).catch(() => {});

    // 2. Obtener todos los usuarios de Ocean Pay
    const { rows: users } = await client.query(
      'SELECT id, aquabux, appbux, ecoxionums FROM ocean_pay_users'
    );

    let migratedUsers = 0;
    let totalRows = 0;
    const log = [];

    for (const user of users) {
      const uid = user.id;

      // Recopilar saldos de TODAS las fuentes para este usuario

      // Fuente A: columnas directas en ocean_pay_users
      const directBalances = {
        aquabux:    Number(user.aquabux    || 0),
        appbux:     Number(user.appbux     || 0),
        ecoxionums: Number(user.ecoxionums || 0),
      };

      // Fuente B: ocean_pay_card_balances (suma de todas las tarjetas del usuario)
      const { rows: cardRows } = await client.query(
        `SELECT b.currency_type, SUM(b.amount) AS total
         FROM ocean_pay_card_balances b
         JOIN ocean_pay_cards c ON c.id = b.card_id
         WHERE c.user_id = $1
         GROUP BY b.currency_type`,
        [uid]
      );
      const cardBalances = {};
      for (const row of cardRows) {
        cardBalances[row.currency_type] = Number(row.total || 0);
      }

      // Fuente C: user_currency existente (puede tener ecocorebits u otras)
      const { rows: ucRows } = await client.query(
        'SELECT currency_type, amount FROM user_currency WHERE user_id = $1',
        [uid]
      );
      const existingUC = {};
      for (const row of ucRows) {
        const key = String(row.currency_type || '').toLowerCase();
        if (!key) continue;
        existingUC[key] = Number(row.amount || 0);
      }

      // Snapshot wallet actual (fuente unificada principal)
      const { rows: walletRows } = await client.query(
        `SELECT balances FROM ${USER_WALLET_TABLE} WHERE user_id = $1 LIMIT 1`,
        [uid]
      );
      const currentWallet = (walletRows[0]?.balances && typeof walletRows[0].balances === 'object')
        ? walletRows[0].balances
        : {};

      // Consolidado legacy para completar faltantes, sin pisar wallet existente.
      const legacyConsolidated = {};
      for (const currency of OP_ALL_CURRENCIES) {
        const a = directBalances[currency]  || 0;
        const b = cardBalances[currency]    || 0;
        const c = existingUC[currency]      || 0;
        legacyConsolidated[currency] = Math.max(a, b, c);
      }
      // Incluir cualquier moneda extra que exista en card_balances pero no en la lista
      for (const [currency, amount] of Object.entries(cardBalances)) {
        if (!(currency in legacyConsolidated)) {
          legacyConsolidated[currency] = Math.max(amount, existingUC[currency] || 0);
        }
      }

      const nextWallet = { ...currentWallet };
      for (const [currency, amount] of Object.entries(legacyConsolidated)) {
        const key = String(currency || '').toLowerCase();
        if (!key) continue;
        if (nextWallet[key] === undefined || nextWallet[key] === null) {
          nextWallet[key] = Math.max(0, Number(amount || 0));
        }
      }
      for (const currency of OP_ALL_CURRENCIES) {
        if (nextWallet[currency] === undefined || nextWallet[currency] === null) {
          nextWallet[currency] = 0;
        }
      }

      // Escribir wallet unificada (sin rescatar valores legacy sobre claves ya existentes).
      await client.query(
        `INSERT INTO ${USER_WALLET_TABLE} (user_id, balances, updated_at)
         VALUES ($1, $2::jsonb, NOW())
         ON CONFLICT (user_id) DO UPDATE
         SET balances = EXCLUDED.balances,
             updated_at = NOW()`,
        [uid, JSON.stringify(nextWallet)]
      );

      for (const [currency, amount] of Object.entries(nextWallet)) {
        await client.query(
          `INSERT INTO user_currency (user_id, currency_type, amount)
           VALUES ($1, $2, $3)
           ON CONFLICT (user_id, currency_type)
           DO UPDATE SET amount = EXCLUDED.amount, updated_at = NOW()`,
          [uid, currency, amount]
        );
        totalRows++;
      }

      log.push({ userId: uid, currencies: Object.keys(nextWallet).length });
      migratedUsers++;
    }

    await client.query('COMMIT');

    console.log('[Migration] Currencies migradas:', migratedUsers, 'usuarios,', totalRows, 'filas');
    res.json({
      success: true,
      migratedUsers,
      totalRows,
      message: `Migracion completada: ${migratedUsers} usuarios, ${totalRows} filas en user_currency.`,
      log
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[Migration] Error:', err);
    res.status(500).json({ error: 'Error en migracion: ' + (err.message || err) });
  } finally {
    client.release();
  }
});

// ── Admin: consultar saldos unificados de un usuario ─────────────────────────
app.get('/ocean-pay/admin/balances/:userId', async (req, res) => {
  if (!requireOwsStoreAdmin(req, res)) return;
  const userId = Number(req.params.userId);
  if (!userId) return res.status(400).json({ error: 'userId invalido' });

  const client = await pool.connect();
  try {
    const balances = await getAllUnifiedBalances(client, userId);

    // Comparar con fuentes originales para auditoria
    const { rows: userRows } = await client.query(
      'SELECT aquabux, appbux, ecoxionums FROM ocean_pay_users WHERE id = $1',
      [userId]
    );
    const { rows: cardRows } = await client.query(
      `SELECT b.currency_type, SUM(b.amount) AS total
       FROM ocean_pay_card_balances b
       JOIN ocean_pay_cards c ON c.id = b.card_id
       WHERE c.user_id = $1
       GROUP BY b.currency_type`,
      [userId]
    );

    const cardMap = {};
    for (const r of cardRows) cardMap[r.currency_type] = Number(r.total);

    res.json({
      success: true,
      userId,
      unified: balances,
      sources: {
        ocean_pay_users: userRows[0] || {},
        ocean_pay_card_balances: cardMap,
      }
    });
  } finally {
    client.release();
  }
});

// ── Admin: ajustar saldo unificado de un usuario ──────────────────────────────
app.patch('/ocean-pay/admin/balances/:userId', async (req, res) => {
  if (!requireOwsStoreAdmin(req, res)) return;
  const userId = Number(req.params.userId);
  if (!userId) return res.status(400).json({ error: 'userId invalido' });

  const { currency, amount, mode } = req.body;
  if (!currency || amount === undefined) {
    return res.status(400).json({ error: 'currency y amount requeridos' });
  }
  if (!OP_ALL_CURRENCIES.includes(currency) && !/^[a-z_]+$/.test(currency)) {
    return res.status(400).json({ error: 'currency invalida' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const current = await getUnifiedBalance(client, userId, currency);
    let newAmount;
    if (mode === 'add') {
      newAmount = current + Number(amount);
    } else if (mode === 'subtract') {
      newAmount = Math.max(0, current - Number(amount));
    } else {
      // set (default)
      newAmount = Number(amount);
    }
    await setUnifiedBalance(client, userId, currency, newAmount);
    await client.query('COMMIT');

    res.json({ success: true, userId, currency, previous: current, current: newAmount, mode: mode || 'set' });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});


const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`Ã°Å¸Å¡â‚¬ API corriendo en https://owsdatabase.onrender.com/`);
  console.log(`Ã¯Â¿Â½ Puerto:  ${PORT}`);
  console.log(`Ã°Å¸Å½Â® Sistema de Quiz Kahoot activo`);

  // Ejecutar migraciones una sola vez
  if (!migrationExecuted) {
    migrationExecuted = true;
    setTimeout(async () => {
      if (typeof notifyUnlinkedUsers !== 'function') {
        console.error('[INIT] notifyUnlinkedUsers no definida. Se omite para evitar crash.');
        return;
      }
      await notifyUnlinkedUsers();
    }, 5000); // Esperar 5 segundos despuÃƒÂ©s del inicio
  }
});


