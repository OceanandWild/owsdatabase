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
// Last deployment trigger: 2026-01-22T22:17 - Ecoxion Auth Headers Fix

/* ===== NAT-MARKET VARS ===== */
import { v2 as cloudinary } from 'cloudinary';
import { CloudinaryStorage } from 'multer-storage-cloudinary';
import { MercadoPagoConfig, Preference } from 'mercadopago';

// ConfiguraciÃƒÂ³n de MercadoPago
const mpClient = new MercadoPagoConfig({ accessToken: 'APP_USR-5761093164230281-020117-8a36b5725093b330c07cf54699b7edb1-3171975745' }); // PRODUCCIÃƒâ€œN
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

app.use(cors({
  exposedHeaders: ['X-WT-Reward-Currency', 'X-WT-Reward-Amount', 'X-WT-New-Balance']
}));
app.use(express.json());

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

      // Fetch cards and balances (Correct logic)
      const { rows: cardRows } = await pool.query(
        `SELECT c.id, c.card_number, c.cvv, c.expiry_date, c.is_active, c.is_primary, c.card_name, c.balances
         FROM ocean_pay_cards c WHERE c.user_id = $1`,
        [opUser.id]
      );

      const cardsWithBalances = await Promise.all(cardRows.map(async (card) => {
        const { rows: balanceRows } = await pool.query(
          'SELECT currency_type, amount FROM ocean_pay_card_balances WHERE card_id = $1',
          [card.id]
        );
        const balances = card.balances || {};
        balanceRows.forEach(b => balances[b.currency_type] = parseFloat(b.amount));
        if (balances.ecoxionums) balances.ecoxionums = parseFloat(balances.ecoxionums);
        return { ...card, balances };
      }));

      const totalEcoxionums = cardsWithBalances.reduce((sum, card) => sum + parseFloat(card.balances?.ecoxionums || 0), 0);
      const totalAquabux = cardsWithBalances.reduce((sum, card) => sum + parseFloat(card.balances?.aquabux || 0), 0);
      const aquabuxBalance = Math.max(totalAquabux, parseFloat(opUser.aquabux || 0));

      // Obtener WildCredits desde metadata como respaldo oficial
      const { rows: wcRows } = await pool.query(
        "SELECT value FROM ocean_pay_metadata WHERE user_id = $1 AND key = 'wildcredits'",
        [opUser.id]
      );
      const metadataWC = wcRows.length > 0 ? parseInt(wcRows[0].value || '0') : 0;

      // Calcular total desde tarjetas y comparar con metadata
      const totalWildCredits = cardsWithBalances.reduce((sum, card) => sum + parseFloat(card.balances?.wildcredits || 0), 0);
      const finalWildCredits = Math.max(metadataWC, totalWildCredits);

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

import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/* ========== MIGRACIÃƒâ€œN AUTOMÃƒÂTICA DE BASE DE DATOS ========== */
async function runDatabaseMigrations() {
  console.log('Ã°Å¸â€â€ž Ejecutando migraciones de base de datos...');

  try {
    // 0. Corregir nombres de columnas en users_nat (necesario para Supabase / NatMarket)
    console.log('Ã°Å¸â€Â§ Corrigiendo esquema de users_nat...');
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
    `).catch(err => console.log('Ã¢Å¡Â Ã¯Â¸Â Aviso: MigraciÃƒÂ³n de nombres de columna users_nat:', err.message));

    // 1. Agregar columna comment a user_ratings_nat si no existe
    await pool.query(`
      ALTER TABLE user_ratings_nat 
      ADD COLUMN IF NOT EXISTS comment TEXT
    `).catch(() => console.log('Ã¢Å¡Â Ã¯Â¸Â Columna comment ya existe en user_ratings_nat'));

    // 2. Eliminar y recrear foreign keys con ON DELETE CASCADE
    console.log('Ã°Å¸â€Â§ Arreglando foreign keys...');

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
    `).catch(() => console.log('Ã¢Å¡Â Ã¯Â¸Â FK ai_product_generations ya existe'));

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
    `).catch(() => console.log('Ã¢Å¡Â Ã¯Â¸Â FK messages_nat ya existe'));

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
    `).catch(() => console.log('Ã¢Å¡Â Ã¯Â¸Â FK user_favorites_nat ya existe'));

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
    `).catch(() => console.log('Ã¢Å¡Â Ã¯Â¸Â FK user_wishlist_nat ya existe'));

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

    // 3. Limpiar registros huÃƒÂ©rfanos (datos que referencian usuarios inexistentes)
    console.log('Ã°Å¸Â§Â¹ Limpiando datos huÃƒÂ©rfanos...');

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
    `).catch(() => console.log('Ã¢Å¡Â Ã¯Â¸Â Tabla reviews_nat ya existe'));

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
    `).catch(() => console.log('Ã¢Å¡Â Ã¯Â¸Â Columna unique_id ya existe en ocean_pay_users'));

    // 6. Agregar columnas de monedas si no existen
    await pool.query(`
      ALTER TABLE ocean_pay_users 
      ADD COLUMN IF NOT EXISTS ecoxionums INTEGER DEFAULT 0,
      ADD COLUMN IF NOT EXISTS aquabux INTEGER DEFAULT 0,
      ADD COLUMN IF NOT EXISTS appbux INTEGER DEFAULT 0
    `).catch(() => console.log('Ã¢Å¡Â Ã¯Â¸Â Columnas de monedas ya existen en ocean_pay_users'));

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
    `).catch(err => console.log('Ã¢Å¡Â Ã¯Â¸Â Aviso: MigraciÃƒÂ³n command_limit_extensions:', err.message));

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
    `).catch(() => console.log('Ã¢Å¡Â Ã¯Â¸Â Tabla ocean_pay_cards ya existe'));

    // 9. Agregar columna balances (JSONB) a ocean_pay_cards para multisaldo flexible
    await pool.query(`
      ALTER TABLE ocean_pay_cards 
      ADD COLUMN IF NOT EXISTS balances JSONB DEFAULT '{}'
    `).catch(() => console.log('Ã¢Å¡Â Ã¯Â¸Â Columna balances ya existe en ocean_pay_cards'));

    // --- MIGRACIÃƒâ€œN DE DATOS REFORZADA (Legacy Metadata + Users Column -> Card Balances) ---
    console.log('Ã°Å¸â€â€ž Ejecutando migraciÃƒÂ³n de saldos Ecoxionums (Fondo de Rescate)...');
    try {
      // 1. Migrar desde Metadata
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

      // 2. Migrar desde Columna ocean_pay_users (muy importante ya que algunos se guardaban ahÃƒÂ­)
      await pool.query(`
        UPDATE ocean_pay_cards opc
        SET balances = jsonb_set(COALESCE(opc.balances, '{}'::jsonb), '{ecoxionums}', to_jsonb(u.ecoxionums))
        FROM ocean_pay_users u
        WHERE opc.user_id = u.id 
        AND opc.is_primary = true
        AND (opc.balances->>'ecoxionums' IS NULL OR (opc.balances->>'ecoxionums')::numeric = 0)
        AND u.ecoxionums > 0
      `);
      console.log('Ã¢Å“â€¦ MigraciÃƒÂ³n de saldos completada.');
    } catch (migErr) {
      console.log('Ã¢Å¡Â Ã¯Â¸Â Aviso: Error en migraciÃƒÂ³n balance:', migErr.message);
    }

    // 2.5. Asegurar 500 VoltBits de cortesÃƒÂ­a para Velocity Surge
    try {
      await pool.query(`
        UPDATE ocean_pay_cards 
        SET balances = jsonb_set(COALESCE(balances, '{}'::jsonb), '{voltbit}', '500'::jsonb)
        WHERE is_primary = true 
        AND (balances->>'voltbit' IS NULL OR (balances->>'voltbit')::numeric = 0)
      `);
      console.log('Ã¢Å“â€¦ Balance de VoltBits (500) inicializado para usuarios existentes');
    } catch (voltErr) {
      console.log('Ã¢Å¡Â Ã¯Â¸Â Aviso: Error en inicializaciÃƒÂ³n VoltBits:', voltErr.message);
    }

    // 2.6. Asegurar MayhemCoins para WildWeapon Mayhem (inicializar en 0 para usuarios existentes)
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
      console.log('Ã¢Å“â€¦ MayhemCoins inicializados para usuarios existentes');
    } catch (mcErr) {
      console.log('Ã¢Å¡Â Ã¯Â¸Â Aviso: Error en inicializaciÃƒÂ³n MayhemCoins:', mcErr.message);
    }

    // 2.7. FUSIÃƒâ€œN: Migrar saldos de ocean_pay_metadata Ã¢â€ â€™ ocean_pay_card_balances (Fuente ÃƒÂºnica de verdad)
    console.log('Ã°Å¸â€â€ž Sincronizando saldos de metadata Ã¢â€ â€™ card_balances...');
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
        `).catch(e => console.log(`Ã¢Å¡Â Ã¯Â¸Â MigraciÃƒÂ³n ${key}:`, e.message));
      }

      // Sincronizar card_balances Ã¢â€ â€™ JSONB balances en ocean_pay_cards
      await pool.query(`
        UPDATE ocean_pay_cards opc
        SET balances = COALESCE(opc.balances, '{}'::jsonb) || (
          SELECT jsonb_object_agg(cb.currency_type, cb.amount)
          FROM ocean_pay_card_balances cb
          WHERE cb.card_id = opc.id
        )
        WHERE opc.is_primary = true
        AND EXISTS (SELECT 1 FROM ocean_pay_card_balances WHERE card_id = opc.id)
      `).catch(e => console.log('Ã¢Å¡Â Ã¯Â¸Â Sync JSONB:', e.message));

      console.log('Ã¢Å“â€¦ FusiÃƒÂ³n de saldos metadata Ã¢â€ â€™ card_balances completada');
    } catch (fusionErr) {
      console.log('Ã¢Å¡Â Ã¯Â¸Â Aviso: Error en fusiÃƒÂ³n de saldos:', fusionErr.message);
    }

    // 2.8. UNIFICACIÃƒâ€œN DE SUSCRIPCIONES: Migrar DinoPass, NaturePass y WildShorts a ocean_pay_subscriptions
    console.log('Ã°Å¸â€â€ž Unificando suscripciones en ocean_pay_subscriptions...');
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
      `).catch(e => console.log('Ã¢Å¡Â Ã¯Â¸Â MigraciÃƒÂ³n Nature-Pass:', e.message));

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
      `).catch(e => console.log('Ã¢Å¡Â Ã¯Â¸Â MigraciÃƒÂ³n DinoPass:', e.message));

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
      `).catch(e => console.log('Ã¢Å¡Â Ã¯Â¸Â MigraciÃƒÂ³n WildShorts:', e.message));

      console.log('Ã¢Å“â€¦ UnificaciÃƒÂ³n de suscripciones completada');

      // Parche: Reparar registros con nulos (evitar "null" en la UI)
      await pool.query(`
        UPDATE ocean_pay_subscriptions 
        SET plan_name = COALESCE(plan_name, sub_name, 'SuscripciÃƒÂ³n'),
            sub_name = COALESCE(sub_name, plan_name, 'SuscripciÃƒÂ³n'),
            project_id = COALESCE(project_id, 'Ocean Pay'),
            currency = COALESCE(currency, 'wildgems')
        WHERE plan_name IS NULL OR sub_name IS NULL OR project_id IS NULL OR currency IS NULL
      `).catch(e => console.log('Ã¢Å¡Â Ã¯Â¸Â Error reparando nulos en subs:', e.message));

    } catch (subErr) {
      console.log('Ã¢Å¡Â Ã¯Â¸Â Aviso: Error en unificaciÃƒÂ³n de suscripciones:', subErr.message);
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
    `).catch(() => console.log('Ã¢Å¡Â Ã¯Â¸Â Tabla ocean_pay_card_balances ya existe'));

    // 10. AÃƒÂ±adir columnas faltantes a ocean_pay_cards
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
    `).catch(err => console.log('Ã¢Å¡Â Ã¯Â¸Â Error creando ocean_pay_pos:', err.message));

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
    `).catch(err => console.log('Ã¢Å¡Â Ã¯Â¸Â Error creando ocean_pay_subscriptions:', err.message));

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
    `).catch(err => console.log('Ã¢Å¡Â Ã¯Â¸Â Error creando ocean_pay_notifications:', err.message));

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
        created_at TIMESTAMP DEFAULT NOW()
      );
    `).catch(err => console.log('Ã¢Å¡Â Ã¯Â¸Â Error creando ocean_pass:', err.message));
    // 16. Crear tabla ows_news_updates para automatizaciÃƒÂ³n de News
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
    `).catch(err => console.log('Ã¢Å¡Â Ã¯Â¸Â Error creando ows_news_updates:', err.message));

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
    `).catch(err => console.log('Ã¢Å¡Â Ã¯Â¸Â Error migrando ows_news_updates:', err.message));
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_ows_news_updates_entry_type
      ON ows_news_updates(entry_type)
    `).catch(() => {});
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_ows_news_updates_update_date
      ON ows_news_updates(update_date DESC)
    `).catch(() => {});

    await ensureOwsStoreNewsSeedData().catch(err => console.log('[OWS] Error seeding ows_news_updates:', err.message));

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
    `).catch(err => console.log('Ã¢Å¡Â Ã¯Â¸Â Error creando ows_projects:', err.message));

    // MigraciÃƒÂ³n: installer_url para descarga de .exe en OWS Store
    await pool.query(`
      ALTER TABLE ows_projects
      ADD COLUMN IF NOT EXISTS installer_url TEXT
    `).catch(() => console.log('Ã¢Å¡Â Ã¯Â¸Â Columna installer_url ya existe en ows_projects'));

    await ensureOwsStoreProjectsSeedData().catch(err => console.log('[OWS] Error seeding ows_projects:', err.message));
    await ensureProjectChangelogSync({ force: true }).catch(err => console.log('[OWS] Error syncing project changelogs:', err.message));

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
    `).catch(err => console.log('Ã¢Å¡Â Ã¯Â¸Â Error creando ows_android_releases:', err.message));

    // MigraciÃƒÂ³n: Asegurar columnas para Intercambio (Swap)
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
      `).catch(() => console.log('Ã¢Å¡Â Ã¯Â¸Â Columna password ya existe en ocean_pay_users'));

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

    // 11. Establecer tarjeta principal para usuarios que no tengan una (CRÃƒÂTICO: Hacer esto ANTES de migrar saldos)
    await pool.query(`
      UPDATE ocean_pay_cards c SET is_primary = true
      WHERE c.id = (
      SELECT MIN(id) FROM ocean_pay_cards WHERE user_id = c.user_id
      ) AND NOT EXISTS(
        SELECT 1 FROM ocean_pay_cards WHERE user_id = c.user_id AND is_primary = true
      )
      `);

    // 12. Migrar saldos existentes (AquaBux, Ecoxionums, AppBux, EcoCoreBits) a la tarjeta principal
    console.log('Ã°Å¸â€â€ž Sincronizando saldos histÃƒÂ³ricos con el sistema de tarjetas...');

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
      SELECT c.id, 'ecorebits', COALESCE(uc.amount, 0)
      FROM ocean_pay_cards c
      JOIN ocean_pay_users u ON c.user_id = u.id
      LEFT JOIN user_currency uc ON u.id = uc.user_id AND uc.currency_type = 'ecocorebits'
      WHERE c.is_primary = true
      ON CONFLICT(card_id, currency_type) DO UPDATE SET amount = EXCLUDED.amount WHERE ocean_pay_card_balances.amount = 0;

      INSERT INTO ocean_pay_card_balances(card_id, currency_type, amount)
      SELECT c.id, 'ecopower', 100
      FROM ocean_pay_cards c WHERE c.is_primary = true
      ON CONFLICT(card_id, currency_type) DO NOTHING;
    `);

    /* 
    // 13. LIMPIEZA DE SALDOS - Resetear todos a 0 (excepto ecopower = 100)
    // Se limpian tanto los nuevos saldos por tarjeta como los antiguos saldos globales
    console.log('Ã°Å¸Â§Â¹ Iniciando limpieza profunda de saldos...');

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

    console.log('Ã¢Å“â€¦ Limpieza de saldos completada. Todos los sistemas en cero.');
    */
    console.log('Ã¢Å“â€¦ Sistema de persistencia de saldos activo.');

    console.log('Ã¢Å“â€¦ Migraciones completadas exitosamente!');

  } catch (err) {
    console.error('Ã¢ÂÅ’ Error en migraciones:', err.message);
  }
}

// Ejecutar migraciones al iniciar el servidor
runDatabaseMigrations();

/* ===== HEALTH CHECK / STATUS ENDPOINT ===== */
// Este endpoint se usa para verificar que el servidor estÃƒÂ© funcionando
// y proporciona el estado de los servicios principales.
app.get('/status', async (_req, res) => {
  const services = {
    server: { status: 'up', name: 'OWS Database Server' },
    ecoconsole: { status: 'up', name: 'EcoConsole' },
    ecoxion: { status: 'up', name: 'Ecoxion' },
    natmarket: { status: 'up', name: 'NatMarket' },
    naturepedia: { status: 'up', name: 'Naturepedia' }
  };

  // Verificar conexiÃƒÂ³n a base de datos
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

// AutenticaciÃƒÂ³n directa con Ocean Pay
app.post('/ecoconsole/auth', async (req, res) => {
  const { token } = req.body;
  // TODO: Validar token con Ocean Pay system
  res.json({ success: true, message: "Placeholder: AutenticaciÃƒÂ³n exitosa" });
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

// EstadÃƒÂ­sticas del usuario
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

async function createFloretReviewNotification({
  type,
  title,
  message,
  productId = null,
  reviewId,
  reviewScope
}) {
  const recipient = await getFloretMalevoRecipient();
  await pool.query(
    `INSERT INTO floret_notifications
      (target_user_id, target_email, type, title, message, product_id, review_id, review_scope)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [
      recipient.userId,
      recipient.email,
      String(type || 'product_review'),
      String(title || 'Nueva reseÃƒÂ±a'),
      String(message || ''),
      productId || null,
      reviewId,
      String(reviewScope || 'product')
    ]
  );
}

async function assertFloretMalevoAccess({ userId, email }) {
  const normalizedEmail = normalizeFloretEmail(email);
  const requiredEmail = normalizeFloretEmail(FLORET_MAIN_SELLER_EMAIL);

  if (normalizedEmail && normalizedEmail === requiredEmail) {
    return { allowed: true };
  }

  if (!userId) return { allowed: false, reason: 'Acceso restringido a Malevo' };

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
  const isMalevo = actorEmail === requiredEmail || actorUser === 'malevo';
  const hasPrivileges = Number(actor.power_level || 0) >= 1 || actor.is_admin === true;
  if (!isMalevo && !hasPrivileges) {
    return { allowed: false, reason: 'Acceso restringido a Malevo' };
  }
  return { allowed: true, actor };
}

// Registro
app.post('/floret/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Usuario y contraseÃƒÂ±a son requeridos' });
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

    // Ã¢Å¡Â Ã¯Â¸Â FIX CRÃƒÂTICO: MercadoPago rechaza localhost/http en auto_return.
    // Forzamos SIEMPRE la URL de producciÃƒÂ³n (HTTPS) para evitar el error 400.
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

// Eliminar producto
app.delete('/floret/products/:id', async (req, res) => {
  const { id } = req.params;
  const { userId } = req.query; // Pasado por query string

  if (!userId) return res.status(401).json({ error: 'No autorizado' });

  try {
    const userRes = await pool.query('SELECT is_admin FROM floret_users WHERE id = $1', [userId]);
    if (!userRes.rows[0] || !userRes.rows[0].is_admin) {
      return res.status(403).json({ error: 'No tienes permisos' });
    }

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

/* ===== ECOXION - ECOXIONUMS ===== */

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
    const { rows } = await pool.query(
      `SELECT c.id, c.balances, u.ecoxionums AS user_ecoxionums
       FROM ocean_pay_cards c
       LEFT JOIN ocean_pay_users u ON u.id = c.user_id
       WHERE c.user_id = $1
       ORDER BY c.is_primary DESC, c.id ASC
       LIMIT 1`,
      [userId]
    );

    if (!rows.length) return res.json({ ecoxionums: 0 });

    const card = rows[0];
    const jsonBal = Number(card?.balances?.ecoxionums || 0);
    const userBal = Number(card?.user_ecoxionums || 0);
    const { rows: tableRows } = await pool.query(
      `SELECT amount FROM ocean_pay_card_balances WHERE card_id = $1 AND currency_type = 'ecoxionums'`,
      [card.id]
    );
    const tableBal = Number(tableRows[0]?.amount || 0);
    const ecoxionums = Math.max(jsonBal, tableBal, userBal);

    res.json({ ecoxionums });
  } catch (e) {
    console.error('Error obteniendo ecoxionums:', e);
    res.json({ ecoxionums: 0 });
  }
});


// Changelogs centralizados para todos los proyectos (fuente: ows_news_updates + sync GitHub)
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
      FROM ows_news_updates
      WHERE entry_type = 'changelog'
      ORDER BY COALESCE(priority, 0) DESC, update_date DESC, created_at DESC
      LIMIT $1
    `, [limit * 2]);

    let list = rows.map(normalizeOwsNewsRow);
    if (!includeInactive) list = list.filter(r => r.is_active !== false);
    if (projectFilter) {
      list = list.filter((r) => {
        const names = Array.isArray(r.project_names) ? r.project_names : [];
        return names.some((name) => String(name || '').toLowerCase().includes(projectFilter));
      });
    }
    list = list.slice(0, limit);
    return res.json({ success: true, total: list.length, changelogs: list });
  } catch (err) {
    console.error('âŒ Error en GET /ows-store/changelogs:', err);
    return res.status(500).json({ error: 'Error interno' });
  }
});

// Sync manual de changelogs desde GitHub releases hacia ows_news_updates
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
         release_date = EXCLUDED.release_date,
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
  const { version } = req.body;
  if (!version) return res.status(400).json({ error: 'VersiÃƒÂ³n requerida' });

  try {
    const { rows } = await pool.query(
      'UPDATE ows_projects SET version = $1, last_update = NOW() WHERE slug = $2 RETURNING *',
      [version, slug]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Proyecto no encontrado' });
    res.json({ success: true, project: rows[0] });
  } catch (err) {
    console.error('Ã¢ÂÅ’ Error en PATCH /ows-store/projects/:version:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Obtener ÃƒÂºltimo release Android publicado por slug
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
      VALUES ($1,$2,$3,$4,$5,$6,$7)`,
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
      SELECT c.id, 'ecorebits', uc.amount
      FROM ocean_pay_cards c
      JOIN ocean_pay_users opu ON c.user_id = opu.id
      JOIN users u ON LOWER(u.username) = LOWER(opu.username)
      JOIN user_currency uc ON uc.user_id = u.id AND uc.currency_type = 'ecocorebits'
      WHERE opu.id = $1 AND c.is_primary = true AND uc.amount > 0
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
  const { userId, listsData } = req.body;
  if (!userId || !listsData) {
    return res.status(400).json({ error: 'Faltan userId o listsData' });
  }

  try {
    await pool.query(
      `INSERT INTO tigertasks_backups (user_id, backup_data, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (user_id) DO UPDATE SET
         backup_data = EXCLUDED.backup_data,
         updated_at = NOW()`,
      [userId, JSON.stringify(listsData)]
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
  res.json(rows[0]?.backup_data || null);
});

/* ===== SUSCRIPCIONES ECOXION ===== */

const ECOXION_PROJECT_ID = 'Ecoxion';
const ECOXION_CURRENCY = 'ecoxionums';
const ECOXION_PLAN_CATALOG = {
  plus: { id: 'plus', label: 'Plus', price: 420, intervalDays: 30 },
  pro: { id: 'pro', label: 'Pro', price: 750, intervalDays: 30 },
  ultra: { id: 'ultra', label: 'Ultra', price: 1250, intervalDays: 30 }
};

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

async function getUnifiedCardCurrencyBalance(client, cardId, currency, forUpdate = true) {
  const curr = String(currency || '').trim().toLowerCase();
  const lockSql = forUpdate ? 'FOR UPDATE' : '';

  const { rows: cardRows } = await client.query(
    `SELECT balances FROM ocean_pay_cards WHERE id = $1 ${lockSql}`,
    [cardId]
  );
  const balances = cardRows[0]?.balances || {};
  const jsonBalance = Number(balances[curr] || 0);

  const { rows: tableRows } = await client.query(
    `SELECT amount
     FROM ocean_pay_card_balances
     WHERE card_id = $1 AND currency_type = $2
     ${lockSql}`,
    [cardId, curr]
  );
  const tableBalance = Number(tableRows[0]?.amount || 0);
  return Math.max(jsonBalance, tableBalance);
}

async function setUnifiedCardCurrencyBalance(client, { userId, cardId, currency, newBalance }) {
  const curr = String(currency || '').trim().toLowerCase();
  const safeBalance = Number(newBalance || 0);

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
  );

  await client.query(
    `INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount)
     VALUES ($1, $2, $3)
     ON CONFLICT (card_id, currency_type)
     DO UPDATE SET amount = EXCLUDED.amount`,
    [cardId, curr, safeBalance]
  );

  if (curr === ECOXION_CURRENCY) {
    await client.query(
      `UPDATE ocean_pay_users SET ecoxionums = $1 WHERE id = $2`,
      [safeBalance, userId]
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
    const userId = Number(req.params.userId);
    if (!Number.isFinite(userId) || userId <= 0) {
      return res.status(400).json({ error: 'userId invalido' });
    }

    const columns = await getWtSubscriptionColumnSet();
    const endsExpr = columns.has('end_date')
      ? 'end_date'
      : (columns.has('next_payment') ? 'next_payment' : 'created_at');
    const renewExpr = columns.has('next_payment')
      ? 'next_payment'
      : (columns.has('end_date') ? 'end_date' : 'created_at');

    const { rows } = await pool.query(
      `SELECT id, plan_name, sub_name, price, currency, status, start_date, ${endsExpr} AS ends_at, ${renewExpr} AS renew_at, created_at
       FROM ocean_pay_subscriptions
       WHERE user_id = $1
         AND LOWER(COALESCE(project_id, '')) = LOWER($2)
       ORDER BY created_at DESC
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
      startsAt: current.start_date || current.created_at,
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

  const planDef = getEcoxionPlanDefinition(req.body?.plan);
  if (!planDef) {
    return res.status(400).json({ error: 'Plan no valido. Usa plus, pro o ultra.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const primaryCard = await getPrimaryCardForUser(client, requestedUserId, true);
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
      pwd_hash TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  // Tabla principal de posts (con soporte para respuestas y likes)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS wildx_posts (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES wildx_users(id) ON DELETE SET NULL,
      username TEXT,
      content TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW(),
      parent_id INTEGER REFERENCES wildx_posts(id) ON DELETE CASCADE,
      likes_count INTEGER NOT NULL DEFAULT 0
    )
  `);

  // Asegurar columnas nuevas si la tabla ya existÃƒÂ­a
  await pool.query('ALTER TABLE wildx_posts ADD COLUMN IF NOT EXISTS parent_id INTEGER REFERENCES wildx_posts(id) ON DELETE CASCADE');
  await pool.query("ALTER TABLE wildx_posts ADD COLUMN IF NOT EXISTS likes_count INTEGER NOT NULL DEFAULT 0");

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

// Crear una notificaciÃƒÂ³n para un usuario de WildX
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
    console.error('Error creando notificaciÃƒÂ³n WildX:', err);
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

function normalizeWildWaveBadgeColor(color) {
  const normalized = String(color || '').trim().toLowerCase();
  return WILDWAVE_BADGE_COLORS.includes(normalized) ? normalized : null;
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
      ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP NULL
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
    const { username, password } = req.body || {};
    const uname = (username || '').toString().trim();
    const pwd = (password || '').toString();
    if (!uname || !pwd) return res.status(400).json({ error: 'Usuario y contraseÃƒÂ±a requeridos' });
    if (uname.length < 3) return res.status(400).json({ error: 'El usuario debe tener al menos 3 caracteres' });

    const hash = await bcrypt.hash(pwd, 10);
    const { rows } = await pool.query(
      'INSERT INTO wildx_users (username, pwd_hash) VALUES ($1,$2) RETURNING id, username, created_at',
      [uname, hash]
    );
    const userRow = rows[0];

    const token = jwt.sign({ wid: userRow.id, un: userRow.username }, process.env.STUDIO_SECRET, { expiresIn: '7d' });
    const user = { id: userRow.id, username: userRow.username, created_at: userRow.created_at, posts_count: 0 };
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

    const { rows } = await pool.query('SELECT id, username, pwd_hash, created_at FROM wildx_users WHERE username=$1', [uname]);
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
      created_at: rows[0].created_at,
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
              u.created_at,
              COALESCE(p.posts_count, 0) AS posts_count,
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
    user.max_post_chars = getWildWaveMaxCharsForTier(user.verify_tier, user.verify_plan_id);

    if (user.username === 'Ocean and Wild Studios') {
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
    `SELECT p.id, p.user_id, p.username, p.content, p.created_at, p.parent_id,
            p.likes_count,
            v.tier AS verify_tier,
            v.badge_color AS verify_badge_color
       FROM wildx_posts p
       LEFT JOIN LATERAL (
         SELECT tier, badge_color
           FROM wildx_verifications
          WHERE user_id = p.user_id
            AND valid_until > NOW()
          ORDER BY started_at ASC
          LIMIT 1
       ) v ON TRUE
      WHERE p.id = $1`,
    [chosen.post_id]
  );

  if (!posts.length) return null;

  return {
    promotion_id: chosen.id,
    amount_wxt: Number(chosen.amount_wxt),
    post: posts[0]
  };
}

// API de posts WildX (Explorar = todos los posts publicados)
app.get('/wildwave/api/posts', async (req, res) => {
  try {
    await ensureWildXTables();
    await ensureWildXExtraColumns();
    const wid = getWildXUserId(req) || 0;
    const postsPromise = pool.query(
      `SELECT p.id, p.user_id, p.username, p.content, p.created_at, p.parent_id,
              p.likes_count,
              (l.user_id IS NOT NULL) AS liked,
              v.tier AS verify_tier,
            v.badge_color AS verify_badge_color
         FROM wildx_posts p
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
        WHERE p.status = 'published' AND p.deleted_at IS NULL
        ORDER BY p.created_at DESC
        LIMIT 100`,
      [wid]
    );

    const [postsResult, promoted] = await Promise.all([
      postsPromise,
      selectPromotedPost().catch(() => null)
    ]);

    res.json({
      posts: postsResult.rows,
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
      `SELECT p.id, p.user_id, p.username, p.content, p.created_at, p.parent_id,
              p.likes_count,
              (l.user_id IS NOT NULL) AS liked,
              v.tier AS verify_tier,
            v.badge_color AS verify_badge_color
         FROM wildx_posts p
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
        WHERE p.user_id = $1 AND p.status = 'published' AND p.deleted_at IS NULL
        ORDER BY p.created_at DESC
        LIMIT 100`,
      [wid]
    );
    res.json(rows);
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

// Helper: detectar admin de WildX
async function isWildXAdmin(userId) {
  const { rows } = await pool.query('SELECT username FROM wildx_users WHERE id = $1', [userId]);
  if (!rows.length) return false;
  const uname = rows[0].username || '';
  return uname === 'Ocean and Wild Studios';
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

    if (!content) return res.status(400).json({ error: 'Contenido requerido' });

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

    const { rows: users } = await pool.query('SELECT username FROM wildx_users WHERE id=$1', [wid]);
    if (!users.length) return res.status(404).json({ error: 'Usuario no encontrado' });
    const uname = users[0].username;

    // Si es respuesta, no permitir responder solo al post inicial propio
    if (parentId) {
      const { rows: parentRows } = await pool.query(
        'SELECT user_id, parent_id FROM wildx_posts WHERE id=$1',
        [parentId]
      );
      if (!parentRows.length) {
        return res.status(404).json({ error: 'Post padre no encontrado' });
      }
      // Bloquear solo si el padre es un post inicial propio (sin parent_id)
      if (parentRows[0].parent_id == null && Number(parentRows[0].user_id) === Number(wid)) {
        return res.status(400).json({ error: 'No puedes responder al post inicial propio' });
      }
    }

    const { rows } = await pool.query(
      'INSERT INTO wildx_posts (user_id, username, content, parent_id, scheduled_at, status) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, user_id, username, content, created_at, parent_id, likes_count, scheduled_at, status',
      [wid, uname, content, parentId, scheduledAt, status]
    );
    res.json(rows[0]);
  } catch (err) {
    console.error('Error en POST /wildwave/api/posts:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Toggle like en un post WildX
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
       SELECT t.id, t.user_id, t.username, t.content, t.created_at, t.parent_id,
              t.likes_count,
              (l.user_id IS NOT NULL) AS liked,
              v.tier AS verify_tier,
            v.badge_color AS verify_badge_color
         FROM thread t
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
        ORDER BY t.created_at ASC`,
      [postId, wid]
    );

    // No devolver posts eliminados
    const filtered = rows.filter(r => !r.deleted_at);
    res.json(filtered);
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
      `SELECT id, user_id, username, content, created_at, parent_id, likes_count, scheduled_at, status
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
await createNatMarketTables();

// Ã°Å¸â€™Â¡ CORRECCIÃƒâ€œN 1: Llama a la limpieza DESPUÃƒâ€°S de asegurar que todas las tablas existen.
console.log("Iniciando limpieza de eventos antiguos...");
await cleanupOldEvents(); // <--- ASEGÃƒÅ¡RATE DE QUE SE EJECUTA AQUÃƒÂ
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

await pool.query(`CREATE INDEX IF NOT EXISTS idx_floret_product_reviews_product ON floret_product_reviews(product_id, created_at DESC)`).catch(() => { });
await pool.query(`CREATE INDEX IF NOT EXISTS idx_floret_seller_reviews_email ON floret_seller_reviews(seller_email, created_at DESC)`).catch(() => { });
await pool.query(`CREATE INDEX IF NOT EXISTS idx_floret_notifications_target ON floret_notifications(target_user_id, created_at DESC)`).catch(() => { });
await pool.query(`CREATE INDEX IF NOT EXISTS idx_floret_notifications_email ON floret_notifications(target_email, created_at DESC)`).catch(() => { });

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
    UPDATE floret_users SET is_admin = true, power_level = 2 WHERE username = 'OceanandWild';
    UPDATE floret_users SET is_admin = true, power_level = 1 WHERE username = 'Malevo' OR email = 'karatedojor@gmail.com';
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

    if (!projectId || !subName || !price || !currency || !cardId) {
      return res.status(400).json({ error: 'Datos incompletos' });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Check balance and deduct
      const isMetadataCurrency = ['amber', 'ecotokens'].includes(currency.toLowerCase());
      let current = 0;

      if (isMetadataCurrency) {
        const { rows: metaRows } = await client.query(
          "SELECT value FROM ocean_pay_metadata WHERE user_id = $1 AND key = $2 FOR UPDATE",
          [userId, currency.toLowerCase()]
        );
        current = parseInt(metaRows[0]?.value || '0');
        if (current < price) {
          await client.query('ROLLBACK');
          return res.status(400).json({ error: `Saldo insuficiente de ${currency.toUpperCase()}` });
        }
        await client.query(
          "UPDATE ocean_pay_metadata SET value = $1 WHERE user_id = $2 AND key = $3",
          [(current - price).toString(), userId, currency.toLowerCase()]
        );
      } else {
        const { rows: balRows } = await client.query(
          "SELECT amount FROM ocean_pay_card_balances WHERE card_id = $1 AND currency_type = $2 FOR UPDATE",
          [cardId, currency.toLowerCase()]
        );
        current = parseFloat(balRows[0]?.amount || '0');
        if (current < price) {
          await client.query('ROLLBACK');
          return res.status(400).json({ error: 'Saldo insuficiente en la tarjeta' });
        }
        await client.query(
          "UPDATE ocean_pay_card_balances SET amount = amount - $1 WHERE card_id = $2 AND currency_type = $3",
          [price, cardId, currency.toLowerCase()]
        );
      }

      // Log TX
      await client.query(
        "INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda) VALUES ($1, $2, $3, $4, $5)",
        [userId, `SuscripciÃƒÂ³n: ${subName}`, -price, projectId, currency]
      );

      // Save Sub
      const nextPayment = new Date();
      nextPayment.setDate(nextPayment.getDate() + (intervalDays || 7));

      const { rows: sub } = await client.query(`
        INSERT INTO ocean_pay_subscriptions (user_id, card_id, project_id, sub_name, plan_name, price, currency, interval_days, next_payment)
        VALUES ($1, $2, $3, $4, $4, $5, $6, $7, $8)
        RETURNING *
      `, [userId, cardId, projectId, subName, price, currency, intervalDays || 7, nextPayment]);

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
   NATUREPEDIA: ECOBOOKS API (CARD-BASED)
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
      const { rows } = await pool.query(
        "SELECT amount FROM ocean_pay_card_balances WHERE card_id = $1 AND currency_type = 'ecobooks'",
        [cardId]
      );
      return res.json({ balance: parseFloat(rows[0]?.amount || '0') });
    } else {
      const { rows } = await pool.query(`
        SELECT c.id, c.card_number, c.card_name, c.is_primary, 
               COALESCE(b.amount, 0) as balance
        FROM ocean_pay_cards c
        LEFT JOIN ocean_pay_card_balances b ON c.id = b.card_id AND b.currency_type = 'ecobooks'
        WHERE c.user_id = $1 AND c.is_active = true
      `, [userId]);
      res.json({ cards: rows });
    }
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/ocean-pay/ecobooks/change', async (req, res) => {
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

      const { rows } = await client.query(
        "SELECT amount FROM ocean_pay_card_balances WHERE card_id = $1 AND currency_type = 'ecobooks' FOR UPDATE",
        [cardId]
      );
      const current = parseFloat(rows[0]?.amount || '0');
      const newBal = current + change;

      if (newBal < 0) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Saldo insuficiente' });
      }

      await client.query(
        `INSERT INTO ocean_pay_card_balances(card_id, currency_type, amount)
         VALUES($1, 'ecobooks', $2)
         ON CONFLICT(card_id, currency_type) DO UPDATE SET amount = $2`,
        [cardId, newBal]
      );

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

  const client = await pool.connect();
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET || process.env.JWT_SECRET || 'secret');
    const userId = decoded.id || (decoded.id || decoded.uid);
    await client.query('BEGIN');

    // 1. Verificar saldo unificado (JSONB + Tabla)
    const { rows: cardRows } = await client.query('SELECT balances FROM ocean_pay_cards WHERE id = $1 AND user_id = $2', [cardId, userId]);
    if (cardRows.length === 0) throw new Error('Tarjeta no encontrada');

    // Obtener saldos de la tabla SQL
    const { rows: balanceRows } = await client.query(
      'SELECT amount FROM ocean_pay_card_balances WHERE card_id = $1 AND currency_type = $2 FOR UPDATE',
      [cardId, 'wildgems']
    );

    let balances = cardRows[0].balances || {};
    let tableWildgems = parseFloat(balanceRows[0]?.amount || 0);
    let jsonWildgems = parseFloat(balances.wildgems || 0);

    // El saldo real es el mayor o la uniÃƒÂ³n (siguiendo lÃƒÂ³gica de /ocean-pay/me)
    let currentWildgems = Math.max(tableWildgems, jsonWildgems);

    if (currentWildgems < price) throw new Error('Saldo insuficiente de WildGems');

    // 2. Descontar saldo y actualizar ambos lugares para consistencia
    let newWildgems = currentWildgems - price;

    // Actualizar JSONB
    balances.wildgems = newWildgems;
    await client.query('UPDATE ocean_pay_cards SET balances = $1 WHERE id = $2', [balances, cardId]);

    // Actualizar Tabla SQL
    await client.query(`
      INSERT INTO ocean_pay_card_balances(card_id, currency_type, amount)
      VALUES($1, 'wildgems', $2)
      ON CONFLICT(card_id, currency_type) DO UPDATE SET amount = $2
    `, [cardId, newWildgems]);

    // 3. Crear suscripciÃƒÂ³n (o extender si ya existe una activa del mismo tipo)
    const endDate = new Date();
    endDate.setDate(endDate.getDate() + durationDays);

    const { rows: subRows } = await client.query(
      `INSERT INTO ocean_pay_subscriptions(user_id, plan_name, sub_name, project_id, price, end_date, currency, card_id) 
       VALUES($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [userId, plan, subName || plan, projectId, price, endDate, 'wildgems', cardId]
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
app.post('/ocean-pay/notifications/read/:id', async (req, res) => {
  const { id } = req.params;
  await pool.query('UPDATE ocean_pay_notifications SET is_read = TRUE WHERE id = $1', [id]);
  res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`Ã°Å¸Å¡â‚¬ API corriendo en https://owsdatabase.onrender.com/`);
  console.log(`Ã¯Â¿Â½ Puerto:  ${PORT}`);
  console.log(`Ã°Å¸Å½Â® Sistema de Quiz Kahoot activo`);

  // Ejecutar migraciones una sola vez
  if (!migrationExecuted) {
    migrationExecuted = true;
    setTimeout(() => {
      notifyUnlinkedUsers();
    }, 5000); // Esperar 5 segundos despuÃƒÂ©s del inicio
  }
});




