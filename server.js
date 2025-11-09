// 0️⃣ SIEMPRE PRIMERO
import "./instrument.js";

// 1️⃣ Después el resto
import express from "express";
import cors from "cors";
import pg from "pg";
import dotenv from "dotenv";
import multer from "multer";
import bcrypt from "bcrypt";
import path from "path";
import fs from "fs";
import jwt from 'jsonwebtoken';
import { Server } from 'socket.io';
import { createServer } from 'http';

// URL FOR THIS DATABASE: https://owsdatabase.onrender.com
dotenv.config();

/* ===== NAT-MARKET VARS ===== */
const uploadDir = path.join(process.cwd(), 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

// Función para generar ID único de usuario (100 caracteres)
function generateUserUniqueId() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < 100; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadDir),
  filename: (_file, _file2, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, unique + path.extname(_file2.originalname));
  }
});
const upload = multer({ storage });

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

app.use(cors());
app.use(express.json());

import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

// Generic auth middleware used by some routes
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }
  const token = authHeader.substring(7);
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    req.userId = decoded.userId || decoded.uid;
    if (!req.userId) throw new Error('Invalid user');
    return next();
  } catch (_e) {
    try {
      const decodedStudio = jwt.verify(token, process.env.STUDIO_SECRET);
      req.userId = decodedStudio.uid || decodedStudio.userId;
      if (!req.userId) throw new Error('Invalid user');
      return next();
    } catch (_e2) {
      return res.status(401).json({ error: 'Token inválido' });
    }
  }
}

app.get('/ocean-pay/index.html', (_req, res) => {
  try {
    const html = fs.readFileSync(join(__dirname, 'Ocean Pay', 'index.html'), 'utf-8');
    res.type('html').send(html);
  } catch (e) {
    res.status(404).send('Archivo no encontrado');
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
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    userId = decoded.uid;
    // Asegurar que userId sea un entero (el id de ocean_pay_users es INTEGER)
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token inválido' });
  }
  
  const { wildCredits } = req.body;
  if (wildCredits === undefined || wildCredits === null) {
    return res.status(400).json({ error: 'wildCredits requerido' });
  }
  
  const wildCreditsValue = parseInt(wildCredits || '0');
  
  try {
    // Asegurar que la tabla existe con el esquema correcto (INTEGER)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ocean_pay_metadata (
        user_id INTEGER NOT NULL,
        key TEXT NOT NULL,
        value TEXT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id, key)
      )
    `);
    
    // Intentar actualizar o insertar
    await pool.query(`
      INSERT INTO ocean_pay_metadata (user_id, key, value)
      VALUES ($1, 'wildcredits', $2)
      ON CONFLICT (user_id, key) 
      DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP
    `, [userId, wildCreditsValue.toString()]);
    
    res.json({ success: true, wildcredits: wildCreditsValue });
  } catch (e) {
    // Si hay un error de tipo de dato (tabla existe con UUID), intentar recrearla
    if (e.code === '22P02' || e.message.includes('uuid')) {
      try {
        console.log('Recreando tabla ocean_pay_metadata con INTEGER...');
        await pool.query('DROP TABLE IF EXISTS ocean_pay_metadata CASCADE');
        await pool.query(`
          CREATE TABLE ocean_pay_metadata (
            user_id INTEGER NOT NULL,
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, key)
          )
        `);
        await pool.query(`
          INSERT INTO ocean_pay_metadata (user_id, key, value)
          VALUES ($1, 'wildcredits', $2)
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
          CREATE TABLE ocean_pay_metadata (
            user_id INTEGER NOT NULL,
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, key)
          )
        `);
        await pool.query(`
          INSERT INTO ocean_pay_metadata (user_id, key, value)
          VALUES ($1, 'wildcredits', $2)
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
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    userId = decoded.uid;
    // Asegurar que userId sea un entero (el id de ocean_pay_users es INTEGER)
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token inválido' });
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
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    userId = decoded.uid;
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token inválido' });
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
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    userId = decoded.uid;
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token inválido' });
  }
  
  const { wildGems } = req.body;
  if (wildGems === undefined || wildGems === null) {
    return res.status(400).json({ error: 'wildGems requerido' });
  }
  
  const wildGemsValue = parseInt(wildGems || '0');
  
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ocean_pay_metadata (
        user_id INTEGER NOT NULL,
        key TEXT NOT NULL,
        value TEXT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id, key)
      )
    `);
    
    await pool.query(`
      INSERT INTO ocean_pay_metadata (user_id, key, value)
      VALUES ($1, 'wildgems', $2)
      ON CONFLICT (user_id, key) 
      DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP
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
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    userId = decoded.uid;
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token inválido' });
  }
  
  const { amount, concepto = 'Operación', origen = 'WildShorts' } = req.body;
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
      INSERT INTO ocean_pay_metadata (user_id, key, value)
      VALUES ($1, 'wildgems', $2)
      ON CONFLICT (user_id, key) 
      DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP
    `, [userId, newBalance.toString()]);
    
    // Registrar transacción
    await client.query(`
      INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
      VALUES ($1, $2, $3, $4, 'WG')
      ON CONFLICT DO NOTHING
    `, [userId, concepto, amount, origen]).catch(async () => {
      // Si falla por falta de columna moneda, intentar sin ella
      await client.query(`
        INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen)
        VALUES ($1, $2, $3, $4)
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
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    userId = decoded.uid;
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token inválido' });
  }
  
  const { planId, paymentMethod } = req.body; // paymentMethod: 'weekly' o 'pay-as-you-go'
  if (!planId || !paymentMethod) {
    return res.status(400).json({ error: 'planId y paymentMethod requeridos' });
  }
  
  // Verificar si la columna moneda existe ANTES de comenzar la transacción
  let hasMonedaColumn = false;
  try {
    const { rows: columnCheck } = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'ocean_pay_txs' AND column_name = 'moneda'
    `);
    hasMonedaColumn = columnCheck.length > 0;
  } catch (e) {
    // Si falla la verificación, asumir que no existe
    hasMonedaColumn = false;
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
    
    // Calcular precio según método de pago
    // Para weekly: precio reducido (ej: 70% del precio mensual)
    // Para pay-as-you-go: no se cobra aquí, se cobra por episodio
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
      return res.status(400).json({ error: `Saldo insuficiente. Necesitas ${planPrice} WildGems.` });
    }
    
    // Si es weekly, descontar inmediatamente
    if (paymentMethod === 'weekly') {
      const newBalance = currentGems - planPrice;
      await client.query(`
        INSERT INTO ocean_pay_metadata (user_id, key, value)
        VALUES ($1, 'wildgems', $2)
        ON CONFLICT (user_id, key) 
        DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP
      `, [userId, newBalance.toString()]);
      
      // Registrar transacción - usar la consulta apropiada según si existe la columna moneda
      if (hasMonedaColumn) {
        await client.query(`
          INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
          VALUES ($1, $2, $3, $4, 'WG')
        `, [userId, `Suscripción ${planId} (WildShorts) - Semanal`, -planPrice, 'WildShorts']);
      } else {
        await client.query(`
          INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen)
          VALUES ($1, $2, $3, $4)
        `, [userId, `Suscripción ${planId} (WildShorts) - Semanal`, -planPrice, 'WildShorts']);
      }
    }
    
    // Crear/actualizar suscripción
    const now = new Date();
    const endsAt = paymentMethod === 'weekly' 
      ? new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000) // 7 días
      : null; // pay-as-you-go no tiene fecha de expiración
    
    // Crear tabla de suscripciones de WildShorts si no existe
    await client.query(`
      CREATE TABLE IF NOT EXISTS wildshorts_subs (
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
    
    // Crear nueva suscripción
    const { rows: subRows } = await client.query(`
      INSERT INTO wildshorts_subs (user_id, plan_id, payment_method, starts_at, ends_at, active)
      VALUES ($1, $2, $3, $4, $5, true)
      ON CONFLICT (user_id, plan_id, payment_method)
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

// ====================
// DEEPDIVE SUBSCRIPTION ENDPOINTS
// ====================

// Get DeepDive Pro subscription status
app.get('/deepdive/subscription/status', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token required' });
  }
  
  const token = authHeader.substring(7);
  
  try {
    // Verify JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    const userId = decoded.userId || decoded.uid;
    
    if (!userId) {
      return res.status(400).json({ error: 'Invalid user ID in token' });
    }
    
    // Check if user has an active subscription
    const { rows } = await pool.query(
      `SELECT * FROM subscriptions 
       WHERE user_id = $1 AND ends_at > NOW() AND status = 'active' 
       ORDER BY ends_at DESC LIMIT 1`,
      [userId]
    );
    
    if (rows.length > 0) {
      // User has an active subscription
      return res.json({
        isActive: true,
        plan: rows[0].plan,
        startsAt: rows[0].starts_at,
        endsAt: rows[0].ends_at,
        createdAt: rows[0].created_at
      });
    } else {
      // No active subscription found
      return res.json({ 
        isActive: false,
        message: 'No active subscription found' 
      });
    }
  } catch (error) {
    console.error('Error checking subscription status:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Create or update subscription (charges WildCredits via Ocean Pay)
app.post('/deepdive/subscription/subscribe', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token required' });
  }

  const token = authHeader.substring(7);
  const { plan, paymentMethod, paymentAmount } = req.body;

  if (!plan || !paymentMethod || paymentAmount === undefined) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  // Resolve userId from either app token (JWT_SECRET) or fallback to studio token
  let userId;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    userId = decoded.userId || decoded.uid;
  } catch (e) {
    try {
      const decodedStudio = jwt.verify(token, process.env.STUDIO_SECRET);
      userId = decodedStudio.uid || decodedStudio.userId;
    } catch (_e2) {
      return res.status(401).json({ error: 'Invalid token' });
    }
  }
  if (!userId) return res.status(400).json({ error: 'Invalid user ID in token' });

  // Normalize amounts by plan to prevent tampering from client
  const normalizedAmount = plan === 'yearly' ? 500 : 50;
  const amount = parseInt(paymentAmount) || normalizedAmount;

  // Quick sanity check: allow slight mismatch only if equals normalized
  if (amount !== normalizedAmount) {
    return res.status(400).json({ error: 'Invalid amount for selected plan' });
  }

  // Check if ocean_pay_txs has currency column (moneda)
  let hasMonedaColumn = false;
  try {
    const { rows: col } = await pool.query(`
      SELECT column_name FROM information_schema.columns
      WHERE table_name = 'ocean_pay_txs' AND column_name = 'moneda'
    `);
    hasMonedaColumn = col.length > 0;
  } catch (_) {
    hasMonedaColumn = false;
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Lock and verify WildCredits balance
    const { rows: wcRows } = await client.query(`
      SELECT value FROM ocean_pay_metadata
      WHERE user_id = $1 AND key = 'wildcredits'
      FOR UPDATE
    `, [userId]);

    const currentWC = parseInt(wcRows[0]?.value || '0');
    if (currentWC < amount) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: `Insufficient WildCredits. Need ${amount}.` });
    }

    // Deduct WildCredits and record transaction
    const newWC = currentWC - amount;
    await client.query(`
      INSERT INTO ocean_pay_metadata (user_id, key, value)
      VALUES ($1, 'wildcredits', $2)
      ON CONFLICT (user_id, key)
      DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP
    `, [userId, newWC.toString()]);

    const concept = `Suscripción Pro (DeepDive) - ${plan === 'yearly' ? 'Anual' : 'Mensual'}`;
    if (hasMonedaColumn) {
      await client.query(`
        INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
        VALUES ($1, $2, $3, $4, 'WC')
      `, [userId, concept, -amount, 'DeepDive Presentations']);
    } else {
      await client.query(`
        INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen)
        VALUES ($1, $2, $3, $4)
      `, [userId, concept, -amount, 'DeepDive Presentations']);
    }

    // Upsert subscription window
    const now = new Date();
    const endsAt = new Date(now);
    endsAt.setMonth(endsAt.getMonth() + (plan === 'yearly' ? 12 : 1));

    const { rows: existingSubs } = await client.query(
      `SELECT id FROM subscriptions 
       WHERE user_id = $1 AND status = 'active' AND ends_at > NOW() 
       LIMIT 1`,
      [userId]
    );

    if (existingSubs.length > 0) {
      await client.query(`
        UPDATE subscriptions
        SET plan = $1, status = 'active', starts_at = $2, ends_at = $3,
            updated_at = NOW(), payment_method = $4, payment_amount = $5
        WHERE user_id = $6 AND status = 'active'
      `, [plan, now, endsAt, paymentMethod, amount, userId]);
    } else {
      await client.query(`
        INSERT INTO subscriptions (user_id, plan, status, starts_at, ends_at, payment_method, payment_amount)
        VALUES ($1, $2, 'active', $3, $4, $5, $6)
      `, [userId, plan, now, endsAt, paymentMethod, amount]);
    }

    // Log payment
    await client.query(`
      INSERT INTO payments (user_id, amount, currency, status, payment_method, subscription_plan, description)
      VALUES ($1, $2, 'WildCredits', 'completed', $3, $4, 'DeepDive Pro Subscription')
    `, [userId, amount, paymentMethod, plan]);

    await client.query('COMMIT');
    res.json({ success: true, message: 'Subscription activated successfully', plan, endsAt, newBalance: newWC });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Error processing subscription:', error);

    // Try to log failed payment attempt (best-effort)
    try {
      const uid = userId || null;
      if (uid) {
        await pool.query(`
          INSERT INTO payments (user_id, amount, currency, status, payment_method, subscription_plan, description, error)
          VALUES ($1, $2, 'WildCredits', 'failed', $3, $4, 'DeepDive Pro Subscription', $5)
        `, [uid, amount, paymentMethod, plan, error.message]);
      }
    } catch (e2) {
      console.error('Failed to log payment error:', e2);
    }

    res.status(500).json({ error: 'Failed to process subscription', details: process.env.NODE_ENV === 'development' ? error.message : undefined });
  } finally {
    client.release();
  }
});

// Cancel subscription
app.post('/deepdive/subscription/cancel', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token required' });
  }
  
  const token = authHeader.substring(7);
  
  try {
    // Verify JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    const userId = decoded.userId || decoded.uid;
    
    if (!userId) {
      return res.status(400).json({ error: 'Invalid user ID in token' });
    }
    
    // Update subscription status to cancelled
    const { rowCount } = await pool.query(
      `UPDATE subscriptions 
       SET status = 'cancelled', cancelled_at = NOW() 
       WHERE user_id = $1 AND status = 'active'`,
      [userId]
    );
    
    if (rowCount === 0) {
      return res.status(404).json({ error: 'No active subscription found' });
    }
    
    res.json({ 
      success: true, 
      message: 'Subscription cancelled successfully',
      cancelledAt: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('Error cancelling subscription:', error);
    res.status(500).json({ 
      error: 'Failed to cancel subscription',
      details: error.message 
    });
  }
});

// Get subscription history
app.get('/deepdive/subscription/history', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token required' });
  }
  
  const token = authHeader.substring(7);
  
  try {
    // Verify JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    const userId = decoded.userId || decoded.uid;
    
    if (!userId) {
      return res.status(400).json({ error: 'Invalid user ID in token' });
    }
    
    // Get subscription history
    const { rows: subscriptions } = await pool.query(
      `SELECT id, plan, status, starts_at as "startsAt", 
              ends_at as "endsAt", created_at as "createdAt",
              cancelled_at as "cancelledAt"
       FROM subscriptions 
       WHERE user_id = $1 
       ORDER BY created_at DESC`,
      [userId]
    );
    
    // Get payment history
    const { rows: payments } = await pool.query(
      `SELECT id, amount, currency, status, payment_method as "paymentMethod",
              subscription_plan as "subscriptionPlan", description, created_at as "createdAt"
       FROM payments 
       WHERE user_id = $1 
       ORDER BY created_at DESC`,
      [userId]
    );
    
    res.json({
      subscriptions,
      payments
    });
    
  } catch (error) {
    console.error('Error fetching subscription history:', error);
    res.status(500).json({ 
      error: 'Failed to fetch subscription history',
      details: error.message 
    });
  }
});

// Webhook for Ocean Pay payment notifications
app.post('/webhooks/ocean-pay', async (req, res) => {
  const signature = req.headers['ocean-pay-signature'];
  const payload = req.body;
  
  // Verify webhook signature (implement your verification logic)
  const isValidSignature = true; // Replace with actual verification
  
  if (!isValidSignature) {
    return res.status(401).json({ error: 'Invalid signature' });
  }
  
  const { event, data } = payload;
  
  try {
    switch (event) {
      case 'payment.succeeded':
        // Handle successful payment
        const { userId, amount, currency, paymentMethod, subscriptionPlan } = data;
        
        // Process the subscription
        const now = new Date();
        const endsAt = new Date(now);
        endsAt.setMonth(endsAt.getMonth() + (subscriptionPlan === 'yearly' ? 12 : 1));
        
        await pool.query(
          `INSERT INTO subscriptions 
           (user_id, plan, status, starts_at, ends_at, payment_method, payment_amount) 
           VALUES ($1, $2, 'active', $3, $4, $5, $6)
           ON CONFLICT (user_id) 
           DO UPDATE SET 
             plan = EXCLUDED.plan,
             status = 'active',
             starts_at = EXCLUDED.starts_at,
             ends_at = EXCLUDED.ends_at,
             payment_method = EXCLUDED.payment_method,
             payment_amount = EXCLUDED.payment_amount,
             updated_at = NOW()`,
          [userId, subscriptionPlan, now, endsAt, paymentMethod, amount]
        );
        
        // Log the payment
        await pool.query(
          `INSERT INTO payments 
           (user_id, amount, currency, status, payment_method, subscription_plan, description) 
           VALUES ($1, $2, $3, 'completed', $4, $5, 'DeepDive Pro Subscription')`,
          [userId, amount, currency, paymentMethod, subscriptionPlan]
        );
        
        break;
        
      case 'payment.failed':
        // Handle failed payment
        const { userId: failedUserId, error: paymentError } = data;
        
        // Log failed payment
        await pool.query(
          `INSERT INTO payments 
           (user_id, amount, currency, status, payment_method, subscription_plan, description, error) 
           VALUES ($1, $2, $3, 'failed', $4, $5, 'DeepDive Pro Subscription', $6)`,
          [failedUserId, data.amount, data.currency, data.paymentMethod, data.subscriptionPlan, paymentError]
        );
        
        break;
        
      default:
        console.log('Unhandled webhook event:', event);
    }
    
    res.status(200).json({ received: true });
  } catch (error) {
    console.error('Error processing webhook:', error);
    res.status(500).json({ error: 'Error processing webhook' });
  }
});

// Create necessary tables if they don't exist
async function createSubscriptionTables() {
  try {
    // Create subscriptions table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS subscriptions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        plan VARCHAR(50) NOT NULL,
        status VARCHAR(20) NOT NULL,
        starts_at TIMESTAMP WITH TIME ZONE NOT NULL,
        ends_at TIMESTAMP WITH TIME ZONE NOT NULL,
        payment_method VARCHAR(50),
        payment_amount DECIMAL(10, 2),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        cancelled_at TIMESTAMP WITH TIME ZONE
      )
    
    // Create payments table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS payments (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        amount DECIMAL(10, 2) NOT NULL,
        currency VARCHAR(10) NOT NULL,
        status VARCHAR(20) NOT NULL,
        payment_method VARCHAR(50),
        subscription_plan VARCHAR(50),
        description TEXT,
        error TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )`);
    
    // Create indexes for better performance
    await pool.query('CREATE INDEX IF NOT EXISTS idx_subscriptions_user_id ON subscriptions(user_id)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_subscriptions_status ON subscriptions(status)');
    await pool.query("CREATE UNIQUE INDEX IF NOT EXISTS ux_subscriptions_active_user ON subscriptions(user_id) WHERE status = 'active'");
    await pool.query('CREATE INDEX IF NOT EXISTS idx_payments_user_id ON payments(user_id)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_payments_created_at ON payments(created_at)');
    
    console.log('Subscription tables created successfully');
  } catch (error) {
    console.error('Error creating subscription tables:', error);
    throw error;
  }
}

// Call the function to create tables when the server starts
createSubscriptionTables().catch(console.error);

// Endpoint para obtener suscripción activa de WildShorts
app.get('/wildshorts/subscription/:userId', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }
  
  const token = authHeader.substring(7);
  let userId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    userId = decoded.uid;
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token inválido' });
  }
  
  try {
    const { rows } = await pool.query(`
      SELECT * FROM wildshorts_subs
      WHERE user_id = $1 AND active = true
      AND (ends_at IS NULL OR ends_at > NOW())
      ORDER BY created_at DESC
      LIMIT 1
    `, [userId]);
    
    res.json(rows[0] || null);
  } catch (e) {
    if (e.code === '42P01') {
      res.json(null);
    } else {
      console.error('Error obteniendo suscripción:', e);
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
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    userId = decoded.uid;
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token inválido' });
  }
  
  const { type, amount } = req.body; // type: 'daily', 'welcome', 'bonus', etc.
  if (!type) {
    return res.status(400).json({ error: 'Tipo de recompensa requerido' });
  }
  
  // Crear tabla e índices FUERA de la transacción (operaciones DDL)
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS wildgems_claims (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        claim_type TEXT NOT NULL,
        amount INTEGER NOT NULL,
        claimed_at TIMESTAMP DEFAULT NOW()
      )
    `);
    
    // Crear índice simple para mejorar el rendimiento de las consultas
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_wildgems_claims_user_type 
      ON wildgems_claims (user_id, claim_type)
    `).catch(() => {
      // Ignorar errores si el índice ya existe
    });
  } catch (ddlError) {
    // Ignorar errores de DDL si la tabla/índice ya existe
    console.log('[WildGems] Tabla/índice ya existe o error al crear:', ddlError.message);
  }
  
  // Verificar límites FUERA de la transacción
  const now = new Date();
  
  // Verificar si ya reclamó hoy (para recompensas diarias)
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
        error: `Ya reclamaste tu recompensa diaria hoy. Próxima recompensa en ${hoursUntil} horas.`,
        nextClaim: nextClaim.toISOString()
      });
    }
  }
  
  // Verificar si ya reclamó (para recompensas únicas)
  if (type === 'welcome') {
    const { rows: welcomeRows } = await pool.query(`
      SELECT * FROM wildgems_claims
      WHERE user_id = $1 AND claim_type = 'welcome'
    `, [userId]);
    
    if (welcomeRows.length > 0) {
      return res.status(400).json({ error: 'Ya reclamaste tu recompensa de bienvenida.' });
    }
  }
  
  // Verificar si la columna moneda existe FUERA de la transacción
  let hasMonedaColumn = false;
  try {
    const { rows: columnCheck } = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'ocean_pay_txs' AND column_name = 'moneda'
    `);
    hasMonedaColumn = columnCheck.length > 0;
  } catch (checkError) {
    // Si falla la verificación, asumir que no existe la columna (por defecto)
    hasMonedaColumn = false;
  }
  
  // Calcular cantidad si no se proporciona
  let gemsAmount = amount || 0;
  if (!gemsAmount) {
    const rewards = {
      daily: 50,      // 50 WildGems diarios
      welcome: 200,   // 200 WildGems de bienvenida
      bonus: 100,     // 100 WildGems de bono
      referral: 150,  // 150 WildGems por referido
      achievement: 75 // 75 WildGems por logro
    };
    gemsAmount = rewards[type] || 0;
  }
  
  if (gemsAmount <= 0) {
    return res.status(400).json({ error: 'Cantidad inválida' });
  }
  
  // Conceptos para las transacciones
  const conceptos = {
    daily: 'Recompensa Diaria (WildShorts)',
    welcome: 'Recompensa de Bienvenida (WildShorts)',
    bonus: 'Bono Especial (WildShorts)',
    referral: 'Recompensa por Referido (WildShorts)',
    achievement: 'Logro Desbloqueado (WildShorts)'
  };
  
  // Ahora sí, comenzar la transacción para las operaciones DML
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
      INSERT INTO ocean_pay_metadata (user_id, key, value)
      VALUES ($1, 'wildgems', $2)
      ON CONFLICT (user_id, key) 
      DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP
    `, [userId, newBalance.toString()]);
    
    // Registrar reclamación
    await client.query(`
      INSERT INTO wildgems_claims (user_id, claim_type, amount)
      VALUES ($1, $2, $3)
    `, [userId, type, gemsAmount]);
    
    // Insertar transacción según la estructura de la tabla (ya sabemos si tiene moneda)
    if (hasMonedaColumn) {
      await client.query(`
        INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
        VALUES ($1, $2, $3, $4, 'WG')
      `, [userId, conceptos[type] || `Recompensa ${type} (WildShorts)`, gemsAmount, 'WildShorts']);
    } else {
      await client.query(`
        INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen)
        VALUES ($1, $2, $3, $4)
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
    // Intentar hacer rollback si la transacción está activa
    try {
      await client.query('ROLLBACK');
    } catch (rollbackError) {
      // Ignorar errores de rollback si la transacción ya fue abortada
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
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    userId = decoded.uid;
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token inválido' });
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
    
    // Calcular próxima recompensa diaria
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
app.post('/wildshorts/episode/pay', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }
  
  const token = authHeader.substring(7);
  let userId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    userId = decoded.uid;
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token inválido' });
  }
  
  const { episodeId, episodePrice, requiredPlan } = req.body;
  if (!episodeId || episodePrice === undefined) {
    return res.status(400).json({ error: 'episodeId y episodePrice requeridos' });
  }
  
  // Verificar si la columna moneda existe FUERA de la transacción
  let hasMonedaColumn = false;
  try {
    const { rows: columnCheck } = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'ocean_pay_txs' AND column_name = 'moneda'
    `);
    hasMonedaColumn = columnCheck.length > 0;
  } catch (checkError) {
    // Si falla la verificación, asumir que no existe la columna
    hasMonedaColumn = false;
  }
  
  // Verificar suscripción FUERA de la transacción
  if (requiredPlan) {
    const { rows: subRows } = await pool.query(`
      SELECT plan_id FROM wildshorts_subs
      WHERE user_id = $1 AND active = true
      AND (ends_at IS NULL OR ends_at > NOW())
    `, [userId]);
    
    const planHierarchy = ['free', 'starter', 'explorer', 'adventurer', 'legend', 'ultra', 'founder'];
    const userPlan = subRows[0]?.plan_id || 'free';
    const requiredPlanIndex = planHierarchy.indexOf(requiredPlan);
    const userPlanIndex = planHierarchy.indexOf(userPlan);
    
    if (userPlanIndex < requiredPlanIndex) {
      return res.status(403).json({ error: 'Plan insuficiente para este episodio' });
    }
  }
  
  // Verificar saldo FUERA de la transacción
  const { rows: gemsRows } = await pool.query(`
    SELECT value FROM ocean_pay_metadata
    WHERE user_id = $1 AND key = 'wildgems'
  `, [userId]);
  
  const currentGems = parseInt(gemsRows[0]?.value || '0');
  const price = parseInt(episodePrice);
  
  if (currentGems < price) {
    return res.status(400).json({ error: `Saldo insuficiente. Necesitas ${price} WildGems.` });
  }
  
  // Ahora sí, comenzar la transacción para las operaciones DML
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    // Obtener saldo con FOR UPDATE dentro de la transacción
    const { rows: gemsRowsLocked } = await client.query(`
      SELECT value FROM ocean_pay_metadata
      WHERE user_id = $1 AND key = 'wildgems'
      FOR UPDATE
    `, [userId]);
    
    const currentGemsLocked = parseInt(gemsRowsLocked[0]?.value || '0');
    
    // Verificar saldo nuevamente (podría haber cambiado)
    if (currentGemsLocked < price) {
      await client.query('ROLLBACK');
      client.release();
      return res.status(400).json({ error: `Saldo insuficiente. Necesitas ${price} WildGems.` });
    }
    
    // Descontar WildGems
    const newBalance = currentGemsLocked - price;
    await client.query(`
      INSERT INTO ocean_pay_metadata (user_id, key, value)
      VALUES ($1, 'wildgems', $2)
      ON CONFLICT (user_id, key) 
      DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP
    `, [userId, newBalance.toString()]);
    
    // Registrar transacción según la estructura de la tabla (ya sabemos si tiene moneda)
    if (hasMonedaColumn) {
      await client.query(`
        INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
        VALUES ($1, $2, $3, $4, 'WG')
      `, [userId, `Episodio ${episodeId} (WildShorts)`, -price, 'WildShorts']);
    } else {
      await client.query(`
        INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen)
        VALUES ($1, $2, $3, $4)
      `, [userId, `Episodio ${episodeId} (WildShorts)`, -price, 'WildShorts']);
    }
    
    await client.query('COMMIT');
    client.release();
    
    res.json({ success: true, newBalance });
  } catch (e) {
    // Intentar hacer rollback si la transacción está activa
    try {
      await client.query('ROLLBACK');
    } catch (rollbackError) {
      // Ignorar errores de rollback si la transacción ya fue abortada
      console.log('[WildShorts] Error en rollback (posiblemente ya abortado):', rollbackError.message);
    }
    client.release();
    
    console.error('Error pagando episodio:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Endpoint para vincular Ocean Pay desde Wild Explorer o WildShorts
app.post('/ocean-pay/link-account', async (req, res) => {
  const { username, password, wildCredits, wildGems } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Faltan datos' });
  
  try {
    // Verificar credenciales
    const { rows } = await pool.query(`
      SELECT opu.id, opu.pwd_hash, opu.aquabux, opu.ecoxionums, opu.appbux,
             COALESCE(uc.amount, 0) as ecorebits
      FROM ocean_pay_users opu
      LEFT JOIN user_currency uc ON opu.id::text = uc.user_id AND uc.currency_type = 'ecocorebits'
      WHERE opu.username = $1
    `, [username]);

    if (rows.length === 0) return res.status(401).json({ error: 'Credenciales incorrectas' });
    
    const ok = await bcrypt.compare(password, rows[0].pwd_hash);
    if (!ok) return res.status(401).json({ error: 'Credenciales incorrectas' });
    
    const token = jwt.sign({ uid: rows[0].id, un: username }, process.env.STUDIO_SECRET, { expiresIn: '7d' });
    
    // WildCredits y WildGems se envían desde el cliente
    const wildCreditsValue = parseInt(wildCredits || '0');
    const wildGemsValue = parseInt(wildGems || '0');
    
    // Guardar wildCredits y wildGems en el servidor
    try {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS ocean_pay_metadata (
          user_id INTEGER NOT NULL,
          key TEXT NOT NULL,
          value TEXT NOT NULL,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          PRIMARY KEY (user_id, key)
        )
      `);
      
      if (wildCreditsValue > 0) {
        await pool.query(`
          INSERT INTO ocean_pay_metadata (user_id, key, value)
          VALUES ($1, 'wildcredits', $2)
          ON CONFLICT (user_id, key) 
          DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP
        `, [rows[0].id, wildCreditsValue.toString()]);
      }
      
      if (wildGemsValue > 0) {
        await pool.query(`
          INSERT INTO ocean_pay_metadata (user_id, key, value)
          VALUES ($1, 'wildgems', $2)
          ON CONFLICT (user_id, key) 
          DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP
        `, [rows[0].id, wildGemsValue.toString()]);
      }
    } catch (e) {
      console.warn('No se pudo guardar wildCredits/wildGems en servidor (continuando):', e.message);
    }
    
    // Obtener wildGems actualizado del servidor
    let serverWildGems = 0;
    try {
      const { rows: gemsRows } = await pool.query(`
        SELECT value FROM ocean_pay_metadata
        WHERE user_id = $1 AND key = 'wildgems'
      `, [rows[0].id]);
      serverWildGems = gemsRows.length > 0 ? parseInt(gemsRows[0].value || '0') : wildGemsValue;
    } catch (e) {
      serverWildGems = wildGemsValue;
    }
    
    res.json({
      success: true,
      token,
      user: {
        id: rows[0].id,
        username,
        aquabux: rows[0].aquabux || 0,
        ecoxionums: rows[0].ecoxionums || 0,
        ecorebits: Number(rows[0].ecorebits) || 0,
        wildcredits: wildCreditsValue,
        wildgems: serverWildGems,
        appbux: rows[0].appbux || 0
      },
      balances: {
        aquabux: rows[0].aquabux || 0,
        ecoxionums: rows[0].ecoxionums || 0,
        ecorebits: Number(rows[0].ecorebits) || 0,
        wildcredits: wildCreditsValue,
        wildgems: serverWildGems,
        appbux: rows[0].appbux || 0
      }
    });
  } catch (err) {
    console.error('Error in /ocean-pay/link-account:', err);
    res.status(500).json({ 
      error: 'Error interno del servidor',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

// Endpoint para obtener el historial de transacciones
app.get('/transaction-history', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.substring(7);
  
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    const userId = decoded.uid || decoded.userId;
    
    if (!userId) {
      return res.status(400).json({ error: 'ID de usuario no válido' });
    }

    // Obtener transacciones de Ocean Pay
    const { rows: oceanRows } = await pool.query(`
      SELECT concepto, monto, origen, created_at
      FROM ocean_pay_txs
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT 50
    `, [userId]);

    // Obtener transacciones de EcoCoreBits
    const { rows: ecbRows } = await pool.query(`
      SELECT concepto, monto, origen, created_at
      FROM ecocore_txs
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT 50
    `, [userId]);

    // Unificar y ordenar transacciones
    const allTransactions = [
      ...oceanRows.map(r => ({ ...r, moneda: 'AB' })),
      ...ecbRows.map(r => ({ ...r, moneda: 'ECB' }))
    ].sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
     .slice(0, 50);

    res.json(allTransactions);
  } catch (error) {
    console.error('Error fetching transaction history:', error);
    res.status(500).json({ 
      error: 'Error al obtener el historial',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Endpoint para obtener suscripción activa
app.get('/active/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const { rows } = await pool.query(
      'SELECT * FROM subscriptions WHERE user_id = $1 AND active = true',
      [userId]
    );
    res.json(rows[0] || null);
  } catch (error) {
    console.error('Error fetching active subscription:', error);
    res.status(500).json({ error: 'Error al obtener la suscripción' });
  }
});

// Endpoint para obtener historial de suscripciones
app.get('/history/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const { rows } = await pool.query(
      'SELECT * FROM subscriptions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50',
      [userId]
    );
    res.json(rows);
  } catch (error) {
    console.error('Error fetching subscription history:', error);
    res.status(500).json({ error: 'Error al obtener el historial' });
  }
});

app.post('/deepdive/subscription/subscribe', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token required' });
  }

  const { plan, paymentMethod, paymentAmount } = req.body;
  if (!plan || !paymentMethod || !paymentAmount) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const token = authHeader.substring(7);
  const client = await pool.connect();
  
  try {
    // Verify token and get user ID
    const { userId } = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    if (!userId) throw new Error('Invalid user ID in token');

    const now = new Date();
    const endsAt = new Date(now);
    endsAt.setMonth(endsAt.getMonth() + (plan === 'yearly' ? 12 : 1));

    await client.query('BEGIN');

    // Upsert subscription
    await client.query(`
      INSERT INTO subscriptions 
        (user_id, plan, status, starts_at, ends_at, payment_method, payment_amount) 
      VALUES ($1, $2, 'active', $3, $4, $5, $6)
      ON CONFLICT (user_id) 
      DO UPDATE SET 
        plan = EXCLUDED.plan,
        status = 'active',
        starts_at = EXCLUDED.starts_at,
        ends_at = EXCLUDED.ends_at,
        payment_method = EXCLUDED.payment_method,
        payment_amount = EXCLUDED.payment_amount,
        updated_at = NOW()
    `, [userId, plan, now, endsAt, paymentMethod, paymentAmount]);

    // Log payment
    await client.query(`
      INSERT INTO payments 
        (user_id, amount, currency, status, payment_method, subscription_plan, description) 
      VALUES ($1, $2, 'WildCredits', 'completed', $3, $4, 'DeepDive Pro Subscription')
    `, [userId, paymentAmount, paymentMethod, plan]);

    await client.query('COMMIT');
    
    res.json({ 
      success: true, 
      message: 'Subscription activated successfully',
      plan,
      endsAt
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Subscription error:', error.message);

    // Handle specific errors
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid token' });
    }
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Session expired' });
    }

    res.status(500).json({ 
      error: 'Failed to process subscription',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  } finally {
    client.release();
  }
});


/* ---------- ADMIN: listar usuarios ---------- */
app.get('/admin/users', async (req, res) => {
  const secret = req.headers['x-admin-secret'];
  if (secret !== process.env.STUDIO_SECRET) {
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

// === FUNCIONES DE REVISIÓN ===
async function ensureDatabase() {
  try {
    // Intentar conectar a la base de datos
    await pool.query("SELECT 1");
    console.log("✅ Conexión a la base de datos OK");
  } catch (err) {
    console.error("❌ La base de datos no existe o no se puede conectar:", err.message);
    process.exit(1); // Terminar servidor si falla
  }
}

async function ensureTables() {
  const tableQueries = [
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
          CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT now()
      );

      CREATE TABLE IF NOT EXISTS products (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        description TEXT,
        price DECIMAL,
        image_url TEXT,
        contact_number TEXT,
        created_at TIMESTAMP DEFAULT now()
      );

      CREATE TABLE IF NOT EXISTS user_ratings (
        id SERIAL PRIMARY KEY,
        rated_user_id INT REFERENCES users(id) ON DELETE CASCADE,
        rater_user_id INT REFERENCES users(id) ON DELETE CASCADE,
        rating INT CHECK (rating BETWEEN 1 AND 5),
        created_at TIMESTAMP DEFAULT now()
      );

  CREATE TABLE IF NOT EXISTS messages (
    id SERIAL PRIMARY KEY,
    sender_id INT REFERENCES users(id) ON DELETE CASCADE,
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

      CREATE TABLE IF NOT EXISTS ocean_pay_users (
    id          SERIAL PRIMARY KEY,
    username    VARCHAR(60) UNIQUE NOT NULL,
    pwd_hash    TEXT NOT NULL,
    aquabux     INTEGER DEFAULT 0,
    appbux      INTEGER DEFAULT 0,
    created_at  TIMESTAMP DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS oceanic_ethernet_users (
    id          SERIAL PRIMARY KEY,
    username    VARCHAR(60) UNIQUE NOT NULL,
    pwd_hash    TEXT NOT NULL,
    created_at  TIMESTAMP DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS oceanic_ethernet_txs (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES oceanic_ethernet_users(id) ON DELETE CASCADE,
    concepto    TEXT NOT NULL,
    monto       NUMERIC(20, 15) NOT NULL,
    origen      VARCHAR(50) DEFAULT 'OceanicEthernet',
    created_at  TIMESTAMP DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS oceanic_ethernet_user_links (
    id          SERIAL PRIMARY KEY,
    oe_user_id  INTEGER NOT NULL REFERENCES oceanic_ethernet_users(id) ON DELETE CASCADE,
    external_user_id INTEGER NOT NULL,
    external_system VARCHAR(50) NOT NULL, -- 'NatMarket', 'AllApp', etc.
    created_at  TIMESTAMP DEFAULT NOW(),
    UNIQUE(external_user_id, external_system)
  );

  CREATE TABLE IF NOT EXISTS tigertasks_backups (
    user_id TEXT PRIMARY KEY,
    backup_data JSONB NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS command_limit_extensions (
            id SERIAL PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id),
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
  
  -- Agregar columna appbux a ocean_pay_users si no existe
  DO $$ 
  BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'ocean_pay_users' AND column_name = 'appbux') THEN
      ALTER TABLE ocean_pay_users ADD COLUMN appbux INTEGER DEFAULT 0;
    END IF;
  END $$;
  
  -- Agregar user_unique_id y unique_id_shown a users_nat si no existen
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
  
  -- Crear tabla de reportes
  CREATE TABLE IF NOT EXISTS product_reports (
    id SERIAL PRIMARY KEY,
    product_id INTEGER NOT NULL REFERENCES products_nat(id) ON DELETE CASCADE,
    reporter_id INTEGER NOT NULL REFERENCES users_nat(id) ON DELETE CASCADE,
    reason TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'pending', -- pending, approved, rejected
    admin_id INTEGER REFERENCES users_nat(id) ON DELETE SET NULL,
    admin_response TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    reviewed_at TIMESTAMP
  );
  
  CREATE INDEX IF NOT EXISTS idx_product_reports_status ON product_reports(status);
  CREATE INDEX IF NOT EXISTS idx_product_reports_product ON product_reports(product_id);
  
  -- Agregar columnas de stock y vendido a products_nat si no existen
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
  
  -- Crear tabla de vistas únicas por usuario y producto
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
  
  -- Crear índice para búsquedas rápidas
  CREATE INDEX IF NOT EXISTS idx_ecoxion_subs_user_active ON ecoxion_subscriptions(user_id, active, ends_at);
`,
  ];

  for (const q of tableQueries) {
    await pool.query(q);
  }
  
  // Migración: Si la tabla command_limit_extensions existe con user_id INTEGER, cambiarla a TEXT
  try {
    const checkColumn = await pool.query(`
      SELECT data_type 
      FROM information_schema.columns 
      WHERE table_name = 'command_limit_extensions' 
      AND column_name = 'user_id'
    `);
    
    if (checkColumn.rows.length > 0 && checkColumn.rows[0].data_type === 'integer') {
      console.log('🔄 Migrando command_limit_extensions: cambiando user_id de INTEGER a TEXT...');
      
      // Eliminar foreign key constraint si existe
      await pool.query(`
        ALTER TABLE command_limit_extensions 
        DROP CONSTRAINT IF EXISTS command_limit_extensions_user_id_fkey
      `).catch(() => {}); // Ignorar si no existe
      
      // Cambiar el tipo de columna
      await pool.query(`
        ALTER TABLE command_limit_extensions 
        ALTER COLUMN user_id TYPE TEXT USING user_id::TEXT
      `);
      
      // Recrear la foreign key constraint
      await pool.query(`
        ALTER TABLE command_limit_extensions 
        ADD CONSTRAINT command_limit_extensions_user_id_fkey 
        FOREIGN KEY (user_id) REFERENCES users(id)
      `);
      
      console.log('✅ Migración completada: user_id ahora es TEXT');
    }
  } catch (err) {
    console.warn('⚠️ Error en migración de command_limit_extensions (puede ignorarse si la tabla no existe):', err.message);
  }
  
  console.log("✅ Todas las tablas existen o fueron creadas");
}

function handleNatError(res, err, place = '') {
  console.error(`[NAT-MARKET ${place}]`, err?.message || err);
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
            return res.status(404).json({ error: 'Usuario no encontrado o sin créditos.' });
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
    const userId = req.user.uid; // CORRECCIÓN: El token guarda el ID como 'uid'
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

        // 4. Deducir costo y registrar transacción
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
        res.json({ success: true, message: '¡Trato aceptado! El Key System ha sido desactivado permanentemente.', newBalance });

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

// GET - Obtener suscripción actual del usuario
app.get('/api/ecoxion/subscription/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    
    const { rows } = await pool.query(
      `SELECT * FROM ecoxion_subscriptions 
       WHERE user_id = $1 AND active = true AND ends_at > NOW()
       ORDER BY created_at DESC 
       LIMIT 1`,
      [userId]
    );
    
    if (rows.length === 0) {
      return res.json(null);
    }
    
    res.json({
      plan: rows[0].plan,
      startsAt: rows[0].starts_at,
      endsAt: rows[0].ends_at,
      createdAt: rows[0].created_at
    });
  } catch (err) {
    console.error('Error obteniendo suscripción:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// POST - Suscribirse a un plan
app.post('/api/ecoxion/subscribe', async (req, res) => {
  const { userId, plan } = req.body;
  
  if (!userId || !plan) {
    return res.status(400).json({ error: 'Faltan datos' });
  }
  
  if (plan !== 'pro') {
    return res.status(400).json({ error: 'Plan no válido' });
  }
  
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    // Verificar que el usuario existe en Ocean Pay
    const { rows: userRows } = await client.query(
      'SELECT id, ecoxionums FROM ocean_pay_users WHERE id::text = $1',
      [userId]
    );
    
    if (userRows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    
    // Verificar saldo (750 Ecoxionums)
    const currentBalance = userRows[0].ecoxionums || 0;
    if (currentBalance < 750) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Saldo insuficiente. Necesitas 750 Ecoxionums.' });
    }
    
    // Descontar Ecoxionums
    const newBalance = currentBalance - 750;
    await client.query(
      'UPDATE ocean_pay_users SET ecoxionums = $1 WHERE id::text = $2',
      [newBalance, userId]
    );
    
    // Cerrar suscripciones anteriores activas
    await client.query(
      `UPDATE ecoxion_subscriptions 
       SET active = false 
       WHERE user_id = $1 AND active = true`,
      [userId]
    );
    
    // Crear nueva suscripción (30 días)
    const now = new Date();
    const endsAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
    
    const { rows: subRows } = await client.query(
      `INSERT INTO ecoxion_subscriptions (user_id, plan, starts_at, ends_at, active)
       VALUES ($1, $2, $3, $4, true)
       RETURNING *`,
      [userId, plan, now, endsAt]
    );
    
    // Registrar transacción en Ocean Pay
    try {
      await client.query(
        `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
         VALUES ($1, $2, $3, $4, 'EX')`,
        [userId, 'Suscripción Plan Pro (Ecoxion)', -750, 'Ecoxion']
      );
    } catch (e) {
      // Si falla por falta de columna moneda, insertar sin ella
      await client.query(
        `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen)
         VALUES ($1, $2, $3, $4)`,
        [userId, 'Suscripción Plan Pro (Ecoxion)', -750, 'Ecoxion']
      );
    }
    
    await client.query('COMMIT');
    
    res.json({
      success: true,
      subscription: {
        plan: subRows[0].plan,
        startsAt: subRows[0].starts_at,
        endsAt: subRows[0].ends_at
      },
      newBalance
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error al suscribirse:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  } finally {
    client.release();
  }
});

// POST - Cancelar suscripción
app.post('/api/ecoxion/subscription/cancel', async (req, res) => {
  const { userId } = req.body;
  
  if (!userId) {
    return res.status(400).json({ error: 'Falta userId' });
  }
  
  try {
    const { rows } = await pool.query(
      `UPDATE ecoxion_subscriptions 
       SET active = false 
       WHERE user_id = $1 AND active = true 
       RETURNING *`,
      [userId]
    );
    
    if (rows.length === 0) {
      return res.status(400).json({ error: 'No tienes una suscripción activa' });
    }
    
    res.json({
      success: true,
      message: 'Suscripción cancelada. Seguirás teniendo acceso hasta la fecha de vencimiento.'
    });
  } catch (err) {
    console.error('Error al cancelar suscripción:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

/* ===== QUIZ KAHOOT SYSTEM ===== */

// Almacenamiento en memoria para salas activas (se puede migrar a Redis en producción)
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
  console.log("✅ Tablas de quiz inicializadas");
}

// Endpoints de API para quizzes
app.post('/api/quiz/create', async (req, res) => {
  try {
    const { userId, title, description, questions } = req.body;
    
    if (!title || !questions || !Array.isArray(questions) || questions.length === 0) {
      return res.status(400).json({ error: 'Título y preguntas son requeridos' });
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

    // Generar PIN único de 6 dígitos
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
    // Asegurar que las preguntas estén parseadas y normalizadas
    let questions = typeof quiz.questions === 'string' 
      ? JSON.parse(quiz.questions) 
      : quiz.questions;
    
    // Normalizar correctIndex a números para todas las preguntas
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
    console.error('Error creando sesión:', err);
    res.status(500).json({ error: 'Error al crear la sesión' });
  }
});

app.get('/api/quiz/session/:pin', async (req, res) => {
  try {
    const { pin } = req.params;
    
    // Primero buscar en memoria
    let room = activeRooms.get(pin);
    
    // Si no está en memoria, buscar en BD y recrear en memoria si está activa
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
      
      // Normalizar correctIndex a números
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
    console.error('Error obteniendo sesión:', err);
    res.status(500).json({ error: 'Error al obtener la sesión' });
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
    
    // Enviar información del quiz y jugadores actuales
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
      socket.emit('error', { message: 'La partida ya comenzó' });
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
    ).catch(err => console.error('Error actualizando sesión:', err));

    // Obtener preguntas
    let questions = typeof room.quiz.questions === 'string' 
      ? JSON.parse(room.quiz.questions) 
      : room.quiz.questions;
    
    // Normalizar correctIndex a números si es necesario
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

  // Jugador envía respuesta
  socket.on('submit-answer', ({ roomPin, playerId, answer, timeTaken }) => {
    console.log('submit-answer recibido:', { roomPin, playerId, answer, socketId: socket.id });
    const room = activeRooms.get(roomPin);
    if (!room) {
      console.log('Sala no encontrada:', roomPin);
      socket.emit('error', { message: 'Sala no encontrada' });
      return;
    }
    
    if (room.state !== 'playing') {
      console.log('Sala no está en estado playing:', room.state);
      socket.emit('error', { message: 'El juego no está en curso' });
      return;
    }

    // Buscar jugador por playerId o socketId
    const player = room.players.find(p => p.id === playerId || p.socketId === socket.id);
    if (!player) {
      console.log('Jugador no encontrado:', { playerId, socketId: socket.id, players: room.players.map(p => ({ id: p.id, socketId: p.socketId })) });
      socket.emit('error', { message: 'Jugador no encontrado en la sala' });
      return;
    }
    
    // Verificar si el jugador ya respondió esta pregunta
    const alreadyAnswered = player.answers.some(a => a.questionIndex === room.currentQuestion);
    if (alreadyAnswered) {
      console.log('Jugador ya respondió esta pregunta');
      return;
    }

    // Obtener y normalizar preguntas
    let questions = typeof room.quiz.questions === 'string' 
      ? JSON.parse(room.quiz.questions) 
      : room.quiz.questions;
    
    // Normalizar correctIndex a números si es necesario
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

    // Calcular puntos según el tipo de pregunta
    if (currentQ.type === 'multiple-choice') {
      // correctIndex puede ser un número o un array
      if (Array.isArray(currentQ.correctIndex)) {
        correct = currentQ.correctIndex.includes(parseInt(answer));
      } else {
        correct = parseInt(answer) === currentQ.correctIndex;
      }
    } else if (currentQ.type === 'single-choice') {
      // Opción única: un solo índice correcto
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
      console.log('Resultado validación true-false:', correct);
    } else if (currentQ.type === 'short-answer') {
      correct = answer.toLowerCase().trim() === currentQ.correctAnswer.toLowerCase().trim();
    } else if (currentQ.type === 'number') {
      const numAnswer = parseFloat(answer);
      const correctNum = typeof currentQ.correctAnswer === 'number' ? currentQ.correctAnswer : parseFloat(currentQ.correctAnswer);
      correct = Math.abs(numAnswer - correctNum) < 0.01; // Permitir pequeñas diferencias por redondeo
    } else if (currentQ.type === 'date') {
      correct = answer.trim() === currentQ.correctAnswer.trim();
    } else if (currentQ.type === 'fill-blank') {
      correct = answer.toLowerCase().trim() === currentQ.correctAnswer.toLowerCase().trim();
    } else if (currentQ.type === 'slider') {
      const sliderAnswer = parseFloat(answer);
      const correctValue = typeof currentQ.correctAnswer === 'number' ? currentQ.correctAnswer : parseFloat(currentQ.correctAnswer);
      // Permitir pequeña tolerancia para valores numéricos
      correct = Math.abs(sliderAnswer - correctValue) < 0.01;
    } else if (currentQ.type === 'code') {
      correct = answer.toLowerCase().trim() === currentQ.correctAnswer.toLowerCase().trim();
    }

    if (correct) {
      // Puntos base: 1000, con bonus por velocidad (máximo 30 segundos)
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

  // Host muestra resultados después de cada pregunta
  socket.on('show-results', ({ roomPin }) => {
    const room = activeRooms.get(roomPin);
    if (!room) return;

    const questions = typeof room.quiz.questions === 'string' 
      ? JSON.parse(room.quiz.questions) 
      : room.quiz.questions;
    const currentQ = questions[room.currentQuestion];
    
    // Calcular estadísticas de respuestas
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

  // Desconexión
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

// Servir favicon (evitar error 404)
app.get('/favicon.ico', (_req, res) => {
  res.status(204).end();
});

await ensureDatabase(); 
await ensureTables();
await ensureQuizTables();

const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 API corriendo en http://0.0.0.0:${PORT}`);
  console.log(`🌐 Puerto: ${PORT}`);
  console.log(`🎮 Sistema de Quiz Kahoot activo`);
});
