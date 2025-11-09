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
      
      // Registrar transacción
      await client.query(`
        INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
        VALUES ($1, $2, $3, $4, 'WG')
      `, [userId, `Suscripción ${planId} (WildShorts) - Semanal`, -planPrice, 'WildShorts']).catch(async () => {
        await client.query(`
          INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen)
          VALUES ($1, $2, $3, $4)
        `, [userId, `Suscripción ${planId} (WildShorts) - Semanal`, -planPrice, 'WildShorts']);
      });
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
    console.error('Error en /ocean-pay/link-account:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Simple status endpoint
app.get('/api/status', (_req, res) => {
  res.json({
    status: 'online',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    uptime: process.uptime()
  });
});

/* ===== HELPERS: Admin ===== */
async function isAdminUserById(userId) {
  const { rows } = await pool.query('SELECT username FROM users_nat WHERE id = $1', [userId]);
  if (!rows.length) return false;
  const un = rows[0].username || '';
  return un === 'OceanandWild' || un === 'Jorge Barboza';
}
async function isAdminUsername(username) {
  return username === 'OceanandWild' || username === 'Jorge Barboza';
}

/* ===== SUPPORT CHATS ===== */
// request support chat (user)
app.post('/natmarket/support/request', async (req, res) => {
  const { user_id } = req.body;
  if (!user_id) return res.status(400).json({ error: 'user_id requerido' });
  try {
    // tables
    await pool.query(`
      CREATE TABLE IF NOT EXISTS support_chats (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users_nat(id) ON DELETE CASCADE,
        admin_id INTEGER REFERENCES users_nat(id),
        status TEXT NOT NULL DEFAULT 'open',
        created_at TIMESTAMP DEFAULT NOW(),
        closed_at TIMESTAMP,
        last_message_at TIMESTAMP DEFAULT NOW()
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS support_messages (
        id SERIAL PRIMARY KEY,
        chat_id INTEGER NOT NULL REFERENCES support_chats(id) ON DELETE CASCADE,
        sender_id INTEGER NOT NULL,
        sender_type TEXT NOT NULL, -- 'user' | 'admin'
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // if existing open chat, return
    const { rows: existing } = await pool.query(
      `SELECT sc.*, u.username as admin_username
       FROM support_chats sc LEFT JOIN users_nat u ON u.id = sc.admin_id
       WHERE sc.user_id = $1 AND sc.status = 'open' ORDER BY sc.created_at DESC LIMIT 1`,
      [user_id]
    );
    if (existing.length) return res.json({ chat: existing[0] });

    // pick admin randomly between OceanandWild and Jorge Barboza that exists
    const { rows: admins } = await pool.query(
      `SELECT id, username FROM users_nat WHERE username IN ('OceanandWild','Jorge Barboza')`
    );
    let adminId = null, adminUsername = null;
    if (admins.length) {
      const idx = Math.floor(Math.random() * admins.length);
      adminId = admins[idx].id; adminUsername = admins[idx].username;
    }

    const { rows: created } = await pool.query(
      `INSERT INTO support_chats (user_id, admin_id, status) VALUES ($1,$2,'open') RETURNING *`,
      [user_id, adminId]
    );
    created[0].admin_username = adminUsername;
    res.json({ chat: created[0] });
  } catch (err) {
    handleNatError(res, err, 'POST /natmarket/support/request');
  }
});

// list support chats (admin overview)
app.get('/natmarket/support/chats', async (req, res) => {
  try {
    const adminUsername = req.headers['x-user-username'] || '';
    if (!(await isAdminUsername(adminUsername))) return res.status(403).json({ error: 'No autorizado' });
    const status = (req.query.status || 'open').toString();
    const { rows } = await pool.query(
      `SELECT sc.*, u1.username AS user_username, u2.username AS admin_username
       FROM support_chats sc
       JOIN users_nat u1 ON u1.id = sc.user_id
       LEFT JOIN users_nat u2 ON u2.id = sc.admin_id
       WHERE sc.status = $1
       ORDER BY sc.last_message_at DESC NULLS LAST, sc.created_at DESC`,
      [status]
    );
    res.json(rows);
  } catch (err) {
    handleNatError(res, err, 'GET /natmarket/support/chats');
  }
});

// user's own support chats
app.get('/natmarket/support/my-chats/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    const status = (req.query.status || '').toString();
    const where = status ? 'AND sc.status = $2' : '';
    const params = status ? [userId, status] : [userId];
    const { rows } = await pool.query(
      `SELECT sc.*, u.username as admin_username
       FROM support_chats sc
       LEFT JOIN users_nat u ON u.id = sc.admin_id
       WHERE sc.user_id = $1 ${where}
       ORDER BY sc.created_at DESC`,
      params
    );
    res.json(rows);
  } catch (err) {
    handleNatError(res, err, 'GET /natmarket/support/my-chats/:userId');
  }
});

// get chat info (status, participants)
app.get('/natmarket/support/chats/:chatId', async (req, res) => {
  const { chatId } = req.params;
  try {
    const { rows } = await pool.query(`
      SELECT sc.*, u1.username AS user_username, u2.username AS admin_username
      FROM support_chats sc
      JOIN users_nat u1 ON u1.id = sc.user_id
      LEFT JOIN users_nat u2 ON u2.id = sc.admin_id
      WHERE sc.id = $1
    `, [chatId]);
    if (!rows.length) return res.status(404).json({ error: 'Chat no encontrado' });
    res.json(rows[0]);
  } catch (err) {
    handleNatError(res, err, 'GET /natmarket/support/chats/:chatId');
  }
});

// messages for a chat
app.get('/natmarket/support/chats/:chatId/messages', async (req, res) => {
  const { chatId } = req.params;
  try {
    const { rows } = await pool.query(
      `SELECT sm.*, u.username as sender_username
       FROM support_messages sm
       LEFT JOIN users_nat u ON u.id = sm.sender_id
       WHERE sm.chat_id = $1 ORDER BY sm.created_at ASC`,
      [chatId]
    );
    res.json(rows);
  } catch (err) {
    handleNatError(res, err, 'GET /natmarket/support/chats/:chatId/messages');
  }
});

// send a message in support chat
app.post('/natmarket/support/chats/:chatId/message', async (req, res) => {
  const { chatId } = req.params;
  const { sender_id, sender_type, message } = req.body;
  if (!sender_id || !sender_type || !message) return res.status(400).json({ error: 'Faltan datos' });
  try {
    const { rows: chatRows } = await pool.query('SELECT * FROM support_chats WHERE id=$1', [chatId]);
    if (!chatRows.length) return res.status(404).json({ error: 'Chat no encontrado' });
    if (chatRows[0].status === 'closed') return res.status(400).json({ error: 'Chat cerrado' });

    await pool.query(
      `INSERT INTO support_messages (chat_id, sender_id, sender_type, message) VALUES ($1,$2,$3,$4)`,
      [chatId, sender_id, sender_type, message]
    );
    await pool.query('UPDATE support_chats SET last_message_at = NOW() WHERE id=$1', [chatId]);
    res.json({ success: true });
  } catch (err) {
    handleNatError(res, err, 'POST /natmarket/support/chats/:chatId/message');
  }
});

// close a support chat (admin)
app.patch('/natmarket/support/chats/:chatId/close', async (req, res) => {
  const { chatId } = req.params;
  const { admin_id } = req.body;
  if (!admin_id) return res.status(400).json({ error: 'admin_id requerido' });
  try {
    if (!(await isAdminUserById(admin_id))) return res.status(403).json({ error: 'No autorizado' });
    const { rows: chatRows } = await pool.query('SELECT * FROM support_chats WHERE id=$1', [chatId]);
    if (!chatRows.length) return res.status(404).json({ error: 'Chat no encontrado' });
    await pool.query(
      "UPDATE support_chats SET status = 'closed', closed_at = NOW() WHERE id = $1",
      [chatId]
    );
    res.json({ success: true });
  } catch (err) {
    handleNatError(res, err, 'PATCH /natmarket/support/chats/:chatId/close');
  }
});

// Keep the existing status page route
app.get('/status', (_req, res) =>
  res.sendFile(join(__dirname, 'Ocean and Wild Studios Status', 'index.html'))
);



const FORBIDDEN = [
  // Drogas
  /\bcoca[ií]na\b/i, /\bporro\b/i, /\bmari[h]uana\b/i,
  /\bextasi[s]?\b/i, /\blsd\b/i, /\bmdma\b/i,
  /\banfetamina[s]?\b/i, /\bhero[íi]na\b/i, /\bmetanfetamina\b/i,
  /\bcrack\b/i, /\bcristal\b/i, /\bpeyote\b/i,
  /\bhongos?\b.*m[aá]gico[s]?\b/i, /\bmescalina\b/i, /\bketamina\b/i,
  /\bfentanilo\b/i, /\bopi[áa]ceo[s]?\b/i, /\bcode[ií]na\b/i,
  /\bmorfin[ao]\b/i, /\bopio\b/i, /\bhash[ií]sh\b/i,
  /\bpasta\s*b[áa]sica\b/i, /\bchiva\b/i, /\bchocolate\b/i,
  /\bcoca\b/i, /\bmar[ií]a\b/i, /\bmar[ií]huana\b/i,
  /\bganja\b/i, /\bweed\b/i, /\bgrifa\b/i,
  /\bmota\b/i, /\bhach[ií]s\b/i,
  
  // Lenguaje ofensivo/sexual
  /\bput[ao]s?\b/i, /\bpendej[ao]s?\b/i, /\bcabr[oó]n\b/i,
  /\bco[ñn]o\b/i, /\bcoj[oó]n\b/i, /\bverga\b/i,
  /\bpich[ao]\b/i, /\bchup[ao]\b/i, /\bmam[ao]\b/i,
  /\bcojer\b/i, /\bcoger\b/i, /\bviolar\b/i,
  /\bestupr[ao]\b/i, /\babus[ao]\b/i, /\bsexo\s*expl[ií]cito\b/i,
  /\bporn[oó]grafi[ao]\b/i, /\bxxx\b/i, /\bonlyfans\b/i,
  /\bdesnud[ao]s?\b/i, /\bnud[ao]s?\b/i, /\bdesnudo\b/i,
  /\bpel[íi]cula\s*porno\b/i, /\bvideo\s*porno\b/i,
  /\bwebcam\s*sex\b/i, /\bescort\b/i, /\bprostitut[ao]\b/i,
  /\bputer[ií]a\b/i, /\bwhore\b/i, /\bslut\b/i,
  /\bfuck\b/i, /\bfucking\b/i, /\bfucker\b/i,
  /\bshit\b/i, /\bbitch\b/i, /\basshole\b/i,
  
  // Contenido violento/peligroso
  /\bmatar\b/i, /\basesinar\b/i, /\basesino\b/i,
  /\bhomici[di]o\b/i, /\bsuicid[ao]\b/i, /\bmatarte\b/i,
  /\barma[s]?\b/i, /\brevolver\b/i, /\bpistola\b/i,
  /\bfusil\b/i, /\bmetralleta\b/i, /\bexplosivo\b/i,
  /\bbomba\b/i, /\bgranada\b/i, /\bdinamita\b/i,
  /\bterrorismo\b/i, /\bterrorista\b/i,
  
  // Estafas y fraudes
  /\bestafa\b/i, /\bfraude\b/i, /\bphishing\b/i,
  /\bclonar\s*tarjeta\b/i, /\bcuenta\s*bancaria\b/i,
  /\btransferencia\s*falsa\b/i, /\benga[ñn]o\b/i,
  /\bpyramid\s*scheme\b/i, /\bpiramidal\b/i,
  
  // Otros inapropiados
  /\bracismo\b/i, /\bracista\b/i, /\bhomof[oó]bico\b/i,
  /\bdiscriminaci[oó]n\b/i, /\bamenaza\b/i, /\bamenazar\b/i,
  /\bespam\b/i, /\bspam\b/i, /\bphishing\b/i,
  /\bmaldito\b/i, /\bmalparido\b/i, /\bhijo\s*de\s*puta\b/i,
  /\bchingar\b/i, /\bch[íi]ngame\b/i, /\bcarajo\b/i,
  /\bchingado\b/i, /\bverga\b/i, /\bpinche\b/i,
  /\bjod[ae]r\b/i, /\bjodido\b/i, /\bjoder\b/i,
  
  // Variaciones comunes
  /\bput[ao]s?\b/i, /\bpendej[ao]s?\b/i,
  /\bmierda\b/i, /\bcagada\b/i, /\bcagar\b/i,
];

function containsInappropriate(text = '') {
  const t = text.toLowerCase();
  return FORBIDDEN.some(rx => rx.test(t));
}

// Función para agregar un strike a un usuario
async function addStrike(userId, reason, productId = null, transactionClient = null) {
  const shouldRelease = !transactionClient;
  const client = transactionClient || await pool.connect();
  try {
    if (!transactionClient) {
      await client.query('BEGIN');
    }
    
    // Obtener strikes actuales
    const { rows } = await client.query(
      'SELECT strikes FROM users_nat WHERE id = $1',
      [userId]
    );
    
    if (rows.length === 0) {
      if (!transactionClient) {
        await client.query('ROLLBACK');
      }
      return { error: 'Usuario no encontrado' };
    }
    
    const currentStrikes = rows[0].strikes || 0;
    const newStrikes = currentStrikes + 1;
    
    // Actualizar strikes
    await client.query(
      'UPDATE users_nat SET strikes = $1 WHERE id = $2',
      [newStrikes, userId]
    );
    
    // Si llega a 3 strikes, banear por 3 días
    if (newStrikes >= 3) {
      const banUntil = new Date();
      banUntil.setDate(banUntil.getDate() + 3); // 3 días desde ahora
      
      await client.query(
        'UPDATE users_nat SET banned_until = $1, ban_reason = $2 WHERE id = $3',
        [banUntil, reason, userId]
      );
      
      // Crear notificación de baneo
      await client.query(
        `INSERT INTO notifications_nat (user_id, type, message, created_at)
         VALUES ($1, 'ban', $2, NOW())`,
        [userId, `🚫 Has sido baneado por 3 días. Razón: ${reason}. Tu cuenta se recuperará el ${banUntil.toLocaleDateString('es-AR')}.`]
      );
      
      if (!transactionClient) {
        await client.query('COMMIT');
      }
      return { 
        strikes: newStrikes, 
        banned: true, 
        banUntil: banUntil.toISOString(),
        reason 
      };
    }
    
    // Crear notificación de strike
    let strikeMessage = `⚠️ Has recibido un strike. Razón: ${reason}.`;
    if (productId) {
      // Intentar obtener el nombre del producto si existe
      let productName = null;
      if (transactionClient) {
        try {
          const { rows: productInfo } = await client.query(
            'SELECT name FROM products_nat WHERE id = $1',
            [productId]
          );
          if (productInfo.length > 0) {
            productName = productInfo[0].name;
          }
        } catch (err) {
          // Ignorar error, usar solo el ID
        }
      }
      
      if (productName) {
        strikeMessage += ` Este strike es por el producto: "${productName}" (ID: ${productId}).`;
      } else {
        strikeMessage += ` Este strike es por el producto ID: ${productId}.`;
      }
    }
    strikeMessage += ` Tienes ${newStrikes}/3 strikes. Con 3 strikes serás baneado por 3 días.`;
    
    // Si el producto ya fue eliminado, usar NULL para product_id para evitar problemas de foreign key
    // Pero primero intentamos con el product_id si existe
    let finalProductId = productId;
    
    // Verificar si el producto existe (solo si estamos en una transacción y productId no es null)
    if (productId && transactionClient) {
      try {
        const { rows: productCheck } = await client.query(
          'SELECT id FROM products_nat WHERE id = $1',
          [productId]
        );
        // Si el producto no existe, usar NULL
        if (productCheck.length === 0) {
          finalProductId = null;
          strikeMessage += ` (Nota: El producto ya fue eliminado)`;
        }
      } catch (checkErr) {
        // Si hay error al verificar, usar NULL para ser seguro
        finalProductId = null;
      }
    }
    
    await client.query(
      `INSERT INTO notifications_nat (user_id, type, message, product_id, created_at)
       VALUES ($1, 'strike', $2, $3, NOW())`,
      [userId, strikeMessage, finalProductId]
    );
    
    if (!transactionClient) {
      await client.query('COMMIT');
    }
    return { strikes: newStrikes, banned: false };
  } catch (err) {
    if (!transactionClient) {
      await client.query('ROLLBACK');
    }
    console.error('[STRIKES] Error:', err);
    return { error: err.message };
  } finally {
    if (shouldRelease) {
      client.release();
    }
  }
}

// Verificar si un usuario está baneado
async function isUserBanned(userId) {
  const { rows } = await pool.query(
    'SELECT banned_until, ban_reason FROM users_nat WHERE id = $1',
    [userId]
  );
  
  if (rows.length === 0 || !rows[0].banned_until) {
    return { banned: false };
  }
  
  const banUntil = new Date(rows[0].banned_until);
  const now = new Date();
  
  if (banUntil > now) {
    return { 
      banned: true, 
      banUntil: banUntil.toISOString(),
      reason: rows[0].ban_reason || 'Violación de términos'
    };
  } else {
    // El baneo expiró, limpiarlo
    await pool.query(
      'UPDATE users_nat SET banned_until = NULL, ban_reason = NULL WHERE id = $1',
      [userId]
    );
    return { banned: false };
  }
}

async function notifyModerator(type, targetId, content, senderId) {
  // Obtener id de OceanandWild
  const { rows } = await pool.query(
    "SELECT id FROM users_nat WHERE username = 'OceanandWild'"
  );
  if (!rows.length) return; // no existe aún
  const modId = rows[0].id;

  const msg = type === 'product'
    ? `Producto id:${targetId} pendiente de revisión (contenido: ${content})`
    : `Mensaje id:${targetId} pendiente de revisión (contenido: ${content})`;

const validDummyProductId = 1; // ← uno que exista
await pool.query(
  `INSERT INTO messages_nat (sender_id, product_id, message, created_at)
   VALUES ($1, $2, $3, NOW())`,
  [senderId, validDummyProductId, msg]
);
}

// === Estadísticas de usuarios ===
app.post("/api/save-country", async (req, res) => {
  const { userId, country, coreInitDate } = req.body;
  if (!userId) return res.status(400).json({ error: "Falta userId" });

  await pool.query(
    `INSERT INTO user_stats (user_id, country, core_init_date)
     VALUES ($1, $2, $3)
     ON CONFLICT (user_id) DO UPDATE
     SET country = EXCLUDED.country,
         core_init_date = EXCLUDED.core_init_date`,
    [userId, country || "Desconocido", coreInitDate || new Date()]
  );

  res.json({ success: true });
});




app.get("/api/stats/countries", async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT country, COUNT(*) as count FROM user_stats GROUP BY country ORDER BY count DESC`
  );
  res.json(rows);
});

// === Blogs ===
app.post("/api/blogs", async (req, res) => {
  const { title, content, author } = req.body;
  if (!title || !content) return res.status(400).json({ error: "Faltan datos" });

  const { rows } = await pool.query(
    `INSERT INTO blogs (title, content, author) VALUES ($1, $2, $3) RETURNING *`,
    [title, content, author || "Anónimo"]
  );

  res.json({ success: true, blog: rows[0] });
});

app.get("/api/blogs", async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT * FROM blogs ORDER BY created_at DESC LIMIT 20`
  );
  res.json(rows);
});

// Obtener todos los eclipses
app.get("/api/eclipse/all", async (_req, res) => {
  try {
    const { rows } = await pool.query(`SELECT * FROM eclipses ORDER BY start DESC`);
    res.json(rows);
  } catch (err) {
    console.error("Error en /api/eclipse/all:", err.message);
    res.status(500).json({ error: err.message });
  }
});


// Obtener el próximo eclipse
app.get("/api/eclipse/next", async (_req, res) => {
  try {
    const now = new Date();
    // Futuro o en curso
    let { rows } = await pool.query(
      `SELECT * FROM eclipses WHERE end_at >= $1 ORDER BY start ASC LIMIT 1`,
      [now]
    );

    if (rows.length === 0) {
      // Último pasado
      ({ rows } = await pool.query(
        `SELECT * FROM eclipses WHERE end_at < $1 ORDER BY start DESC LIMIT 1`,
        [now]
      ));
    }

    res.json(rows[0] || null);
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

// Historial de eclipses
app.get("/api/eclipse/history", async (_req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM eclipses WHERE start < $1 ORDER BY start DESC`,
      [new Date()]
    );
    res.json(rows);
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

// Marcar eclipse como anunciado
app.post("/api/eclipse/:id/announce", async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query(`UPDATE eclipses SET announced = TRUE WHERE id = $1`, [id]);
    res.json({ success: true });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

// Marcar eclipse como recompensado
app.post("/api/eclipse/:id/reward", async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query(`UPDATE eclipses SET rewarded = TRUE WHERE id = $1`, [id]);
    res.json({ success: true });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});





// === Extensiones ===
app.post("/api/extensions/save", async (req, res) => {
  const { userId, extensions } = req.body;
  if (!userId || !extensions) return res.status(400).json({ error: "Faltan datos" });

  await pool.query(
    `INSERT INTO installed_extensions (user_id, installed, updated_at)
     VALUES ($1, $2, NOW())
     ON CONFLICT (user_id) DO UPDATE SET installed = EXCLUDED.installed, updated_at = NOW()`,
    [userId, JSON.stringify(extensions)]
  );
  res.json({ success: true });
});

app.get("/api/extensions/:userId", async (req, res) => {
  const { userId } = req.params;
  try {
    const { rows } = await pool.query(`SELECT installed FROM installed_extensions WHERE user_id=$1`, [userId]);
    res.json(rows[0]?.installed || {});
  } catch (err) {
    console.error('❌ Error en GET /api/extensions/:userId:', err);
    res.json({});
  }
});

app.put("/api/extensions/:userId", async (req, res) => {
  const { userId } = req.params;
  const state = req.body;
  
  try {
    await pool.query(
      `INSERT INTO installed_extensions (user_id, installed, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (user_id) DO UPDATE SET installed = EXCLUDED.installed, updated_at = NOW()`,
      [userId, JSON.stringify(state)]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('❌ Error en PUT /api/extensions/:userId:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});



// 📌 Guardar instalación de extensión
app.post("/api/extensions/install", async (req, res) => {
  const { userId, extension } = req.body;
  if (!userId || !extension?.id) {
    return res.status(400).json({ error: "Faltan datos" });
  }

  try {
    // Actualizamos la columna `installed` agregando/modificando la clave
    await pool.query(
      `UPDATE installed_extensions
       SET installed = installed || $1::jsonb,
           updated_at = NOW()
       WHERE user_id = $2
      `,
      [JSON.stringify({ [extension.id]: extension }), userId]
    );

    // Si no existe el registro, lo insertamos
    const { rowCount } = await pool.query(
      `SELECT 1 FROM installed_extensions WHERE user_id=$1`,
      [userId]
    );

    if (rowCount === 0) {
      await pool.query(
        `INSERT INTO installed_extensions (user_id, installed, updated_at)
         VALUES ($1, $2, NOW())`,
        [userId, JSON.stringify({ [extension.id]: extension })]
      );
    }

    res.json({ success: true });

  } catch (err) {
    console.error("Error en /api/extensions/install:", err.message);
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/extensions/uninstall", async (req, res) => {
  const { userId, extensionId } = req.body;
  if (!userId || !extensionId) return res.status(400).json({ error: "Faltan datos" });

  try {
    await pool.query(
      `UPDATE installed_extensions
       SET installed = installed - $2,
           updated_at = NOW()
       WHERE user_id = $1`,
      [userId, extensionId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error("❌ Error en /uninstall:", err.message);
    res.status(500).json({ error: err.message });
  }
});

/* ---------- EcoLight ---------- */
app.post("/api/ecolight/state", async (req, res) => {
  const { userId, mood, pulse } = req.body;
  await pool.query(
    `INSERT INTO ecolight_state (user_id, mood, pulse, updated_at)
     VALUES ($1, $2, $3, NOW())
     ON CONFLICT (user_id) DO UPDATE
     SET mood = EXCLUDED.mood,
         pulse = EXCLUDED.pulse,
         updated_at = NOW()`,
    [userId, mood, pulse]
  );
  res.json({ success: true });
});

app.get("/api/ecolight/state/:userId", async (req, res) => {
  const { userId } = req.params;
  const { rows } = await pool.query(
    `SELECT mood, pulse FROM ecolight_state WHERE user_id = $1`,
    [userId]
  );
  res.json(rows[0] || { mood: "happy", pulse: 75 });
});

app.post("/api/ecolight/scenes", async (req, res) => {
  const { userId, scene } = req.body;
  await pool.query(
    `UPDATE ecolight_state
     SET scenes = COALESCE(scenes, '[]'::jsonb) || $2::jsonb
     WHERE user_id = $1`,
    [userId, JSON.stringify(scene)]
  );
  res.json({ success: true });
});

app.get("/api/ecolight/scenes/:userId", async (req, res) => {
  const { userId } = req.params;
  const { rows } = await pool.query(
    `SELECT COALESCE(scenes, '[]'::jsonb) AS scenes FROM ecolight_state WHERE user_id = $1`,
    [userId]
  );
  res.json(rows[0]?.scenes || []);
});

/* ----------  PREGUNTAS IA  ---------- */
const QUESTIONS_POOL = [
  {id:1, question:"¿Cuál es el planeta más grande del sistema solar?", category:"Ciencia", answer:"Júpiter"},
  {id:2, question:"¿En qué país nació el tango?", category:"Cultura", answer:"Argentina"},
  {id:3, question:"¿Qué elemento tiene el símbolo 'Au'?", category:"Química", answer:"Oro"},
  {id:4, question:"¿Quién pintó 'La noche estrellada'?", category:"Arte", answer:"Van Gogh"},
  {id:5, question:"¿Cuántos bits hay en un byte?", category:"Tecnología", answer:"8"}
];

/* 1) devuelve pregunta y **marca** como usada ya */
app.get('/api/ia-question/:userId', async (req,res)=>{
  const {userId} = req.params;
  const {rows} = await pool.query(
    `SELECT used_today FROM ia_state WHERE user_id = $1`,[userId]
  );
  const used = rows[0]?.used_today || [];
  const avail = QUESTIONS_POOL.filter(q=>!used.includes(q.id));
  if (!avail.length) return res.status(404).json(null);
  const q = avail[Math.floor(Math.random()*avail.length)];

  /* guardarla AHORA → no se repite */
  await pool.query(
    `UPDATE ia_state SET used_today = array_append(used_today,$2) WHERE user_id=$1`,
    [userId, q.id]
  );
  res.json(q);
});

/* 2) respuesta SIEMPRE correcta + recompensa + nivel en vivo */
app.post('/api/ia-answer/:userId', async (req,res)=>{
  const {userId} = req.params;
  const {questionId} = req.body;

  /* recompensa */
  const roll = Math.random();
  let reward = {type:'', amount:0};
  if (roll < 0.65){              // 65 % Ecoxionums
    reward.type = 'coins';
    reward.amount = 30 + Math.floor(Math.random()*21);   // 30-50
  }else{                         // 35 % EXP
    reward.type = 'exp';
    reward.amount = 25 + Math.floor(Math.random()*11);   // 25-35
  }

  /* aplicar recompensa y subir nivel si corresponde */
  const lvl = await getLevelLive(userId);          // nivel actual
  let newExp = lvl.exp + reward.amount;
  let newLvl = lvl.level;
  let needed = expForLevel(newLvl);
  while (newExp >= needed){                       // sube de nivel
    newExp -= needed;
    newLvl++;
    needed = expForLevel(newLvl);
  }
  await saveLevelLive(userId, newLvl, newExp);    // persiste

  res.json({success:true, reward, level:{level:newLvl, exp:newExp, nextExp:needed}});
});

/* 3) límite diario */
app.get('/api/ia-limit/:userId', async (req,res)=>{
  const {userId} = req.params;
  const now = new Date();
  const {rows} = await pool.query(
    `SELECT reset_at, array_length(used_today,1) AS used
     FROM ia_state WHERE user_id = $1`,[userId]
  );
  let reset = rows[0]?.reset_at;
  if (!reset || new Date(reset) <= now){
    reset = new Date(Date.now()+5*60*60*1000).toISOString();
    await pool.query(
      `INSERT INTO ia_state(user_id,used_today,reset_at) VALUES($1,'{}',$2)
       ON CONFLICT(user_id) DO UPDATE SET used_today='{}', reset_at=$2`,
      [userId, reset]
    );
    return res.json({remaining:3, nextReset:reset});
  }
  const used = rows[0]?.used||0;
  res.json({remaining:Math.max(0,3-used), nextReset:reset});
});

/* ----------  HELPERS LIVE  ---------- */
async function getLevelLive(userId){
  const {rows} = await pool.query(
    `SELECT level, exp FROM user_levels WHERE user_id = $1`,[userId]
  );
  return rows[0] || {level:1, exp:0};
}
async function saveLevelLive(userId, level, exp){
  await pool.query(
    `INSERT INTO user_levels (user_id, level, exp) VALUES ($1,$2,$3)
     ON CONFLICT (user_id) DO UPDATE SET level=$2, exp=$3`,
    [userId, level, exp]
  );
}
function expForLevel(lvl){
  return 100 * Math.pow(1.05, lvl-1);   // igual que tenías
}

// === RUTAS ===

// 📌 VERSIONES
app.get("/version", async (_req, res) => {
  try {
    const { rows } = await pool.query(
        "SELECT version, news, date FROM updates_ecoconsole ORDER BY date DESC LIMIT 1"
    );

    if (rows.length === 0) {
      return res.json({
        version: "1.0.0",
        news: "Mejoras de rendimiento.",
      });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error("❌ Error en /version:", err.message);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

// Frontend expects this endpoint to fetch featured update notes for the modal
app.get("/api/featured-update", async (_req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT version, news, date FROM updates_ecoconsole ORDER BY date DESC LIMIT 1"
    );
    if (rows.length === 0) return res.json(null);
    // The client can render either sections or raw news; we return news here
    res.json({ version: rows[0].version, date: rows[0].date, news: rows[0].news });
  } catch (err) {
    console.error("❌ Error en /api/featured-update:", err.message);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

app.post("/publish-version", async (req, res) => {
  const { secret, version, news } = req.body;
  if (secret !== process.env.STUDIO_SECRET)
    return res.status(401).json({ error: "No autorizado" });

  await pool.query(
    "INSERT INTO updates_ecoconsole (version, news, date) VALUES ($1, $2, NOW())",
    [version, news || ""]
  );

  res.json({ ok: true, msg: "Versión publicada" });
});

// 📌 SUGERENCIAS DE COMANDOS
app.post("/sugerir-comandos", async (req, res) => {
  const { userId, text } = req.body;
  if (!userId || !text || text.length < 10)
    return res.status(400).json({ error: "Datos inválidos" });

  const today = new Date().toISOString().slice(0, 10);

  const { rows } = await pool.query(
    "SELECT COUNT(*) FROM suggestions WHERE userId=$1 AND date::date=$2::date",
    [userId, today]
  );

  if (rows[0].count > 0)
    return res.status(429).json({ error: "Ya enviaste hoy." });

  await pool.query(
    "INSERT INTO suggestions (userId, text, date) VALUES ($1, $2, NOW())",
    [userId, text]
  );

  res.json({ ok: true, msg: "✅ Sugerencia guardada. Gracias." });
});

app.get("/sugerencias", async (req, res) => {
  const { secret, page = 1, perPage = 10 } = req.query;
  if (secret !== process.env.STUDIO_SECRET)
    return res.status(401).json({ error: "Clave incorrecta" });

  const { rows: countRows } = await pool.query("SELECT COUNT(*) FROM suggestions");
  const total = parseInt(countRows[0].count, 10);

  const { rows } = await pool.query(
    "SELECT * FROM suggestions ORDER BY date DESC OFFSET $1 LIMIT $2",
    [(page - 1) * perPage, perPage]
  );

  res.json({ total, page: Number(page), perPage: Number(perPage), list: rows });
});

// In your server.js, update the publish-event endpoint
app.post("/ecoconsole/publish-event", async (req, res) => {
    const { secret, name, keyword, musicURL, startAt, rewardBits = 100 } = req.body;
    
    if (secret !== process.env.STUDIO_SECRET) {
        return res.status(401).json({ error: "No autorizado" });
    }

    try {
        // Validate and parse the date
        let startDate;
        try {
            // Try parsing the date string directly
            startDate = new Date(startAt);
            
            // If the date is invalid, try fixing common issues
            if (isNaN(startDate.getTime())) {
                // Try removing any timezone offset and assume UTC
                const dateString = startAt.split(/[+-]\d{2}:\d{2}$/)[0];
                startDate = new Date(dateString + 'Z');
                
                if (isNaN(startDate.getTime())) {
                    throw new Error("Formato de fecha inválido");
                }
            }
        } catch (e) {
            return res.status(400).json({ 
                error: "Formato de fecha inválido",
                details: "Use el formato: YYYY-MM-DDTHH:mm:ss±HH:mm"
            });
        }

        // Convert to ISO string for consistent storage
        const utcDate = startDate.toISOString();
        
        const result = await pool.query(
            `INSERT INTO ecoconsole_events 
             (name, keyword, musicURL, startAt, rewardBits, created) 
             VALUES ($1, $2, $3, $4, $5, NOW())
             RETURNING *`,
            [name, keyword.toLowerCase(), musicURL, utcDate, rewardBits]
        );

        console.log('Evento creado:', {
            id: result.rows[0].id,
            name: result.rows[0].name,
            startAt: result.rows[0].startat
        });
        
        res.json({ 
            ok: true, 
            msg: "Evento EcoConsole programado",
            event: {
                ...result.rows[0],
                // Return the date in a more readable format
                formattedDate: new Date(result.rows[0].startat).toLocaleString('es-AR', {
                    timeZone: 'America/Argentina/Buenos_Aires',
                    dateStyle: 'medium',
                    timeStyle: 'short'
                })
            }
        });

    } catch (error) {
        console.error('Error al programar evento:', error);
        res.status(500).json({ 
            error: "Error al programar el evento",
            details: error.message
        });
    }
});

app.get("/ecoconsole/active-event", async (_req, res) => {
    try {
        // Primero, marcar como terminados los eventos con más de 24 horas
        await pool.query(`
            UPDATE ecoconsole_events 
            SET finished = true 
            WHERE startAt <= (NOW() - INTERVAL '24 hours')
            AND (finished IS NULL OR finished = false)
        `);

        // Obtener el evento activo (que haya empezado hace menos de 1 hora)
        const { rows } = await pool.query(`
            SELECT * FROM ecoconsole_events 
            WHERE startAt >= (NOW() - INTERVAL '1 hour')
            AND startAt <= NOW()
            AND (finished IS NULL OR finished = false)
            ORDER BY startAt DESC 
            LIMIT 1
        `);

        if (rows.length === 0) {
            console.log('No hay eventos activos actualmente');
            return res.json({ error: "No hay eventos activos" });
        }

        console.log('Evento activo encontrado:', {
            id: rows[0].id,
            name: rows[0].name,
            startAt: rows[0].startat,
            minutes_since_start: (new Date() - new Date(rows[0].startat)) / 60000
        });

        res.json(rows[0]);
    } catch (error) {
        console.error('Error en /ecoconsole/active-event:', error);
        res.status(500).json({ 
            error: "Error al obtener el evento activo",
            details: error.message
        });
    }
});

app.patch("/ecoconsole/finish-event", async (req, res) => {
  const { secret, eventId } = req.body;
  if (secret !== process.env.STUDIO_SECRET)
    return res.status(401).json({ error: "No autorizado" });

  await pool.query("UPDATE ecoconsole_events SET finished=true WHERE id=$1", [eventId]);
  res.json({ ok: true });
});

app.get("/ecoconsole/upcoming-events", async (req, res) => {
    try {
        const { rows } = await pool.query(`
            SELECT 
                id,
                name,
                keyword,
                musicURL,
                startAt,
                rewardBits,
                created,
                finished,
                TO_CHAR(
                    startAt AT TIME ZONE 'UTC' AT TIME ZONE 'America/Argentina/Buenos_Aires', 
                    'DD/MM/YYYY, hh12:mi:ss AM'
                ) as formatted_date
            FROM ecoconsole_events 
            WHERE startAt > NOW() - INTERVAL '1 hour'
            AND (finished IS NULL OR finished = false)
            ORDER BY startAt ASC
            LIMIT 5
        `);
        
        res.json(rows);
    } catch (error) {
        console.error('Error al obtener próximos eventos:', error);
        res.status(500).json({ 
            error: 'Error al obtener eventos',
            details: error.message
        });
    }
});

// En server.js, agrega esta función
async function cleanupOldEvents() {
    try {
        await pool.query(`
            DELETE FROM ecoconsole_events 
            WHERE startAt <= (NOW() - INTERVAL '36 hours')
        `);
        console.log('Limpieza de eventos antiguos completada');
    } catch (error) {
        console.error('Error al limpiar eventos antiguos:', error);
    }
}

// Ejecutar la limpieza cada 6 horas
setInterval(cleanupOldEvents, 6 * 60 * 60 * 1000);

// Ejecutar al inicio
cleanupOldEvents();

/* ===== NAT-MARKET ENDPOINTS ===== */
app.use('/uploads/nat', express.static(uploadDir)); // archivos estáticos

// AUTH
app.post('/natmarket/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username y password requeridos' });
    const hashed = await bcrypt.hash(password, 10);
    const userUniqueId = generateUserUniqueId(); // Generar ID único
    
    const { rows } = await pool.query(
      'INSERT INTO users_nat (username, password, user_unique_id) VALUES ($1,$2,$3) RETURNING id, username, user_unique_id',
      [username, hashed, userUniqueId]
    );
    
    // Devolver el ID único solo en el registro (se muestra una vez)
    res.json({ 
      id: rows[0].id, 
      username: rows[0].username,
      user_unique_id: rows[0].user_unique_id, // Solo se muestra en registro
      message: 'IMPORTANTE: Guarda este ID de Usuario Único. Será necesario para recuperar tu contraseña.'
    });
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'Usuario ya existe' });
    handleNatError(res, err, '/natmarket/register');
  }
});

app.post('/natmarket/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username y password requeridos' });
    const { rows } = await pool.query('SELECT id, username, password, user_unique_id FROM users_nat WHERE username=$1', [username]);
    if (rows.length === 0) return res.status(401).json({ error: 'Usuario no encontrado' });
    const ok = await bcrypt.compare(password, rows[0].password);
    if (!ok) return res.status(401).json({ error: 'Contraseña incorrecta' });
    
    // Si el usuario no tiene user_unique_id (usuario existente), generarlo automáticamente
    let userUniqueId = rows[0].user_unique_id;
    if (!userUniqueId) {
      userUniqueId = generateUserUniqueId();
      await pool.query('UPDATE users_nat SET user_unique_id = $1 WHERE id = $2', [userUniqueId, rows[0].id]);
    }
    
    // Verificar si está vinculado con OceanicEthernet
    const { rows: linkRows } = await pool.query(
      `SELECT oe_user_id FROM oceanic_ethernet_user_links 
       WHERE external_user_id = $1 AND external_system = 'NatMarket'`,
      [rows[0].id]
    );
    
    const isLinked = linkRows.length > 0;
    
    res.json({ 
      id: rows[0].id, 
      username: rows[0].username,
      needs_unique_id: !rows[0].user_unique_id,
      user_unique_id: !rows[0].user_unique_id ? userUniqueId : undefined,
      needs_oceanic_ethernet_link: !isLinked // Indica si necesita vincular OceanicEthernet
    });
  } catch (err) {
    handleNatError(res, err, '/natmarket/login');
  }
});

// USERS
app.get('/natmarket/users/:id', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, username, created_at FROM users_nat WHERE id=$1', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
    res.json(rows[0]);
  } catch (err) {
    handleNatError(res, err, 'GET /natmarket/users/:id');
  }
});

app.put('/natmarket/users/:id/password', async (req, res) => {
  try {
    const { id } = req.params;
    const { oldPassword, newPassword, user_unique_id } = req.body;
    
    if (!oldPassword || !newPassword) return res.status(400).json({ error: 'Faltan contraseñas' });
    if (!user_unique_id) return res.status(400).json({ error: 'Se requiere el ID de Usuario Único para cambiar la contraseña' });
    
    const { rows } = await pool.query('SELECT password, user_unique_id FROM users_nat WHERE id=$1', [id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
    
    // Verificar contraseña actual
    const ok = await bcrypt.compare(oldPassword, rows[0].password);
    if (!ok) return res.status(401).json({ error: 'Contraseña actual incorrecta' });
    
    // Verificar ID único de usuario
    if (rows[0].user_unique_id !== user_unique_id) {
      return res.status(403).json({ error: 'ID de Usuario Único incorrecto' });
    }
    
    const hashed = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users_nat SET password=$1 WHERE id=$2', [hashed, id]);
    res.json({ success: true, message: 'Contraseña actualizada exitosamente' });
  } catch (err) {
    handleNatError(res, err, 'PUT /natmarket/users/:id/password');
  }
});

// Verificar vinculación con OceanicEthernet
app.get('/natmarket/users/:id/oceanic-ethernet-link', async (req, res) => {
  try {
    const { id } = req.params;
    const { rows } = await pool.query(
      `SELECT oe_user_id FROM oceanic_ethernet_user_links 
       WHERE external_user_id = $1 AND external_system = 'NatMarket'`,
      [id]
    );
    res.json({ linked: rows.length > 0, oe_user_id: rows.length > 0 ? rows[0].oe_user_id : null });
  } catch (err) {
    handleNatError(res, err, 'GET /natmarket/users/:id/oceanic-ethernet-link');
  }
});

// Vincular cuenta de NatMarket con OceanicEthernet usando credenciales
app.post('/natmarket/users/:id/link-oceanic-ethernet', async (req, res) => {
  try {
    const { id } = req.params;
    const { oe_username, oe_password } = req.body;
    
    if (!oe_username || !oe_password) {
      return res.status(400).json({ error: 'Usuario y contraseña de OceanicEthernet requeridos' });
    }
    
    // Verificar credenciales de OceanicEthernet
    const { rows: oeRows } = await pool.query(
      'SELECT id FROM oceanic_ethernet_users WHERE username = $1',
      [oe_username]
    );
    
    if (oeRows.length === 0) {
      return res.status(401).json({ error: 'Usuario de OceanicEthernet no encontrado' });
    }
    
    const { rows: pwdRows } = await pool.query(
      'SELECT id, pwd_hash FROM oceanic_ethernet_users WHERE username = $1',
      [oe_username]
    );
    
    if (pwdRows.length === 0) {
      return res.status(401).json({ error: 'Error al verificar credenciales' });
    }
    
    const ok = await bcrypt.compare(oe_password, pwdRows[0].pwd_hash);
    if (!ok) {
      return res.status(401).json({ error: 'Contraseña de OceanicEthernet incorrecta' });
    }
    
    const oeUserId = pwdRows[0].id;
    
    // Crear o actualizar vinculación
    await pool.query(
      `INSERT INTO oceanic_ethernet_user_links (oe_user_id, external_user_id, external_system)
       VALUES ($1, $2, 'NatMarket')
       ON CONFLICT (external_user_id, external_system) 
       DO UPDATE SET oe_user_id = $1`,
      [oeUserId, id]
    );
    
    res.json({ success: true, message: 'Cuenta vinculada correctamente' });
  } catch (err) {
    handleNatError(res, err, 'POST /natmarket/users/:id/link-oceanic-ethernet');
  }
});

// PRODUCTS
app.post('/natmarket/products', upload.array('images', 10), async (req, res) => {
  try {
    const { user_id, name, description = null, price = null, contact_number = null, stock = 1, category = null, status = 'disponible' } = req.body;
    if (!user_id || !name) return res.status(400).json({ error: 'user_id y name son requeridos' });
    const stockNum = parseInt(stock) || 1;
    const { rows: [product] } = await pool.query(
      'INSERT INTO products_nat (user_id, name, description, price, contact_number, stock, category, status, published_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW()) RETURNING *',
      [user_id, name, description, price, contact_number, stockNum, category, status]
    );
    const host = process.env.BACKEND_URL || `https://${req.get('host')}`;
    const urls = (req.files || []).map(f => `${host}/uploads/nat/${f.filename}`);
    for (const url of urls) await pool.query('INSERT INTO product_images_nat (product_id, url) VALUES ($1,$2)', [product.id, url]);
    const { rows: imgs } = await pool.query('SELECT url FROM product_images_nat WHERE product_id=$1 ORDER BY created_at ASC', [product.id]);
    
    // Notificar a los seguidores del usuario
    try {
      const { rows: followers } = await pool.query(
        'SELECT follower_id FROM user_follows WHERE following_id = $1',
        [user_id]
      );
      
      if (followers.length > 0) {
        // Obtener el username del vendedor
        const { rows: [seller] } = await pool.query(
          'SELECT username FROM users_nat WHERE id = $1',
          [user_id]
        );
        const sellerName = seller?.username || 'Un usuario';
        
        // Crear notificaciones para cada seguidor
        for (const follower of followers) {
          await pool.query(
            `INSERT INTO notifications_nat (user_id, type, message, product_id, sender_id, created_at)
             VALUES ($1, 'new_product', $2, $3, $4, NOW())`,
            [
              follower.follower_id,
              `${sellerName} publicó un nuevo producto: "${name}"`,
              product.id,
              user_id
            ]
          );
        }
        console.log(`[NOTIFICATIONS] ${followers.length} notificaciones de nuevo producto creadas`);
      }
    } catch (notifErr) {
      console.error('[NOTIFICATIONS] Error notificando a seguidores:', notifErr);
      // No fallar la creación del producto si falla la notificación
    }
    
    res.json({ ...product, image_urls: imgs.map(i => i.url) });
  } catch (err) {
    handleNatError(res, err, 'POST /natmarket/products');
  }
});

app.post('/natmarket/products/:id/images', upload.array('images', 10), async (req, res) => {
  try {
    const productId = req.params.id;
    const { rows } = await pool.query('SELECT id FROM products_nat WHERE id=$1', [productId]);
    if (rows.length === 0) return res.status(404).json({ error: 'Producto no encontrado' });
    if (!req.files || req.files.length === 0) return res.status(400).json({ error: 'No se subieron imágenes' });
    const host = process.env.BACKEND_URL || `https://${req.get('host')}`;
    const urls = req.files.map(f => `${host}/uploads/nat/${f.filename}`);
    for (const url of urls) await pool.query('INSERT INTO product_images_nat (product_id, url) VALUES ($1,$2)', [productId, url]);
    const { rows: imgs } = await pool.query('SELECT url FROM product_images_nat WHERE product_id=$1 ORDER BY created_at ASC', [productId]);
    res.json({ success: true, image_urls: imgs.map(i => i.url) });
  } catch (err) {
    handleNatError(res, err, 'POST /natmarket/products/:id/images');
  }
});

app.get('/natmarket/products', async (_req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT p.*, u.username,
        COALESCE((SELECT ROUND(AVG(rating)::numeric,1) FROM user_ratings_nat WHERE rated_user_id=u.id),0) AS avg_rating
      FROM products_nat p
      JOIN users_nat u ON p.user_id = u.id
      ORDER BY COALESCE(p.published_at, p.created_at) DESC
    `);
    const products = await Promise.all(rows.map(async p => {
      const { rows: imgs } = await pool.query('SELECT url FROM product_images_nat WHERE product_id=$1 ORDER BY created_at ASC', [p.id]);
      // videos (tabla puede no existir aún)
      let vids = [];
      try {
        const { rows: v } = await pool.query('SELECT url FROM product_videos_nat WHERE product_id=$1 ORDER BY created_at ASC', [p.id]);
        vids = v;
      } catch (_) { vids = []; }

      // descuento activo (tabla puede no existir)
      let discount = null;
      let final_price = p.price;
      try {
        const { rows: d } = await pool.query(`
          SELECT percent, amount, starts_at, ends_at
          FROM product_discounts
          WHERE product_id = $1
            AND active = TRUE
            AND (starts_at IS NULL OR starts_at <= NOW())
            AND (ends_at IS NULL OR ends_at >= NOW())
          ORDER BY created_at DESC
          LIMIT 1
        `, [p.id]);
        if (d.length) {
          const row = d[0];
          if (row.amount != null) {
            final_price = Number(row.amount);
          } else if (row.percent != null && p.price != null) {
            final_price = Math.max(0, Number(p.price) * (1 - Number(row.percent) / 100));
          }
          discount = { percent: row.percent, amount: row.amount, final_price };
        }
      } catch (_) {}

      return { ...p, image_urls: imgs.map(i => i.url), video_urls: vids.map(v => v.url), final_price, discount };
    }));
    res.json(products);
  } catch (err) {
    handleNatError(res, err, 'GET /natmarket/products');
  }
});

app.patch('/natmarket/products/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { user_id, stock, sold, buyer_id } = req.body;
    
    if (!user_id) return res.status(400).json({ error: 'user_id requerido' });
    
    // Verificar que el producto existe y pertenece al usuario
    const { rows: productRows } = await pool.query('SELECT user_id, sold FROM products_nat WHERE id=$1', [id]);
    if (productRows.length === 0) return res.status(404).json({ error: 'Producto no encontrado' });
    if (Number(productRows[0].user_id) !== Number(user_id)) return res.status(403).json({ error: 'No autorizado' });
    
    const currentProduct = productRows[0];
    
    // Si el producto está vendido, NO permitir modificar el stock
    if (currentProduct.sold && stock !== undefined) {
      return res.status(400).json({ error: 'No se puede modificar el stock de un producto vendido' });
    }
    
    const updates = [];
    const values = [];
    let paramIndex = 1;
    
    if (stock !== undefined) {
      updates.push(`stock = $${paramIndex}`);
      values.push(parseInt(stock) || 0);
      paramIndex++;
    }
    
    if (sold !== undefined) {
      updates.push(`sold = $${paramIndex}`);
      values.push(sold === true || sold === 'true');
      paramIndex++;
    }
    
    if (buyer_id !== undefined) {
      updates.push(`buyer_id = $${paramIndex}`);
      values.push(buyer_id ? parseInt(buyer_id) : null);
      paramIndex++;
    }
    
    if (updates.length === 0) return res.status(400).json({ error: 'No hay campos para actualizar' });
    
    values.push(id);
    const query = `UPDATE products_nat SET ${updates.join(', ')} WHERE id = $${paramIndex} RETURNING *`;
    
    const { rows: [updated] } = await pool.query(query, values);
    res.json(updated);
  } catch (err) {
    handleNatError(res, err, 'PATCH /natmarket/products/:id');
  }
});

// Obtener participantes del chat de un producto (para seleccionar comprador)
app.get('/natmarket/products/:id/chat-participants', async (req, res) => {
  try {
    const { id } = req.params;
    const { user_id } = req.query;
    
    if (!user_id) return res.status(400).json({ error: 'user_id requerido' });
    
    // Verificar que el producto existe y pertenece al usuario
    const { rows: productRows } = await pool.query('SELECT user_id FROM products_nat WHERE id=$1', [id]);
    if (productRows.length === 0) return res.status(404).json({ error: 'Producto no encontrado' });
    if (Number(productRows[0].user_id) !== Number(user_id)) return res.status(403).json({ error: 'No autorizado' });
    
    // Obtener todos los usuarios que han participado en el chat de este producto (excluyendo al vendedor)
    const { rows } = await pool.query(`
      SELECT DISTINCT u.id, u.username
      FROM messages_nat m
      JOIN users_nat u ON m.sender_id = u.id
      WHERE m.product_id = $1 AND m.sender_id != $2
      ORDER BY u.username
    `, [id, user_id]);
    
    res.json(rows);
  } catch (err) {
    handleNatError(res, err, 'GET /natmarket/products/:id/chat-participants');
  }
});

app.delete('/natmarket/products/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { user_id } = req.body;
    if (!user_id) return res.status(400).json({ error: 'user_id requerido' });
    const { rows } = await pool.query('SELECT user_id FROM products_nat WHERE id=$1', [id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Producto no encontrado' });
    if (Number(rows[0].user_id) !== Number(user_id)) return res.status(403).json({ error: 'No autorizado' });
    // borrar imágenes físicas
    const { rows: imgs } = await pool.query('SELECT url FROM product_images_nat WHERE product_id=$1', [id]);
    for (const img of imgs) {
      const file = path.join(uploadDir, path.basename(img.url));
      if (fs.existsSync(file)) fs.unlinkSync(file);
    }
    await pool.query('DELETE FROM product_images_nat WHERE product_id=$1', [id]);
    // Al borrar un producto, las vistas también se borran automáticamente por CASCADE
    // pero asegurémonos de limpiar manualmente también
    await pool.query('DELETE FROM product_views_unique WHERE product_id=$1', [id]);
    const { rows: [deleted] } = await pool.query('DELETE FROM products_nat WHERE id=$1 RETURNING *', [id]);
    res.json({ success: true, deleted });
  } catch (err) {
    handleNatError(res, err, 'DELETE /natmarket/products/:id');
  }
});

/* ---------- REPUBLICAR PRODUCTO ---------- */
app.post('/natmarket/products/:id/repost', async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { id } = req.params;
    const { user_id, name, description, price, contact_number, stock, places, methods } = req.body;
    
    if (!user_id) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'user_id requerido' });
    }
    
    // Verificar si el usuario está vinculado con OceanicEthernet (OBLIGATORIO)
    const { rows: linkRows } = await client.query(
      `SELECT oe_user_id FROM oceanic_ethernet_user_links 
       WHERE external_user_id = $1 AND external_system = 'NatMarket'`,
      [user_id]
    );
    
    if (linkRows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(403).json({ 
        error: 'Debes vincular tu cuenta con OceanicEthernet para republicar productos. Ve a tu perfil para vincular.',
        needs_link: true
      });
    }
    
    const oeUserId = linkRows[0].oe_user_id;
    
    // Verificar que el producto existe y pertenece al usuario
    const { rows: productRows } = await client.query('SELECT * FROM products_nat WHERE id=$1', [id]);
    if (productRows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Producto no encontrado' });
    }
    if (Number(productRows[0].user_id) !== Number(user_id)) {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: 'No autorizado' });
    }
    
    const currentProduct = productRows[0];
    
    // Validar datos si se proporcionan para edición
    const newName = name || currentProduct.name;
    const newDescription = description !== undefined ? description : currentProduct.description;
    const newPrice = price !== undefined ? (price ? parseFloat(price) : null) : currentProduct.price;
    const newContact = contact_number !== undefined ? contact_number : currentProduct.contact_number;
    const newStock = stock !== undefined ? parseInt(stock) || 1 : currentProduct.stock;
    
    // Moderación si hay cambios en nombre/descripción
    const bad = containsInappropriate(newName + ' ' + (newDescription || ''));
    if (bad) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'El contenido contiene palabras inapropiadas' });
    }
    
    // Consumir internet al republicar producto (0.1 GB por producto)
    try {
      const { rows: metaRows } = await client.query(`
        SELECT value FROM ocean_pay_metadata
        WHERE user_id = $1 AND key = 'internet_gb'
        FOR UPDATE
      `, [oeUserId]);
      
      if (metaRows.length > 0) {
        const currentBalance = parseFloat(metaRows[0].value || '0');
        const internetCost = 0.1; // 0.1 GB por producto
        
        // Verificar saldo suficiente
        if (currentBalance < internetCost) {
          await client.query('ROLLBACK');
          return res.status(400).json({ 
            error: `Saldo insuficiente. Necesitas ${internetCost} GB de internet para republicar un producto. Tu saldo actual: ${currentBalance.toFixed(1)} GB`,
            insufficient_balance: true
          });
        }
        
        const newBalance = currentBalance - internetCost;
        
        await client.query(`
          UPDATE ocean_pay_metadata
          SET value = $1
          WHERE user_id = $2 AND key = 'internet_gb'
        `, [newBalance.toString(), oeUserId]);
        
        // Registrar transacción de consumo en tabla de OceanicEthernet
        await client.query(
          `INSERT INTO oceanic_ethernet_txs (user_id, concepto, monto, origen)
           VALUES ($1, $2, $3, $4)`,
          [oeUserId, `Republicar producto en NatMarket: ${newName}`, -internetCost, 'NatMarket']
        );
      } else {
        // No tiene saldo inicializado, requerir recarga
        await client.query('ROLLBACK');
        return res.status(400).json({ 
          error: 'No tienes saldo de internet. Recarga tu cuenta en OceanicEthernet para republicar productos.',
          insufficient_balance: true
        });
      }
    } catch (e) {
      await client.query('ROLLBACK');
      console.error('Error consumiendo internet en NatMarket:', e);
      return res.status(500).json({ error: 'Error al procesar el consumo de internet' });
    }
    
    // Actualizar producto con nueva fecha de publicación
    const { rows: [updated] } = await client.query(
      `UPDATE products_nat 
       SET name=$1, description=$2, price=$3, contact_number=$4, stock=$5, published_at=NOW(), sold=false, buyer_id=NULL
       WHERE id=$6 RETURNING *`,
      [newName, newDescription, newPrice, newContact, newStock, id]
    );
    
    // Parsear lugares y métodos si vienen como string JSON
    let placesArray = places;
    let methodsArray = methods;
    if (typeof places === 'string') {
      try { placesArray = JSON.parse(places); } catch { placesArray = []; }
    }
    if (typeof methods === 'string') {
      try { methodsArray = JSON.parse(methods); } catch { methodsArray = []; }
    }
    
    // Obtener lugares y métodos actuales si no se proporcionan
    if (!placesArray || placesArray.length === 0) {
      const { rows: currentPlaces } = await client.query('SELECT place_id FROM product_places WHERE product_id=$1', [id]);
      placesArray = currentPlaces.map(p => p.place_id.toString());
    }
    
    if (!methodsArray || methodsArray.length === 0) {
      const { rows: currentMethods } = await client.query('SELECT shipping_method_id FROM product_shipping_methods WHERE product_id=$1', [id]);
      methodsArray = currentMethods.map(m => m.shipping_method_id.toString());
    }
    
    // Actualizar lugares y métodos
    await client.query('DELETE FROM product_places WHERE product_id=$1', [id]);
    for (const pId of placesArray) {
      await client.query('INSERT INTO product_places (product_id, place_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [id, pId]);
    }
    
    await client.query('DELETE FROM product_shipping_methods WHERE product_id=$1', [id]);
    for (const mId of methodsArray) {
      await client.query('INSERT INTO product_shipping_methods (product_id, shipping_method_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [id, mId]);
    }
    
    // Resetear vistas para que aparezca como nuevo
    await client.query('DELETE FROM product_views_unique WHERE product_id=$1', [id]);
    await client.query('UPDATE products_nat SET views=0 WHERE id=$1', [id]);
    
    // Notificar a los seguidores del usuario (producto republicado)
    try {
      const { rows: followers } = await client.query(
        'SELECT follower_id FROM user_follows WHERE following_id = $1',
        [user_id]
      );
      
      if (followers.length > 0) {
        // Obtener el username del vendedor
        const { rows: [seller] } = await client.query(
          'SELECT username FROM users_nat WHERE id = $1',
          [user_id]
        );
        const sellerName = seller?.username || 'Un usuario';
        
        // Crear notificaciones para cada seguidor
        for (const follower of followers) {
          await client.query(
            `INSERT INTO notifications_nat (user_id, type, message, product_id, sender_id, created_at)
             VALUES ($1, 'new_product', $2, $3, $4, NOW())`,
            [
              follower.follower_id,
              `${sellerName} republicó un producto: "${newName}"`,
              id,
              user_id
            ]
          );
        }
        console.log(`[NOTIFICATIONS] ${followers.length} notificaciones de producto republicado creadas`);
      }
    } catch (notifErr) {
      console.error('[NOTIFICATIONS] Error notificando a seguidores:', notifErr);
      // No fallar el repost si falla la notificación
    }
    
    await client.query('COMMIT');
    res.json({ success: true, product: updated });
  } catch (err) {
    await client.query('ROLLBACK');
    handleNatError(res, err, 'POST /natmarket/products/:id/repost');
  } finally {
    client.release();
  }
});

/* ---------- BORRAR Y REPUBLICAR PRODUCTO ---------- */
app.post('/natmarket/products/:id/repost-delete', upload.array('images', 10), async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const { id } = req.params;
    const { user_id, name, description, price, contact_number, stock, places, methods } = req.body;
    
    if (!user_id) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'user_id requerido' });
    }
    
    // Verificar si el usuario está vinculado con OceanicEthernet (OBLIGATORIO)
    const { rows: linkRows } = await client.query(
      `SELECT oe_user_id FROM oceanic_ethernet_user_links 
       WHERE external_user_id = $1 AND external_system = 'NatMarket'`,
      [user_id]
    );
    
    if (linkRows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(403).json({ 
        error: 'Debes vincular tu cuenta con OceanicEthernet para republicar productos. Ve a tu perfil para vincular.',
        needs_link: true
      });
    }
    
    const oeUserId = linkRows[0].oe_user_id;
    
    // Verificar que el producto existe y pertenece al usuario
    const { rows: productRows } = await client.query('SELECT * FROM products_nat WHERE id=$1', [id]);
    if (productRows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Producto no encontrado' });
    }
    if (Number(productRows[0].user_id) !== Number(user_id)) {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: 'No autorizado' });
    }
    
    const currentProduct = productRows[0];
    
    // Usar datos editados o los actuales
    const newName = name || currentProduct.name;
    const newDescription = description !== undefined ? description : currentProduct.description;
    const newPrice = price !== undefined ? (price ? parseFloat(price) : null) : currentProduct.price;
    const newContact = contact_number !== undefined ? contact_number : currentProduct.contact_number;
    const newStock = stock !== undefined ? parseInt(stock) || 1 : currentProduct.stock;
    const placesArray = places ? JSON.parse(places) : [];
    const methodsArray = methods ? JSON.parse(methods) : [];
    
    // Validaciones
    if (!newName) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Nombre es obligatorio' });
    }
    
    // Moderación
    const bad = containsInappropriate(newName + ' ' + (newDescription || ''));
    if (bad) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'El contenido contiene palabras inapropiadas' });
    }
    
    // Consumir internet al borrar y republicar producto (0.1 GB por producto)
    try {
      const { rows: metaRows } = await client.query(`
        SELECT value FROM ocean_pay_metadata
        WHERE user_id = $1 AND key = 'internet_gb'
        FOR UPDATE
      `, [oeUserId]);
      
      if (metaRows.length > 0) {
        const currentBalance = parseFloat(metaRows[0].value || '0');
        const internetCost = 0.1; // 0.1 GB por producto
        
        // Verificar saldo suficiente
        if (currentBalance < internetCost) {
          await client.query('ROLLBACK');
          return res.status(400).json({ 
            error: `Saldo insuficiente. Necesitas ${internetCost} GB de internet para republicar un producto. Tu saldo actual: ${currentBalance.toFixed(1)} GB`,
            insufficient_balance: true
          });
        }
        
        const newBalance = currentBalance - internetCost;
        
        await client.query(`
          UPDATE ocean_pay_metadata
          SET value = $1
          WHERE user_id = $2 AND key = 'internet_gb'
        `, [newBalance.toString(), oeUserId]);
        
        // Registrar transacción de consumo en tabla de OceanicEthernet
        await client.query(
          `INSERT INTO oceanic_ethernet_txs (user_id, concepto, monto, origen)
           VALUES ($1, $2, $3, $4)`,
          [oeUserId, `Borrar y republicar producto en NatMarket: ${newName}`, -internetCost, 'NatMarket']
        );
      } else {
        // No tiene saldo inicializado, requerir recarga
        await client.query('ROLLBACK');
        return res.status(400).json({ 
          error: 'No tienes saldo de internet. Recarga tu cuenta en OceanicEthernet para republicar productos.',
          insufficient_balance: true
        });
      }
    } catch (e) {
      await client.query('ROLLBACK');
      console.error('Error consumiendo internet en NatMarket:', e);
      return res.status(500).json({ error: 'Error al procesar el consumo de internet' });
    }
    
    // Obtener imágenes, lugares y métodos actuales antes de borrar
    const { rows: currentImgs } = await client.query('SELECT url FROM product_images_nat WHERE product_id=$1', [id]);
    const { rows: currentPlaces } = await client.query('SELECT place_id FROM product_places WHERE product_id=$1', [id]);
    const { rows: currentMethods } = await client.query('SELECT shipping_method_id FROM product_shipping_methods WHERE product_id=$1', [id]);
    
    // Borrar producto (CASCADE borrará imágenes y relaciones)
    await client.query('DELETE FROM product_images_nat WHERE product_id=$1', [id]);
    await client.query('DELETE FROM product_views_unique WHERE product_id=$1', [id]);
    await client.query('DELETE FROM products_nat WHERE id=$1', [id]);
    
    // Crear nuevo producto
    const { rows: [newProduct] } = await client.query(
      `INSERT INTO products_nat (user_id, name, description, price, contact_number, stock, published_at)
       VALUES ($1,$2,$3,$4,$5,$6,NOW()) RETURNING *`,
      [user_id, newName, newDescription, newPrice, newContact, newStock]
    );
    
    // Subir nuevas imágenes si hay
    const host = process.env.BACKEND_URL || `https://${req.get('host')}`;
    const newUrls = (req.files || []).map(f => `${host}/uploads/nat/${f.filename}`);
    for (const url of newUrls) {
      await client.query('INSERT INTO product_images_nat (product_id, url) VALUES ($1,$2)', [newProduct.id, url]);
    }
    
    // Si no hay nuevas imágenes pero había imágenes anteriores, copiarlas
    if (newUrls.length === 0 && currentImgs.length > 0) {
      for (const img of currentImgs) {
        await client.query('INSERT INTO product_images_nat (product_id, url) VALUES ($1,$2)', [newProduct.id, img.url]);
      }
    }
    
    // Lugares: usar los proporcionados o los actuales
    const placesIds = placesArray.length > 0 ? placesArray : currentPlaces.map(p => p.place_id);
    for (const pId of placesIds) {
      await client.query('INSERT INTO product_places (product_id, place_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [newProduct.id, pId]);
    }
    
    // Métodos: usar los proporcionados o los actuales
    const methodsIds = methodsArray.length > 0 ? methodsArray : currentMethods.map(m => m.shipping_method_id);
    for (const mId of methodsIds) {
      await client.query('INSERT INTO product_shipping_methods (product_id, shipping_method_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [newProduct.id, mId]);
    }

    // Notificar a los seguidores del usuario (producto borrado y republicado)
    try {
      const { rows: followers } = await client.query(
        'SELECT follower_id FROM user_follows WHERE following_id = $1',
        [user_id]
      );
      
      if (followers.length > 0) {
        // Obtener el username del vendedor
        const { rows: [seller] } = await client.query(
          'SELECT username FROM users_nat WHERE id = $1',
          [user_id]
        );
        const sellerName = seller?.username || 'Un usuario';
        
        // Crear notificaciones para cada seguidor
        for (const follower of followers) {
          await client.query(
            `INSERT INTO notifications_nat (user_id, type, message, product_id, sender_id, created_at)
             VALUES ($1, 'new_product', $2, $3, $4, NOW())`,
            [
              follower.follower_id,
              `${sellerName} publicó un nuevo producto: "${newName}"`,
              newProduct.id,
              user_id
            ]
          );
        }
        console.log(`[NOTIFICATIONS] ${followers.length} notificaciones de producto nuevo creadas (repost-delete)`);
      }
    } catch (notifErr) {
      console.error('[NOTIFICATIONS] Error notificando a seguidores:', notifErr);
      // No fallar la creación si falla la notificación
    }
    
    await client.query('COMMIT');
    res.json({ success: true, product: newProduct });
  } catch (err) {
    await client.query('ROLLBACK');
    handleNatError(res, err, 'POST /natmarket/products/:id/repost-delete');
  } finally {
    client.release();
  }
});

// MESSAGES
app.post('/natmarket/messages', async (req, res) => {
  try {
    const { sender_id, product_id, message } = req.body;
    if (!sender_id || !product_id || !message) return res.status(400).json({ error: 'Faltan parámetros' });
    const { rows: [msg] } = await pool.query(
      'INSERT INTO messages_nat (sender_id, product_id, message) VALUES ($1,$2,$3) RETURNING *',
      [sender_id, product_id, message]
    );
    res.json(msg);
  } catch (err) {
    handleNatError(res, err, 'POST /natmarket/messages');
  }
});

app.post('/natmarket/messages/v2', async (req, res) => {
  const { sender_id, product_id, message, username } = req.body;
  
  // Validación estricta de parámetros
  if (!product_id || !message) {
    console.error('[MESSAGES] Faltan parámetros:', { sender_id, product_id, message: message ? 'presente' : 'faltante' });
    return res.status(400).json({ error: 'Faltan datos' });
  }

  // Asegurar que product_id sea un número
  const productIdNum = parseInt(product_id);
  
  if (isNaN(productIdNum)) {
    console.error('[MESSAGES] product_id inválido:', { product_id });
    return res.status(400).json({ error: 'product_id inválido' });
  }

  let senderIdNum;
  
  // Si product_id es 0, es chat global - manejar usuario automáticamente
  if (productIdNum === 0) {
    console.log(`[MESSAGES] Mensaje para chat global`);
    
    // Si se proporciona username, buscar o crear usuario automáticamente
    if (username) {
      const cleanUsername = username.trim().substring(0, 50); // Limitar longitud
      if (!cleanUsername) {
        return res.status(400).json({ error: 'Username inválido' });
      }
      
      try {
        // Buscar usuario existente por username
        let { rows: userRows } = await pool.query(
          'SELECT id FROM users_nat WHERE username = $1 LIMIT 1',
          [cleanUsername]
        );
        
        if (userRows.length > 0) {
          senderIdNum = userRows[0].id;
          console.log(`[MESSAGES] Usuario encontrado: ${cleanUsername} (id: ${senderIdNum})`);
        } else {
          // Crear nuevo usuario para chat global
          const { rows: newUserRows } = await pool.query(
            'INSERT INTO users_nat (username, created_at) VALUES ($1, NOW()) RETURNING id',
            [cleanUsername]
          );
          senderIdNum = newUserRows[0].id;
          console.log(`[MESSAGES] Nuevo usuario creado: ${cleanUsername} (id: ${senderIdNum})`);
        }
      } catch (userErr) {
        console.error('[MESSAGES] Error manejando usuario:', userErr);
        return res.status(500).json({ error: 'Error al procesar usuario' });
      }
    } else if (sender_id) {
      // Si se proporciona sender_id directamente, usarlo
      senderIdNum = parseInt(sender_id);
      if (isNaN(senderIdNum)) {
        return res.status(400).json({ error: 'sender_id inválido' });
      }
      
      // Verificar que el usuario existe
      const { rows: userCheck } = await pool.query(
        'SELECT id FROM users_nat WHERE id = $1',
        [senderIdNum]
      );
      if (userCheck.length === 0) {
        return res.status(404).json({ error: 'Usuario no encontrado' });
      }
    } else {
      return res.status(400).json({ error: 'Se requiere username o sender_id para chat global' });
    }
  } else {
    // Chat privado - requiere sender_id válido
    if (!sender_id) {
      return res.status(400).json({ error: 'Se requiere sender_id para chat privado' });
    }
    senderIdNum = parseInt(sender_id);
    if (isNaN(senderIdNum)) {
      return res.status(400).json({ error: 'sender_id inválido' });
    }
  }

  console.log(`[MESSAGES] Nuevo mensaje - sender_id: ${senderIdNum}, product_id: ${productIdNum}, mensaje: "${message.substring(0, 50)}..."`);

  let product = null;
  
  // Si product_id es 0, es chat global (no necesita verificar producto)
  if (productIdNum === 0) {
    // Ya manejado arriba
  } else {
    // Si product_id > 0, es chat privado - verificar que el producto existe
    const { rows: productRows } = await pool.query(
      'SELECT id, user_id, name FROM products_nat WHERE id = $1',
      [productIdNum]
    );
    
    if (productRows.length === 0) {
      console.error(`[MESSAGES] Producto no encontrado: ${productIdNum}`);
      return res.status(404).json({ error: 'Producto no encontrado' });
    }

    product = productRows[0];
    console.log(`[MESSAGES] Producto encontrado: "${product.name}" (id: ${product.id}), vendedor: ${product.user_id}`);
  }

  // Verificar si el usuario está baneado (después de obtener senderIdNum)
  const banCheck = await isUserBanned(senderIdNum);
  if (banCheck.banned) {
    const banUntil = new Date(banCheck.banUntil);
    return res.status(403).json({ 
      error: `Tu cuenta está baneada hasta el ${banUntil.toLocaleDateString('es-AR')}. Razón: ${banCheck.reason}` 
    });
  }

  const bad = containsInappropriate(message);
  if (bad) {
    await pool.query(
      `INSERT INTO messages_pending (product_id, sender_id, message)
       VALUES ($1,$2,$3)`,
      [productIdNum, senderIdNum, message]
    );
    await notifyModerator('message', productIdNum, message, senderIdNum);
    return res.status(202).json({
      warning: 'Tu mensaje está en revisión por contenido potencialmente inapropiado.'
    });
  }
  
  // si está OK, guardar directamente con validación explícita
  const { rows: [msg] } = await pool.query(
    `INSERT INTO messages_nat (sender_id, product_id, message) VALUES ($1,$2,$3) RETURNING id, sender_id, product_id, message, created_at`,
    [senderIdNum, productIdNum, message]
  );
  
  // Verificación adicional
  if (Number(msg.product_id) !== productIdNum) {
    console.error(`[MESSAGES] ERROR: Mensaje guardado con product_id incorrecto. Esperado: ${productIdNum}, Obtenido: ${msg.product_id}`);
  }
  
  console.log(`[MESSAGES] Mensaje guardado - ID: ${msg.id}, sender_id: ${msg.sender_id}, product_id: ${msg.product_id}, verificado: ${Number(msg.product_id) === productIdNum ? 'OK' : 'ERROR'}`);
    
    // Crear notificaciones solo para chats privados (product_id > 0)
    // El chat global (product_id = 0) no genera notificaciones
    if (productIdNum > 0 && product) {
      const sellerId = product.user_id;
      const isSellerMessage = senderIdNum === Number(sellerId);
    
    // Lista de usuarios a notificar
    const usersToNotify = new Set();
    
    if (isSellerMessage) {
      // Si el vendedor envía un mensaje, notificar a todos los que han participado (excepto el vendedor)
      const { rows: participants } = await pool.query(`
        SELECT DISTINCT sender_id 
        FROM messages_nat 
        WHERE product_id = $1 AND sender_id != $2
      `, [productIdNum, senderIdNum]);
      
      participants.forEach(p => usersToNotify.add(String(p.sender_id)));
    } else {
      // Si un usuario envía un mensaje, notificar al vendedor y a otros participantes
      usersToNotify.add(String(sellerId));
      
      const { rows: participants } = await pool.query(`
        SELECT DISTINCT sender_id 
        FROM messages_nat 
        WHERE product_id = $1 AND sender_id != $2 AND sender_id != $3
      `, [productIdNum, senderIdNum, sellerId]);
      
      participants.forEach(p => usersToNotify.add(String(p.sender_id)));
    }
    
    // Obtener nombre del remitente
    const { rows: senderRow } = await pool.query(
      'SELECT username FROM users_nat WHERE id = $1',
      [senderIdNum]
    );
    const senderName = senderRow[0]?.username || 'Alguien';
    
    // Crear notificaciones
    for (const userIdStr of usersToNotify) {
      const userId = parseInt(userIdStr);
      if (userId && Number(userId) !== senderIdNum) {
        try {
          await pool.query(`
            INSERT INTO notifications_nat (user_id, type, message, product_id, sender_id, created_at)
            VALUES ($1, 'message', $2, $3, $4, NOW())
          `, [
            userId,
            `${senderName} envió un mensaje sobre "${product.name}"`,
            productIdNum,
            senderIdNum
          ]);
          console.log(`[NOTIFICATIONS] Notificación creada para usuario ${userId} sobre producto ${productIdNum}`);
        } catch (notifErr) {
          console.error(`[NOTIFICATIONS] Error creando notificación para ${userId}:`, notifErr);
        }
      }
    }
    }
    
    res.json(msg);
});

app.get('/mod/pending', async (req, res) => {
  console.log('[DIAG] Headers:', req.headers);
  const userHeader = (req.headers['x-user-username'] || '').trim();

  if (userHeader.toLowerCase() !== 'oceanandwild') {
    console.log('[DIAG] 401 – No autorizado');
    return res.status(401).json({ error: 'No autorizado' }); // ← importante el return
  }

  try {
    const [prods, msgs] = await Promise.all([
      pool.query(`SELECT p.*, u.username AS owner
                  FROM products_pending p
                  JOIN users_nat u ON u.id = p.user_id
                  ORDER BY p.created_at DESC`),
      pool.query(`SELECT m.*, u.username AS sender_name, pr.name AS product_name
                  FROM messages_pending m
                  JOIN users_nat u ON u.id = m.sender_id
                  JOIN products_nat pr ON pr.id = m.product_id
                  ORDER BY m.created_at DESC`)
    ]);
    res.json({ products: prods.rows, messages: msgs.rows });
  } catch (err) {
    console.error('[DIAG] Error interno:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/mod/decide-product', async (req, res) => {
  if (req.headers['x-user-username'] !== 'OceanandWild') return res.status(401).json({ error: 'No autorizado' });

  const { pending_id, approve, reason } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows: [p] } = await client.query(
      'SELECT * FROM products_pending WHERE id = $1',
      [pending_id]
    );
    if (!p) return res.status(404).json({ error: 'No encontrado' });

    if (approve) {
      // 1. crear producto oficial
      const { rows: [prod] } = await client.query(
        `INSERT INTO products_nat (user_id, name, description, price, contact_number)
         VALUES ($1,$2,$3,$4,$5) RETURNING *`,
        [p.user_id, p.name, p.description, p.price, p.contact_number]
      );
      // 2. imágenes (no hay en pendientes, se avisará al usuario)
      // 3. lugares/métodos
      const places = typeof p.places === 'string' ? JSON.parse(p.places) : p.places;
      const methods = typeof p.methods === 'string' ? JSON.parse(p.methods) : p.methods;
      for (const pid of places)  await client.query('INSERT INTO product_places (product_id, place_id) VALUES ($1,$2)', [prod.id, pid]);
      for (const mid of methods) await client.query('INSERT INTO product_shipping_methods (product_id, shipping_method_id) VALUES ($1,$2)', [prod.id, mid]);
      
      await client.query('COMMIT');
      res.json({ ok: true });
    } else {
      // rechazar → dar strike al usuario
      const rejectReason = reason || 'Contenido inapropiado detectado en revisión';
      
      // Agregar strike
      const strikeResult = await addStrike(p.user_id, rejectReason, null, client);
      
      if (strikeResult.error) {
        await client.query('ROLLBACK');
        return res.status(500).json({ error: 'Error agregando strike: ' + strikeResult.error });
      }
      
      // Guardar en historial de rechazados
      await client.query(
        'INSERT INTO products_rejected (user_id, name, reason) VALUES ($1,$2,$3)',
        [p.user_id, p.name, rejectReason]
      );
      
      await client.query('DELETE FROM products_pending WHERE id = $1', [pending_id]);
      await client.query('COMMIT');
      res.json({ 
        ok: true, 
        strikes: strikeResult.strikes,
        banned: strikeResult.banned || false,
        banUntil: strikeResult.banUntil || null
      });
    }
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

/* ---------- MOD: mensajes pendientes ---------- */
app.get('/mod/pending-messages', async (req, res) => {
  const userHeader = (req.headers['x-user-username'] || '').trim().toLowerCase();
  if (userHeader !== 'oceanandwild') return res.status(401).json({ error: 'No autorizado' });

  try {
    const { rows } = await pool.query(`
      SELECT m.id,
             m.message,
             m.created_at,
             u.username  AS sender_name,
             pr.name     AS product_name,
             pr.id       AS product_id
      FROM messages_pending m
      JOIN users_nat u ON u.id = m.sender_id
      JOIN products_nat pr ON pr.id = m.product_id
      ORDER BY m.created_at DESC
    `);
    res.json(rows);
  } catch (err) {
    console.error('[MOD] Error listando mensajes:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

/* ---------- REPORTES DE PRODUCTOS ---------- */
// Reportar un producto
app.post('/natmarket/products/:id/report', async (req, res) => {
  try {
    const { id } = req.params;
    const { reporter_id, reason } = req.body;
    
    if (!reporter_id || !reason) {
      return res.status(400).json({ error: 'Faltan datos (reporter_id y reason requeridos)' });
    }
    
    // Verificar que el producto existe
    const { rows: productRows } = await pool.query(
      'SELECT id, user_id FROM products_nat WHERE id = $1',
      [id]
    );
    
    if (productRows.length === 0) {
      return res.status(404).json({ error: 'Producto no encontrado' });
    }
    
    // Verificar que no se reporte a sí mismo
    if (productRows[0].user_id === reporter_id) {
      return res.status(400).json({ error: 'No puedes reportar tu propio producto' });
    }
    
    // Verificar si ya existe un reporte pendiente de este usuario para este producto
    const { rows: existingReport } = await pool.query(
      'SELECT id FROM product_reports WHERE product_id = $1 AND reporter_id = $2 AND status = $3',
      [id, reporter_id, 'pending']
    );
    
    if (existingReport.length > 0) {
      return res.status(400).json({ error: 'Ya tienes un reporte pendiente para este producto' });
    }
    
    // Crear reporte
    const { rows: [report] } = await pool.query(
      `INSERT INTO product_reports (product_id, reporter_id, reason, status, created_at)
       VALUES ($1, $2, $3, 'pending', NOW()) RETURNING *`,
      [id, reporter_id, reason]
    );
    
    // Notificar a OceanandWild
    const { rows: adminRows } = await pool.query(
      "SELECT id FROM users_nat WHERE username = 'OceanandWild'"
    );
    
    if (adminRows.length > 0) {
      const adminId = adminRows[0].id;
      const { rows: reporterRows } = await pool.query(
        'SELECT username FROM users_nat WHERE id = $1',
        [reporter_id]
      );
      const reporterName = reporterRows[0]?.username || 'Un usuario';
      
      await pool.query(
        `INSERT INTO notifications_nat (user_id, type, message, product_id, created_at)
         VALUES ($1, 'report', $2, $3, NOW())`,
        [adminId, `📢 Nuevo reporte: ${reporterName} reportó un producto. Razón: ${reason}`, id]
      );
    }
    
    res.json({ success: true, report });
  } catch (err) {
    console.error('[REPORTS] Error:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Obtener todos los reportes (solo admin)
app.get('/natmarket/admin/reports', async (req, res) => {
  const userHeader = (req.headers['x-user-username'] || '').trim();
  const allowed = await isAdminUsername(userHeader);
  if (!allowed) {
    return res.status(401).json({ error: 'No autorizado' });
  }
  
  try {
    const { rows } = await pool.query(`
      SELECT 
        r.id,
        r.product_id,
        r.reporter_id,
        r.reason,
        r.status,
        r.created_at,
        r.reviewed_at,
        r.admin_response,
        p.name AS product_name,
        p.user_id AS product_owner_id,
        reporter.username AS reporter_username,
        owner.username AS owner_username
      FROM product_reports r
      JOIN products_nat p ON p.id = r.product_id
      JOIN users_nat reporter ON reporter.id = r.reporter_id
      JOIN users_nat owner ON owner.id = p.user_id
      ORDER BY r.created_at DESC
    `);
    res.json(rows);
  } catch (err) {
    console.error('[REPORTS] Error:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Aprobar o rechazar un reporte (solo admin)
app.post('/natmarket/admin/reports/:id/decide', async (req, res) => {
  const userHeader = (req.headers['x-user-username'] || '').trim();
  const allowed = await isAdminUsername(userHeader);
  if (!allowed) {
    return res.status(401).json({ error: 'No autorizado' });
  }
  
  const { id } = req.params;
  const { approve, admin_response } = req.body;
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    // Obtener el reporte
    const { rows: reportRows } = await client.query(
      `SELECT r.*, p.user_id AS product_owner_id
       FROM product_reports r
       JOIN products_nat p ON p.id = r.product_id
       WHERE r.id = $1`,
      [id]
    );
    
    if (reportRows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Reporte no encontrado' });
    }
    
    const report = reportRows[0];
    
    if (report.status !== 'pending') {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Este reporte ya fue revisado' });
    }
    
    // Obtener ID de admin
    const { rows: adminRows } = await client.query(
      "SELECT id FROM users_nat WHERE username = 'OceanandWild'"
    );
    const adminId = adminRows[0]?.id;
    
    if (approve) {
      // Aprobar: eliminar producto y dar strike al dueño
      const reason = admin_response || 'Producto reportado y eliminado por violación de términos';
      
      // Guardar el product_id y nombre del producto antes de eliminarlo
      const deletedProductId = report.product_id;
      
      // Obtener nombre del producto para la notificación
      const { rows: productRows } = await client.query(
        'SELECT name FROM products_nat WHERE id = $1',
        [deletedProductId]
      );
      const productName = productRows[0]?.name || `Producto ID: ${deletedProductId}`;
      
      // Crear razón completa con información del producto
      const fullReason = `${reason} Producto eliminado: "${productName}"`;
      
      // Dar strike al dueño del producto ANTES de eliminar el producto
      // (para que la notificación pueda referenciar el producto)
      const strikeResult = await addStrike(report.product_owner_id, fullReason, deletedProductId, client);
      
      if (strikeResult.error) {
        await client.query('ROLLBACK');
        console.error('[REPORTS] Error agregando strike:', strikeResult.error);
        return res.status(500).json({ error: 'Error agregando strike: ' + strikeResult.error });
      }
      
      // Ahora eliminar el producto (después de crear la notificación)
      await client.query('DELETE FROM products_nat WHERE id = $1', [deletedProductId]);
      
      // Actualizar reporte
      await client.query(
        `UPDATE product_reports 
         SET status = 'approved', admin_id = $1, admin_response = $2, reviewed_at = NOW()
         WHERE id = $3`,
        [adminId, admin_response || 'Reporte aprobado. Producto eliminado.', id]
      );
      
      await client.query('COMMIT');
      res.json({ 
        success: true, 
        message: 'Reporte aprobado. Producto eliminado.',
        strikes: strikeResult.strikes,
        banned: strikeResult.banned || false
      });
    } else {
      // Rechazar: dar strike al reporter
      const reason = admin_response || 'Reporte infundado. El producto no viola los términos.';
      
      const strikeResult = await addStrike(report.reporter_id, reason, null, client);
      
      if (strikeResult.error) {
        await client.query('ROLLBACK');
        console.error('[REPORTS] Error agregando strike:', strikeResult.error);
        return res.status(500).json({ error: 'Error agregando strike: ' + strikeResult.error });
      }
      
      // Actualizar reporte
      await client.query(
        `UPDATE product_reports 
         SET status = 'rejected', admin_id = $1, admin_response = $2, reviewed_at = NOW()
         WHERE id = $3`,
        [adminId, admin_response || 'Reporte rechazado. El producto no viola los términos.', id]
      );
      
      await client.query('COMMIT');
      res.json({ 
        success: true, 
        message: 'Reporte rechazado. Strike aplicado al reporter.',
        strikes: strikeResult.strikes,
        banned: strikeResult.banned || false
      });
    }
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[REPORTS] Error:', err);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

app.post('/mod/decide-message', async (req, res) => {
  const userHeader = (req.headers['x-user-username'] || '').trim().toLowerCase();
  if (userHeader !== 'oceanandwild') return res.status(401).json({ error: 'No autorizado' });

  const { pending_id, approve } = req.body;
  if (!pending_id) return res.status(400).json({ error: 'Falta pending_id' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1. Traer el mensaje
    const { rows: [m] } = await client.query(
      `SELECT m.*, u.username AS sender_name, pr.name AS product_name
       FROM messages_pending m
       JOIN users_nat u ON u.id = m.sender_id
       JOIN products_nat pr ON pr.id = m.product_id
       WHERE m.id = $1`,
      [pending_id]
    );
    if (!m) return res.status(404).json({ error: 'Mensaje no encontrado' });

    if (approve) {
      // 2.A. Mover a tabla oficial
      await client.query(
        `INSERT INTO messages_nat (sender_id, product_id, message, created_at)
         VALUES ($1, $2, $3, $4)`,
        [m.sender_id, m.product_id, m.message, m.created_at]
      );
    } else {
      // 2.B. Opcional: guardar rechazado (o solo ignorar)
      await client.query(
        `INSERT INTO messages_rejected (sender_id, product_id, message, reason, created_at)
         VALUES ($1, $2, $3, $4, NOW())`,
        [m.sender_id, m.product_id, m.message, 'Contenido inapropiado']
      );
    }

    // 3. Borrar de pendientes
    await client.query('DELETE FROM messages_pending WHERE id = $1', [pending_id]);
    await client.query('COMMIT');

    res.json({ ok: true });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[MOD] Error decidiendo mensaje:', err);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

app.get('/natmarket/users/:id/rejected', async (req, res) => {
  const { rows } = await pool.query(
    'SELECT name, reason, created_at FROM products_rejected WHERE user_id = $1 ORDER BY created_at DESC',
    [req.params.id]
  );
  res.json(rows);
});

app.get('/natmarket/messages/:product_id', async (req, res) => {
  try {
    const { product_id } = req.params;
    const productIdNum = parseInt(product_id);
    
    // Si product_id es 0, es el chat global (todos ven todos los mensajes globales)
    // Si product_id > 0, es un chat privado (solo ese producto)
    if (isNaN(productIdNum)) {
      return res.status(400).json({ error: 'product_id inválido' });
    }
    
    let query, params;
    
    if (productIdNum === 0) {
      // Chat global: solo mensajes con product_id = 0
      query = `
        SELECT m.*, u.username AS sender_username
        FROM messages_nat m
        JOIN users_nat u ON m.sender_id = u.id
        WHERE m.product_id = 0
        ORDER BY m.created_at ASC
      `;
      params = [];
    } else {
      // Chat privado: solo mensajes de ese producto específico
      query = `
        SELECT m.*, u.username AS sender_username
        FROM messages_nat m
        JOIN users_nat u ON m.sender_id = u.id
        WHERE m.product_id = $1
        ORDER BY m.created_at ASC
      `;
      params = [productIdNum];
    }
    
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    handleNatError(res, err, 'GET /natmarket/messages/:product_id');
  }
});

/* ========== ALLAPP – MENSAJES GLOBALES ========== */
// Inicializar tabla allapp_messages si no existe
async function initAllAppMessagesTable() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS allapp_messages (
        id SERIAL PRIMARY KEY,
        sender_username VARCHAR(50) NOT NULL,
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('[ALLAPP] Tabla allapp_messages inicializada');
  } catch (err) {
    console.error('[ALLAPP] Error creando tabla allapp_messages:', err);
    // Si la tabla ya existe, no es un error crítico
    if (!err.message.includes('already exists')) {
      throw err;
    }
  }
}

// Inicializar al arrancar
initAllAppMessagesTable().catch(err => {
  console.error('[ALLAPP] Error crítico inicializando tabla:', err);
});

// Endpoint específico para AllApp LionChat - Enviar mensajes
app.post('/allapp/messages', async (req, res) => {
  try {
    const { username, message } = req.body;
    
    // Validación de parámetros
    if (!username || !message) {
      console.error('[ALLAPP] Faltan parámetros:', { username, message: message ? 'presente' : 'faltante' });
      return res.status(400).json({ error: 'Se requiere username y message' });
    }
    
    const cleanUsername = username.trim().substring(0, 50);
    if (!cleanUsername) {
      return res.status(400).json({ error: 'Username inválido' });
    }
    
    console.log(`[ALLAPP] Nuevo mensaje - username: ${cleanUsername}, mensaje: "${message.substring(0, 50)}..."`);
    
    // Verificar contenido inapropiado
    const bad = containsInappropriate(message);
    if (bad) {
      // Guardar en tabla de pendientes (opcional, puede ser la misma tabla con un flag)
      return res.status(202).json({
        warning: 'Tu mensaje está en revisión por contenido potencialmente inapropiado.'
      });
    }
    
    // Guardar mensaje en tabla específica de AllApp
    const { rows: [msg] } = await pool.query(
      `INSERT INTO allapp_messages (sender_username, message) VALUES ($1, $2) RETURNING id, sender_username, message, created_at`,
      [cleanUsername, message]
    );
    
    console.log(`[ALLAPP] Mensaje guardado - ID: ${msg.id}, username: ${msg.sender_username}`);
    
    res.json(msg);
  } catch (err) {
    console.error('[ALLAPP] Error en POST /allapp/messages:', err);
    // Si la tabla no existe, intentar crearla y reintentar
    if (err.message.includes('does not exist') || err.message.includes('relation') || err.code === '42P01') {
      try {
        await initAllAppMessagesTable();
        // Reintentar inserción
        const { rows: [msg] } = await pool.query(
          `INSERT INTO allapp_messages (sender_username, message) VALUES ($1, $2) RETURNING id, sender_username, message, created_at`,
          [req.body.username.trim().substring(0, 50), req.body.message]
        );
        return res.json(msg);
      } catch (retryErr) {
        console.error('[ALLAPP] Error en reintento:', retryErr);
        return res.status(500).json({ error: 'Error al crear tabla de mensajes' });
      }
    }
    handleNatError(res, err, 'POST /allapp/messages');
  }
});

// Endpoint específico para AllApp LionChat - Obtener mensajes
app.get('/allapp/messages', async (req, res) => {
  try {
    // Obtener mensajes de la tabla específica de AllApp
    const { rows } = await pool.query(`
      SELECT 
        id,
        sender_username,
        message,
        created_at
      FROM allapp_messages
      ORDER BY created_at ASC
    `);
    
    console.log(`[ALLAPP] Obtenidos ${rows.length} mensajes del chat global`);
    res.json(rows);
  } catch (err) {
    console.error('[ALLAPP] Error en GET /allapp/messages:', err);
    // Si la tabla no existe, devolver array vacío
    if (err.message.includes('does not exist') || err.message.includes('relation') || err.code === '42P01') {
      try {
        await initAllAppMessagesTable();
        return res.json([]);
      } catch (initErr) {
        console.error('[ALLAPP] Error inicializando tabla:', initErr);
        return res.json([]);
      }
    }
    handleNatError(res, err, 'GET /allapp/messages');
  }
});

// NOTIFICACIONES
app.get('/natmarket/notifications/:user_id', async (req, res) => {
  try {
    const { user_id } = req.params;
    const { unread_only } = req.query; // opcional: ?unread_only=true
    const whereClause = unread_only === 'true' ? 'AND n.read = false' : '';
    
    const { rows } = await pool.query(`
      SELECT n.*, 
             u.username AS sender_username,
             p.name AS product_name
      FROM notifications_nat n
      LEFT JOIN users_nat u ON n.sender_id = u.id
      LEFT JOIN products_nat p ON n.product_id = p.id
      WHERE n.user_id = $1 ${whereClause}
      ORDER BY n.created_at DESC
      LIMIT 50
    `, [user_id]);
    res.json(rows);
  } catch (err) {
    handleNatError(res, err, 'GET /natmarket/notifications/:user_id');
  }
});

app.get('/natmarket/notifications/:user_id/count', async (req, res) => {
  try {
    const { user_id } = req.params;
    const { rows } = await pool.query(`
      SELECT COUNT(*) AS count
      FROM notifications_nat
      WHERE user_id = $1 AND read = false
    `, [user_id]);
    res.json({ count: parseInt(rows[0]?.count || 0) });
  } catch (err) {
    handleNatError(res, err, 'GET /natmarket/notifications/:user_id/count');
  }
});

app.patch('/natmarket/notifications/:id/read', async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query(`
      UPDATE notifications_nat SET read = true WHERE id = $1
    `, [id]);
    res.json({ success: true });
  } catch (err) {
    handleNatError(res, err, 'PATCH /natmarket/notifications/:id/read');
  }
});

app.patch('/natmarket/notifications/user/:user_id/read-all', async (req, res) => {
  try {
    const { user_id } = req.params;
    await pool.query(`
      UPDATE notifications_nat SET read = true WHERE user_id = $1 AND read = false
    `, [user_id]);
    res.json({ success: true });
  } catch (err) {
    handleNatError(res, err, 'PATCH /natmarket/notifications/user/:user_id/read-all');
  }
});

/* ===== SISTEMA DE SEGUIDORES ===== */
// Seguir a un usuario
app.post('/natmarket/users/:following_id/follow', async (req, res) => {
  try {
    const { following_id } = req.params;
    const { follower_id } = req.body;
    
    if (!follower_id) return res.status(400).json({ error: 'follower_id requerido' });
    if (Number(follower_id) === Number(following_id)) {
      return res.status(400).json({ error: 'No puedes seguirte a ti mismo' });
    }
    
    // Verificar que ambos usuarios existen
    const { rows: users } = await pool.query(
      'SELECT id, username FROM users_nat WHERE id IN ($1, $2)',
      [follower_id, following_id]
    );
    if (users.length !== 2) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    
    const follower = users.find(u => Number(u.id) === Number(follower_id));
    const following = users.find(u => Number(u.id) === Number(following_id));
    
    // Verificar si ya lo sigue
    const { rows: existing } = await pool.query(
      'SELECT id FROM user_follows WHERE follower_id = $1 AND following_id = $2',
      [follower_id, following_id]
    );
    
    if (existing.length > 0) {
      return res.status(400).json({ error: 'Ya sigues a este usuario' });
    }
    
    // Crear el seguimiento
    await pool.query(
      'INSERT INTO user_follows (follower_id, following_id) VALUES ($1, $2)',
      [follower_id, following_id]
    );
    
    // Crear notificación para el usuario seguido
    await pool.query(
      `INSERT INTO notifications_nat (user_id, type, message, sender_id, created_at)
       VALUES ($1, 'follower', $2, $3, NOW())`,
      [
        following_id,
        `Nuevo seguidor: ${follower.username}`,
        follower_id
      ]
    );
    
    res.json({ success: true, message: 'Usuario seguido exitosamente' });
  } catch (err) {
    if (err.code === '23505') { // Unique violation
      return res.status(400).json({ error: 'Ya sigues a este usuario' });
    }
    handleNatError(res, err, 'POST /natmarket/users/:following_id/follow');
  }
});

// Dejar de seguir a un usuario
app.post('/natmarket/users/:following_id/unfollow', async (req, res) => {
  try {
    const { following_id } = req.params;
    const { follower_id } = req.body;
    
    if (!follower_id) return res.status(400).json({ error: 'follower_id requerido' });
    
    // Verificar que existe el seguimiento
    const { rows } = await pool.query(
      'DELETE FROM user_follows WHERE follower_id = $1 AND following_id = $2 RETURNING id',
      [follower_id, following_id]
    );
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'No sigues a este usuario' });
    }
    
    // Obtener nombre del que deja de seguir
    const { rows: userRow } = await pool.query(
      'SELECT username FROM users_nat WHERE id = $1',
      [follower_id]
    );
    const username = userRow[0]?.username || 'Alguien';
    
    // Crear notificación para el usuario que fue dejado de seguir
    await pool.query(
      `INSERT INTO notifications_nat (user_id, type, message, sender_id, created_at)
       VALUES ($1, 'unfollow', $2, $3, NOW())`,
      [
        following_id,
        `${username} te ha dejado de seguir`,
        follower_id
      ]
    );
    
    res.json({ success: true, message: 'Dejaste de seguir al usuario' });
  } catch (err) {
    handleNatError(res, err, 'POST /natmarket/users/:following_id/unfollow');
  }
});

// Obtener seguidores de un usuario
app.get('/natmarket/users/:user_id/followers', async (req, res) => {
  try {
    const { user_id } = req.params;
    const { rows } = await pool.query(`
      SELECT u.id, u.username, u.created_at, uf.created_at AS followed_at
      FROM user_follows uf
      JOIN users_nat u ON uf.follower_id = u.id
      WHERE uf.following_id = $1
      ORDER BY uf.created_at DESC
    `, [user_id]);
    res.json(rows);
  } catch (err) {
    handleNatError(res, err, 'GET /natmarket/users/:user_id/followers');
  }
});

// Obtener usuarios que sigue un usuario
app.get('/natmarket/users/:user_id/following', async (req, res) => {
  try {
    const { user_id } = req.params;
    const { rows } = await pool.query(`
      SELECT u.id, u.username, u.created_at, uf.created_at AS followed_at
      FROM user_follows uf
      JOIN users_nat u ON uf.following_id = u.id
      WHERE uf.follower_id = $1
      ORDER BY uf.created_at DESC
    `, [user_id]);
    res.json(rows);
  } catch (err) {
    handleNatError(res, err, 'GET /natmarket/users/:user_id/following');
  }
});

// Verificar si un usuario sigue a otro
app.get('/natmarket/users/:user_id/is-following/:target_id', async (req, res) => {
  try {
    const { user_id, target_id } = req.params;
    const { rows } = await pool.query(
      'SELECT id FROM user_follows WHERE follower_id = $1 AND following_id = $2',
      [user_id, target_id]
    );
    res.json({ is_following: rows.length > 0 });
  } catch (err) {
    handleNatError(res, err, 'GET /natmarket/users/:user_id/is-following/:target_id');
  }
});

// Obtener todos los chats de un vendedor (productos con mensajes)
app.get('/natmarket/chats/:seller_id', async (req, res) => {
  try {
    const { seller_id } = req.params;
    console.log(`[CHATS] Obteniendo chats para vendedor: ${seller_id}`);
    
    // Primero obtener los productos con mensajes
    const { rows: productRows } = await pool.query(`
      SELECT DISTINCT p.id AS product_id, p.name AS product_name
      FROM products_nat p
      WHERE p.user_id = $1
        AND EXISTS (
          SELECT 1 FROM messages_nat m WHERE m.product_id = p.id
        )
    `, [seller_id]);
    
    console.log(`[CHATS] Productos base encontrados: ${productRows.length}`);
    
    // Luego obtener los detalles de cada producto
    const rows = await Promise.all(productRows.map(async (p) => {
      // Último mensaje
      const { rows: lastMsgRows } = await pool.query(`
        SELECT 
          u2.id AS sender_id,
          u2.username AS sender_username,
          m.message,
          m.created_at
        FROM messages_nat m
        JOIN users_nat u2 ON m.sender_id = u2.id
        WHERE m.product_id = $1
        ORDER BY m.created_at DESC
        LIMIT 1
      `, [p.product_id]);
      
      // Contador de participantes
      const { rows: participantsRows } = await pool.query(`
        SELECT COUNT(DISTINCT sender_id) AS count
        FROM messages_nat
        WHERE product_id = $1
      `, [p.product_id]);
      
      // Última actividad
      const { rows: activityRows } = await pool.query(`
        SELECT MAX(created_at) AS last_activity
        FROM messages_nat
        WHERE product_id = $1
      `, [p.product_id]);
      
      return {
        product_id: p.product_id,
        product_name: p.product_name,
        last_message: lastMsgRows.length > 0 ? [{
          sender_id: lastMsgRows[0].sender_id,
          sender_username: lastMsgRows[0].sender_username,
          message: lastMsgRows[0].message,
          created_at: lastMsgRows[0].created_at
        }] : null,
        participants_count: parseInt(participantsRows[0]?.count || 0),
        last_activity: activityRows[0]?.last_activity || null
      };
    }));
    
    // Ordenar por última actividad
    rows.sort((a, b) => {
      if (!a.last_activity && !b.last_activity) return 0;
      if (!a.last_activity) return 1;
      if (!b.last_activity) return -1;
      return new Date(b.last_activity) - new Date(a.last_activity);
    });
    
    console.log(`[CHATS] Encontrados ${rows.length} productos con mensajes para vendedor ${seller_id}`);
    console.log(`[CHATS] Primera fila de ejemplo:`, rows[0]);
    
    // Si no hay filas, devolver array vacío
    if (!rows || rows.length === 0) {
      console.log(`[CHATS] No hay productos, devolviendo array vacío`);
      return res.json([]);
    }
    
    // Obtener imágenes de cada producto
    console.log(`[CHATS] Procesando ${rows.length} productos para obtener imágenes...`);
    const chatsWithImages = await Promise.all(rows.map(async (chat, index) => {
      try {
        const { rows: imgRows } = await pool.query(
          'SELECT url FROM product_images_nat WHERE product_id = $1 ORDER BY created_at ASC LIMIT 1',
          [chat.product_id]
        );
        const result = {
          product_id: chat.product_id,
          product_name: chat.product_name,
          product_image: imgRows[0]?.url || null,
          last_message: chat.last_message || null,
          participants_count: chat.participants_count || 0,
          last_activity: chat.last_activity
        };
        console.log(`[CHATS] Producto ${index + 1}/${rows.length} procesado:`, result.product_id, result.product_name);
        return result;
      } catch (imgErr) {
        console.error(`[CHATS] Error obteniendo imagen para producto ${chat.product_id}:`, imgErr);
        return {
          product_id: chat.product_id,
          product_name: chat.product_name,
          product_image: null,
          last_message: chat.last_message || null,
          participants_count: chat.participants_count || 0,
          last_activity: chat.last_activity
        };
      }
    }));
    
    console.log(`[CHATS] Resultado final antes de enviar:`, chatsWithImages);
    console.log(`[CHATS] Es array?:`, Array.isArray(chatsWithImages));
    console.log(`[CHATS] Longitud:`, chatsWithImages.length);
    
    res.json(chatsWithImages);
  } catch (err) {
    console.error('[GET /natmarket/chats/:seller_id] Error:', err);
    // En caso de error, devolver array vacío en lugar de error
    res.json([]);
  }
});

// RATINGS
app.post('/natmarket/rate-product', async (req, res) => {
  try {
    const { product_id, rater_user_id, rating, comment } = req.body;
    if (!product_id || !rater_user_id || !rating) return res.status(400).json({ error: 'Faltan parámetros' });
    
    // Verificar que el producto existe
    const { rows } = await pool.query('SELECT user_id, sold, buyer_id FROM products_nat WHERE id=$1', [product_id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Producto no encontrado' });
    
    const product = rows[0];
    
    // Si el producto está vendido, solo el comprador puede calificarlo
    if (product.sold && product.buyer_id) {
      if (Number(product.buyer_id) !== Number(rater_user_id)) {
        return res.status(403).json({ error: 'Solo el comprador puede calificar este producto vendido' });
      }
    }
    
    await pool.query(
      `INSERT INTO user_ratings_nat (rated_user_id, rater_user_id, rating, comment, product_id, type)
       VALUES ($1,$2,$3,$4,$5,'product')`,
      [product.user_id, rater_user_id, rating, comment, product_id]
    );
    res.json({ success: true });
  } catch (err) {
    handleNatError(res, err, 'POST /natmarket/rate-product');
  }
});

app.post('/natmarket/rate-seller', async (req, res) => {
  try {
    const { seller_id, rater_user_id, rating, comment } = req.body;
    if (!seller_id || !rater_user_id || !rating) return res.status(400).json({ error: 'Faltan parámetros' });
    await pool.query(
      `INSERT INTO user_ratings_nat (rated_user_id, rater_user_id, rating, comment, type)
       VALUES ($1,$2,$3,$4,'seller')`,
      [seller_id, rater_user_id, rating, comment]
    );
    res.json({ success: true });
  } catch (err) {
    handleNatError(res, err, 'POST /natmarket/rate-seller');
  }
});

app.get('/natmarket/user-ratings/:user_id', async (req, res) => {
  try {
    const { user_id } = req.params;
    const { rows } = await pool.query(`
      SELECT r.*, u.username AS rater_username, p.name AS product_name
      FROM user_ratings_nat r
      JOIN users_nat u ON r.rater_user_id = u.id
      LEFT JOIN products_nat p ON p.user_id = r.rated_user_id
      WHERE r.rated_user_id = $1
      ORDER BY r.created_at DESC
    `, [user_id]);
    const avg = rows.length ? (rows.reduce((a, b) => a + b.rating, 0) / rows.length).toFixed(1) : 0;
    res.json({ avg_rating: avg, ratings: rows });
  } catch (err) {
    handleNatError(res, err, 'GET /natmarket/user-ratings/:user_id');
  }
});

app.get('/natmarket/ratings/product/:product_id', async (req, res) => {
  try {
    const { product_id } = req.params;
    const { rows } = await pool.query(`
      SELECT r.*, u.username AS rater_username
      FROM user_ratings_nat r
      JOIN users_nat u ON r.rater_user_id = u.id
      WHERE r.product_id = $1 AND r.type='product'
      ORDER BY r.created_at DESC
    `, [product_id]);
    const avg = rows.length ? (rows.reduce((a, b) => a + b.rating, 0) / rows.length).toFixed(1) : 0;
    res.json({ avg_rating: avg, ratings: rows });
  } catch (err) {
    handleNatError(res, err, 'GET /natmarket/ratings/product/:product_id');
  }
});

app.get('/natmarket/ratings/seller/:seller_id', async (req, res) => {
  try {
    const { seller_id } = req.params;
    const { rows } = await pool.query(`
      SELECT r.*, u.username AS rater_username, p.name AS product_name
      FROM user_ratings_nat r
      LEFT JOIN products_nat p ON r.product_id = p.id
      JOIN users_nat u ON r.rater_user_id = u.id
      WHERE r.rated_user_id = $1 AND r.type='seller'
      ORDER BY r.created_at DESC
    `, [seller_id]);
    const avg = rows.length ? (rows.reduce((a, b) => a + b.rating, 0) / rows.length).toFixed(1) : 0;
    res.json({ avg_rating: avg, ratings: rows });
  } catch (err) {
    handleNatError(res, err, 'GET /natmarket/ratings/seller/:seller_id');
  }
});


const PLANS = [
  { id: 'free', name: 'Plan Free', price: 0, perks: ['Acceso básico', 'Sin publicidad'], highlight: false },
  { id: 'eco-basic', name: 'Eco Basic', price: 200, perks: ['1 extensión premium/mes', 'Soporte prioritario'] },
  { id: 'eco-premium', name: 'Eco Premium', price: 500, perks: ['Extensiones exclusivas', 'Pack mensual sorpresa', 'Sin publicidad'], highlight: true },
];


/* -----  suscripción activa de un usuario  ----- */
app.get('/active/:userId', async (req, res) => {
  const { userId } = req.params;
  const row = await db.collection('subs').findOne({ userId, active: true });
  res.json(row || null);
});

/* -----  historial  ----- */
app.get('/history/:userId', async (req, res) => {
  const { userId } = req.params;
  const rows = await db.collection('subs')
    .find({ userId })
    .sort({ start: -1 })
    .limit(50)
    .toArray();
  res.json(rows);
});


app.get("/api/subscriptions/plans", (_req, res) => res.json(PLANS));

app.get("/api/subscriptions/active/:userId", async (req, res) => {
  const { userId } = req.params;
  try {
    const { rows } = await pool.query(
      `SELECT * FROM subs WHERE user_id = $1 AND active = true AND ends_at > NOW()`, // ✅ ends_at
      [userId]
    );
    res.json(rows[0] || null);
  } catch (err) {
    console.error("❌ /active ERROR:", err.message);
    res.status(500).json({ error: "Error interno" });
  }
});

app.get("/api/subscriptions/history/:userId", async (req, res) => {
  const { userId } = req.params;
  try {
    const { rows } = await pool.query(
      `SELECT * FROM subs WHERE user_id = $1 ORDER BY start DESC LIMIT 50`,
      [userId]
    );
    res.json(rows);
  } catch (err) {
    console.error("❌ /history:", err);
    res.status(500).json({ error: "Error interno" });
  }
});

// 🔥 DESCUENTO + COBRO MENSUAL REAL
app.post("/api/subscriptions/subscribe", async (req, res) => {
  const { userId, planId } = req.body;
  
  // Validar que userId y planId estén presentes
  if (!userId) {
    console.error("❌ /subscribe ERROR: userId faltante. Body recibido:", req.body);
    return res.status(400).json({ error: "userId es requerido" });
  }
  
  if (!planId) {
    console.error("❌ /subscribe ERROR: planId faltante. Body recibido:", req.body);
    return res.status(400).json({ error: "planId es requerido" });
  }
  
  const plan = PLANS.find(p => p.id === planId);
  if (!plan) {
    console.error("❌ /subscribe ERROR: Plan inválido. planId recibido:", planId, "Planes disponibles:", PLANS.map(p => p.id));
    return res.status(400).json({ error: `Plan inválido: ${planId}. Planes disponibles: ${PLANS.map(p => p.id).join(', ')}` });
  }
  
  // Asegurar que userId sea string
  const userIdStr = String(userId);

  const now = new Date();
  const end = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1) Verificar si tiene suscripción activa y si es upgrade
    const { rows: activeSub } = await client.query(
      `SELECT * FROM subs WHERE user_id = $1 AND active = true AND ends_at > NOW()`,
      [userIdStr]
    );
    
    // Guardar estado para usar después
    const hasActiveSub = activeSub.length > 0;
    const currentPlanId = hasActiveSub ? activeSub[0].plan_id : null;
    
    console.log(`📋 Verificando suscripciones activas para userId: ${userIdStr}`, {
      activeSubs: activeSub.length,
      activeSubData: activeSub
    });
    
    if (hasActiveSub) {
      const currentPlan = PLANS.find(p => p.id === currentPlanId);
      
      console.log(`📊 Comparando planes:`, {
        currentPlanId: currentPlanId,
        currentPlanFound: !!currentPlan,
        currentPlanPrice: currentPlan?.price,
        targetPlanId: plan.id,
        targetPlanPrice: plan.price,
        canUpgrade: currentPlan ? currentPlan.price < plan.price : true
      });
      
      // Si el plan actual no está en PLANS, permitimos la suscripción (plan inválido o desactualizado)
      if (!currentPlan) {
        console.log(`⚠️ Plan actual (${currentPlanId}) no encontrado en PLANS, permitiendo suscripción`);
        // Cancelaremos la suscripción anterior después de validar el saldo
      } else if (currentPlan.id === plan.id) {
        // El usuario ya tiene el mismo plan: permitimos renovar/extender la suscripción
        console.log(`🔄 Renovando suscripción al mismo plan: ${currentPlan.name}`);
        // Continuamos con el proceso para extender la fecha de vencimiento
      } else if (currentPlan.price >= plan.price) {
        await client.query('ROLLBACK');
        return res.status(400).json({ 
          error: `Ya tienes una suscripción activa al plan "${currentPlan.name}" (${currentPlan.price} Bits). Solo puedes suscribirte a un plan superior (${plan.name} cuesta ${plan.price} Bits) o renovar tu plan actual.` 
        });
      } else {
        // Es un upgrade válido, cerraremos la suscripción anterior después
        console.log(`✅ Upgrade válido: ${currentPlan.name} (${currentPlan.price}) → ${plan.name} (${plan.price})`);
      }
    }

    // 2) Leer saldo EcoCoreBits desde user_currency
    const { rows: curRows } = await client.query(
      `SELECT amount FROM user_currency WHERE user_id = $1 AND currency_type = 'ecocorebits' FOR UPDATE`,
      [userIdStr]
    );
    const current = curRows[0]?.amount || 0;
    if (current < plan.price) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: `Te faltan ${plan.price - current} EcoCoreBits.` });
    }

    const next = current - plan.price;
    await client.query(
      `INSERT INTO user_currency (user_id, currency_type, amount)
       VALUES ($1,'ecocorebits',$2)
       ON CONFLICT (user_id, currency_type)
       DO UPDATE SET amount = EXCLUDED.amount`,
      [userIdStr, next]
    );

    // 3) Registrar transacción en EcoCoreBits
    await client.query(
      `INSERT INTO ecocore_txs (user_id, concepto, monto, origen)
       VALUES ($1, $2, $3, $4)`,
      [userIdStr, 'Suscripción Plan Pro (EcoConsole)', -plan.price, 'EcoConsole']
    );

    // 4) Cerrar suscripción anterior (si existe)
    if (hasActiveSub) {
      await client.query(
        `UPDATE subs SET active = false, ends_at = NOW() WHERE user_id = $1 AND active = true`,
        [userIdStr]
      );
      console.log(`✅ Suscripción anterior cerrada para permitir nueva suscripción`);
    }

    // 5) Crear nueva suscripción
    const { rows } = await client.query(
      `INSERT INTO subs (user_id, plan_id, plan_name, start, ends_at, active)
       VALUES ($1, $2, $3, $4, $5, true) RETURNING *`,
      [userIdStr, plan.id, plan.name, now, end]
    );

    // 6) Ticket/recibo en Ocean Pay (historial)
    await client.query(
      `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen)
       VALUES ($1, $2, $3, $4)`,
      [userIdStr, 'Suscripción Plan Pro (EcoConsole)', 0, 'EcoConsole']
    );

    await client.query('COMMIT');
    res.json({ success: true, sub: rows[0] });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error("❌ /subscribe ERROR:", err.message);
    res.status(500).json({ error: "Error interno del servidor" });
  } finally {
    client.release();
  }
});

app.post("/api/subscriptions/cancel", async (req, res) => {
  const { userId } = req.body;

  try {
    const { rows } = await pool.query(
      `UPDATE subs SET active = false, ends_at = NOW() WHERE user_id = $1 AND active = true RETURNING *`,
      [userId]
    );

    if (rows.length === 0) {
      return res.status(400).json({ error: "No tienes una suscripción activa." });
    }

    res.json({ success: true, message: "Suscripción cancelada. Podrás seguir usando los beneficios hasta la fecha de vencimiento." });

  } catch (err) {
    console.error("❌ /cancel ERROR:", err.message);
    res.status(500).json({ error: "Error interno" });
  }
});

// 📅 ESTO SE EJECUTA CADA DÍA A LAS 00:00 UTC
import cron from "node-cron";

cron.schedule("0 0 * * *", async () => {
  console.log("🔄 Ejecutando cobro mensual...");

  try {
    // 1) Suscripciones que vencen HOY con auto_pay
    const { rows: dueSubs } = await pool.query(`
      SELECT s.*
      FROM subs s
      WHERE s.active = true
        AND s.auto_pay = true
        AND DATE(s.ends_at) = CURRENT_DATE
    `);

    for (const sub of dueSubs) {
      const userId = sub.user_id;
      const planId = sub.plan_id;
      const plan = PLANS.find(p => p.id === planId);
      const price = plan?.price || 0;

      // 2) Leer saldo EcoCoreBits
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const { rows: cur } = await client.query(
          `SELECT amount FROM user_currency WHERE user_id = $1 AND currency_type = 'ecocorebits' FOR UPDATE`,
          [userId]
        );
        const balance = cur[0]?.amount || 0;

        if (balance >= price && price > 0) {
          const next = balance - price;
          await client.query(
            `INSERT INTO user_currency (user_id, currency_type, amount)
             VALUES ($1,'ecocorebits',$2)
             ON CONFLICT (user_id, currency_type)
             DO UPDATE SET amount = EXCLUDED.amount`,
            [userId, next]
          );

          await client.query(
            `INSERT INTO ecocore_txs (user_id, concepto, monto, origen)
             VALUES ($1, $2, $3, $4)`,
            [userId, 'Renovación Suscripción Plan Pro (EcoConsole)', -price, 'EcoConsole']
          );

          // Extender 30 días
          await client.query(
            `UPDATE subs SET ends_at = NOW() + INTERVAL '30 days' WHERE id = $1`,
            [sub.id]
          );

          // Ticket en Ocean Pay (monto 0)
          await client.query(
            `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen)
             VALUES ($1, $2, $3, $4)`,
            [userId, 'Renovación Suscripción Plan Pro (EcoConsole)', 0, 'EcoConsole']
          );

          await client.query('COMMIT');
          console.log(`✅ Renovado ${planId} para ${userId}`);
        } else {
          // Sin saldo suficiente → downgrade
          await client.query(`UPDATE subs SET active = false WHERE id = $1`, [sub.id]);
          await client.query(
            `INSERT INTO subs (user_id, plan_id, plan_name, start, ends_at, active, auto_pay)
             VALUES ($1, 'free', 'Plan Free', NOW(), NOW() + INTERVAL '30 days', true, false)`,
            [userId]
          );
          await client.query(
            `INSERT INTO alerts (user_id, type, message) VALUES ($1, 'warning', $2)`,
            [userId, '💰 Saldo insuficiente para renovar tu plan. Se te ha asignado Plan Free temporalmente.']
          );
          await client.query('COMMIT');
          console.log(`❌ Downgrade a Free por falta de fondos: ${userId}`);
        }
      } catch (err) {
        await client.query('ROLLBACK');
        console.error('❌ Error en renovación:', err.message);
      } finally {
        client.release();
      }
    }
  } catch (err) {
    console.error("❌ Error en cobro automático:", err.message);
  }
});

app.patch("/api/subscriptions/auto-pay", async (req, res) => {
  const { userId, enabled } = req.body; // enabled: boolean

  try {
    const { rows } = await pool.query(
      `UPDATE subs SET auto_pay = $1 WHERE user_id = $2 AND active = true RETURNING auto_pay`,
      [enabled, userId]
    );
    if (rows.length === 0) return res.status(400).json({ error: "No tienes suscripción activa." });

    res.json({ success: true, autoPay: rows[0].auto_pay });

  } catch (err) {
    console.error("❌ /auto-pay ERROR:", err.message);
    res.status(500).json({ error: "Error interno" });
  }
});
 

app.get("/api/subscriptions/has-access/:userId/:feature", async (req, res) => {
  const { userId, feature } = req.params;
  try {
    const { rows } = await pool.query(
      `SELECT * FROM subs WHERE user_id = $1 AND active = true AND ends_at > NOW()`,
      [userId]
    );
    if (rows.length === 0) return res.json({ hasAccess: false, message: "Sin suscripción activa" });

    const plan = rows[0];
    const perks = PLANS.find(p => p.id === plan.plan_id)?.perks || [];
    const hasAccess = perks.includes(feature);
    res.json({ hasAccess, plan: plan.plan_name });
  } catch (err) {
    console.error("❌ /has-access:", err);
    res.status(500).json({ error: "Error interno" });
  }
});

app.get('/api/users/me', async (req, res) => {
  const userId = req.headers['x-user-id'] || req.query.userId;
  if (!userId) return res.status(401).json({ error: 'Falta userId' });

  const { rows } = await pool.query(
    'SELECT id, username, balance FROM users WHERE id = $1',
    [userId]
  );

  if (!rows.length) return res.status(404).json({ error: 'Usuario no encontrado' });
  res.json(rows[0]);
});


app.post('/api/users/create', async (req, res) => {
  const { userId, username } = req.body;
  if (!userId || !username) return res.status(400).json({ error: 'Faltan datos' });

  try {
    const { rows } = await pool.query(
      `INSERT INTO users (id, username, password, balance)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (id) DO UPDATE
         SET username = EXCLUDED.username
       RETURNING id, username, balance`,
      [userId, username, 'nopass', 50000]
    );
    res.json({ success: true, user: rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Username ya existe' });
    console.error('❌ /users/create', err);
    res.status(500).json({ error: 'Error interno' });
  }
});


// GET /api/users/:id/balance
app.get('/api/users/:id/balance', async (req, res) => {
  const { id } = req.params;
  try {
    const { rows } = await pool.query(
      'SELECT balance FROM users WHERE id = $1',
      [id]
    );
    res.json({ balance: rows[0]?.balance ?? 0 });
  } catch (err) {
    console.error('❌ /users/:id/balance', err);
    res.status(500).json({ error: 'Error interno' });
  }
});



/* ===== LUGARES RECURRENTES ===== */
app.get('/natmarket/places/:userId', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM user_places WHERE user_id=$1 ORDER BY created_at DESC',
      [req.params.userId]
    );
    res.json(rows);
  } catch (err) { handleNatError(res, err, 'GET /places'); }
});

app.post('/natmarket/places', async (req, res) => {
  try {
    const { user_id, dept, street } = req.body;
    if (!user_id || !dept || !street) return res.status(400).json({ error: 'Faltan datos' });
    const { rows } = await pool.query(
      'INSERT INTO user_places (user_id, dept, street) VALUES ($1,$2,$3) RETURNING *',
      [user_id, dept, street]
    );
    res.json(rows[0]);
  } catch (err) { handleNatError(res, err, 'POST /places'); }
});

/* ===== MÉTODOS DE ENVÍO RECURRENTES ===== */
app.get('/natmarket/shipping-methods/:userId', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM user_shipping_methods WHERE user_id=$1 ORDER BY created_at DESC',
      [req.params.userId]
    );
    res.json(rows);
  } catch (err) { handleNatError(res, err, 'GET /shipping-methods'); }
});

app.post('/natmarket/shipping-methods', async (req, res) => {
  try {
    const { user_id, name } = req.body;
    if (!user_id || !name) return res.status(400).json({ error: 'Faltan datos' });
    const { rows } = await pool.query(
      'INSERT INTO user_shipping_methods (user_id, name) VALUES ($1,$2) RETURNING *',
      [user_id, name]
    );
    res.json(rows[0]);
  } catch (err) { handleNatError(res, err, 'POST /shipping-methods'); }
});

/* ===== LUGARES / MÉTODOS DE UN PRODUCTO ===== */
app.get('/natmarket/products/:id/places', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT pl.id, pl.dept, pl.street
      FROM product_places pp
      JOIN user_places pl ON pl.id = pp.place_id
      WHERE pp.product_id = $1
    `, [req.params.id]);
    res.json(rows);
  } catch (err) { handleNatError(res, err, 'GET /products/:id/places'); }
});

app.get('/natmarket/products/:id/shipping-methods', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT sm.id, sm.name
      FROM product_shipping_methods ps
      JOIN user_shipping_methods sm ON sm.id = ps.shipping_method_id
      WHERE ps.product_id = $1
    `, [req.params.id]);
    res.json(rows);
  } catch (err) { handleNatError(res, err, 'GET /products/:id/shipping-methods'); }
});

/* ===== CREAR PRODUCTO (v2) ===== */
app.post('/natmarket/products/v2', upload.fields([
  { name: 'images', maxCount: 10 },
  { name: 'videos', maxCount: 4 }
]), async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { user_id, name, description, price, contact_number, stock } = req.body;

    // Verificar si el usuario está vinculado con OceanicEthernet (OBLIGATORIO)
    const { rows: linkRows } = await client.query(
      `SELECT oe_user_id FROM oceanic_ethernet_user_links 
       WHERE external_user_id = $1 AND external_system = 'NatMarket'`,
      [user_id]
    );
    
    if (linkRows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(403).json({ 
        error: 'Debes vincular tu cuenta con OceanicEthernet para publicar productos. Ve a tu perfil para vincular.',
        needs_link: true
      });
    }
    
    const oeUserId = linkRows[0].oe_user_id;

    // Verificar si el usuario está baneado
    const banCheck = await isUserBanned(user_id);
    if (banCheck.banned) {
      await client.query('ROLLBACK');
      const banUntil = new Date(banCheck.banUntil);
      return res.status(403).json({ 
        error: `Tu cuenta está baneada hasta el ${banUntil.toLocaleDateString('es-AR')}. Razón: ${banCheck.reason}` 
      });
    }

    // ➜ parsear arrays y definir variables
    const places  = JSON.parse(req.body.places || '[]');
    const methods = JSON.parse(req.body.methods || '[]');
    const stockNum = parseInt(stock) || 1;
    const category = req.body.category || null;
    const productStatus = req.body.status || 'disponible';

    // --- moderación ---
    const bad = containsInappropriate(name + ' ' + description);
    if (bad) {
      // Guardar en pendientes
      const { rows: [pend] } = await client.query(
        `INSERT INTO products_pending (user_id, name, description, price, contact_number, places, methods)
         VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
        [user_id, name, description, price ? parseFloat(price) : null, contact_number || null, JSON.stringify(places), JSON.stringify(methods)]
      );
      // Notificar al moderador
      await notifyModerator('product', pend.id, name, user_id);
      await client.query('COMMIT');
      return res.status(202).json({
        warning: 'Tu producto está en revisión por contenido potencialmente inapropiado.'
      });
    }
    // si está limpio, continúa con el flujo normal (tu INSERT original)

    if (!user_id || !name) return res.status(400).json({ error: 'Faltan datos' });

    const { rows: [product] } = await client.query(
      `INSERT INTO products_nat (user_id, name, description, price, contact_number, stock, category, status, published_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW()) RETURNING *`,
      [user_id, name, description, price ? parseFloat(price) : null, contact_number || null, stockNum, category || null, productStatus]
    );

    // Consumir internet al crear producto (0.1 GB por producto)
    try {
      const { rows: metaRows } = await client.query(`
        SELECT value FROM ocean_pay_metadata
        WHERE user_id = $1 AND key = 'internet_gb'
        FOR UPDATE
      `, [oeUserId]);
      
      if (metaRows.length > 0) {
        const currentBalance = parseFloat(metaRows[0].value || '0');
        const internetCost = 0.1; // 0.1 GB por producto
        
        // Verificar saldo suficiente
        if (currentBalance < internetCost) {
          await client.query('ROLLBACK');
          return res.status(400).json({ 
            error: `Saldo insuficiente. Necesitas ${internetCost} GB de internet para publicar un producto. Tu saldo actual: ${currentBalance.toFixed(1)} GB`,
            insufficient_balance: true
          });
        }
        
        const newBalance = currentBalance - internetCost;
        
        await client.query(`
          UPDATE ocean_pay_metadata
          SET value = $1
          WHERE user_id = $2 AND key = 'internet_gb'
        `, [newBalance.toString(), oeUserId]);
        
        // Registrar transacción de consumo en tabla de OceanicEthernet
        await client.query(
          `INSERT INTO oceanic_ethernet_txs (user_id, concepto, monto, origen)
           VALUES ($1, $2, $3, $4)`,
          [oeUserId, `Crear producto en NatMarket: ${name}`, -internetCost, 'NatMarket']
        );
      } else {
        // No tiene saldo inicializado, requerir recarga
        await client.query('ROLLBACK');
        return res.status(400).json({ 
          error: 'No tienes saldo de internet. Recarga tu cuenta en OceanicEthernet para publicar productos.',
          insufficient_balance: true
        });
      }
    } catch (e) {
      await client.query('ROLLBACK');
      console.error('Error consumiendo internet en NatMarket:', e);
      return res.status(500).json({ error: 'Error al procesar el consumo de internet' });
    }

    // archivos subidos (imágenes y videos)
    const host = process.env.BACKEND_URL || `https://${req.get('host')}`;
    const imageFiles = (req.files && req.files.images) ? req.files.images : [];
    const videoFiles = (req.files && req.files.videos) ? req.files.videos : [];

    // imágenes
    const imageUrls = imageFiles.map(f => `${host}/uploads/nat/${f.filename}`);
    for (const url of imageUrls) {
      await client.query('INSERT INTO product_images_nat (product_id, url) VALUES ($1,$2)', [product.id, url]);
    }

    // videos
    if (videoFiles.length) {
      await client.query(`
        CREATE TABLE IF NOT EXISTS product_videos_nat (
          id SERIAL PRIMARY KEY,
          product_id INTEGER NOT NULL REFERENCES products_nat(id) ON DELETE CASCADE,
          url TEXT NOT NULL,
          created_at TIMESTAMP DEFAULT NOW()
        )
      `);
      const videoUrls = videoFiles.map(f => `${host}/uploads/nat/${f.filename}`);
      for (const url of videoUrls) {
        await client.query('INSERT INTO product_videos_nat (product_id, url) VALUES ($1,$2)', [product.id, url]);
      }
    }

    // lugares
    for (const pId of places) {
      await client.query(
        'INSERT INTO product_places (product_id, place_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
        [product.id, pId]
      );
    }
    // métodos
    for (const mId of methods) {
      await client.query(
        'INSERT INTO product_shipping_methods (product_id, shipping_method_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
        [product.id, mId]
      );
    }

    // Notificar a los seguidores del usuario
    try {
      const { rows: followers } = await client.query(
        'SELECT follower_id FROM user_follows WHERE following_id = $1',
        [user_id]
      );
      
      if (followers.length > 0) {
        // Obtener el username del vendedor
        const { rows: [seller] } = await client.query(
          'SELECT username FROM users_nat WHERE id = $1',
          [user_id]
        );
        const sellerName = seller?.username || 'Un usuario';
        
        // Crear notificaciones para cada seguidor
        for (const follower of followers) {
          await client.query(
            `INSERT INTO notifications_nat (user_id, type, message, product_id, sender_id, created_at)
             VALUES ($1, 'new_product', $2, $3, $4, NOW())`,
            [
              follower.follower_id,
              `${sellerName} publicó un nuevo producto: "${name}"`,
              product.id,
              user_id
            ]
          );
        }
        console.log(`[NOTIFICATIONS] ${followers.length} notificaciones de nuevo producto creadas`);
      }
    } catch (notifErr) {
      console.error('[NOTIFICATIONS] Error notificando a seguidores:', notifErr);
      // No fallar la creación del producto si falla la notificación
    }

    await client.query('COMMIT');
    res.json({ success: true, product });
  } catch (err) {
    await client.query('ROLLBACK');
    handleNatError(res, err, 'POST /products/v2');
  } finally {
    client.release();
  }
});

/* ===== PRODUCT VIDEOS ===== */
app.post('/natmarket/products/:id/videos', upload.array('videos', 4), async (req, res) => {
  try {
    const productId = req.params.id;
    const { rows: exists } = await pool.query('SELECT id FROM products_nat WHERE id=$1', [productId]);
    if (!exists.length) return res.status(404).json({ error: 'Producto no encontrado' });
    if (!req.files || req.files.length === 0) return res.status(400).json({ error: 'No se subieron videos' });

    await pool.query(`
      CREATE TABLE IF NOT EXISTS product_videos_nat (
        id SERIAL PRIMARY KEY,
        product_id INTEGER NOT NULL REFERENCES products_nat(id) ON DELETE CASCADE,
        url TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    const host = process.env.BACKEND_URL || `https://${req.get('host')}`;
    const urls = req.files.map(f => `${host}/uploads/nat/${f.filename}`);
    for (const url of urls) {
      await pool.query('INSERT INTO product_videos_nat (product_id, url) VALUES ($1,$2)', [productId, url]);
    }
    const { rows: vids } = await pool.query('SELECT url FROM product_videos_nat WHERE product_id=$1 ORDER BY created_at ASC', [productId]);
    res.json({ success: true, video_urls: vids.map(v => v.url) });
  } catch (err) {
    handleNatError(res, err, 'POST /natmarket/products/:id/videos');
  }
});

/* ===== PRODUCT DISCOUNTS ===== */
app.post('/natmarket/products/:id/discount', async (req, res) => {
  const { id } = req.params;
  const { user_id, percent = null, amount = null, starts_at = null, ends_at = null } = req.body;
  if (!user_id) return res.status(400).json({ error: 'user_id requerido' });
  try {
    // verificar dueño
    const { rows: prod } = await pool.query('SELECT user_id, price FROM products_nat WHERE id=$1', [id]);
    if (!prod.length) return res.status(404).json({ error: 'Producto no encontrado' });
    if (Number(prod[0].user_id) !== Number(user_id)) return res.status(403).json({ error: 'No autorizado' });

    await pool.query(`
      CREATE TABLE IF NOT EXISTS product_discounts (
        id SERIAL PRIMARY KEY,
        product_id INTEGER NOT NULL REFERENCES products_nat(id) ON DELETE CASCADE,
        percent NUMERIC,
        amount NUMERIC,
        starts_at TIMESTAMP NULL,
        ends_at TIMESTAMP NULL,
        active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // desactivar descuentos activos previos
    await pool.query('UPDATE product_discounts SET active=false WHERE product_id=$1 AND active=true', [id]);

    const { rows } = await pool.query(
      `INSERT INTO product_discounts (product_id, percent, amount, starts_at, ends_at, active)
       VALUES ($1,$2,$3,$4,$5,true)
       RETURNING *`,
      [id, percent, amount, starts_at, ends_at]
    );

    res.json({ success: true, discount: rows[0] });
  } catch (err) {
    handleNatError(res, err, 'POST /natmarket/products/:id/discount');
  }
});

app.delete('/natmarket/products/:id/discount', async (req, res) => {
  const { id } = req.params;
  const { user_id } = req.body;
  if (!user_id) return res.status(400).json({ error: 'user_id requerido' });
  try {
    const { rows: prod } = await pool.query('SELECT user_id FROM products_nat WHERE id=$1', [id]);
    if (!prod.length) return res.status(404).json({ error: 'Producto no encontrado' });
    if (Number(prod[0].user_id) !== Number(user_id)) return res.status(403).json({ error: 'No autorizado' });
    await pool.query('UPDATE product_discounts SET active=false WHERE product_id=$1 AND active=true', [id]);
    res.json({ success: true });
  } catch (err) {
    handleNatError(res, err, 'DELETE /natmarket/products/:id/discount');
  }
});

app.get('/natmarket/products/:id/discount', async (req, res) => {
  const { id } = req.params;
  try {
    const { rows } = await pool.query(`
      SELECT percent, amount, starts_at, ends_at
      FROM product_discounts
      WHERE product_id=$1 AND active=true
        AND (starts_at IS NULL OR starts_at <= NOW())
        AND (ends_at IS NULL OR ends_at >= NOW())
      ORDER BY created_at DESC
      LIMIT 1
    `, [id]);
    res.json(rows[0] || null);
  } catch (err) {
    if (err.code === '42P01') return res.json(null); // tabla no existe aún
    handleNatError(res, err, 'GET /natmarket/products/:id/discount');
  }
});

/* ===== FAVORITES & WISHLIST ===== */
app.post('/natmarket/products/:id/favorite', async (req, res) => {
  const { id } = req.params;
  const { user_id } = req.body;
  if (!user_id) return res.status(400).json({ error: 'user_id requerido' });
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_favorites_nat (
        user_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL REFERENCES products_nat(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT NOW(),
        PRIMARY KEY (user_id, product_id)
      )
    `);
    await pool.query('INSERT INTO user_favorites_nat (user_id, product_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [user_id, id]);
    res.json({ success: true });
  } catch (err) { handleNatError(res, err, 'POST /natmarket/products/:id/favorite'); }
});

app.delete('/natmarket/products/:id/favorite', async (req, res) => {
  const { id } = req.params;
  const { user_id } = req.body;
  if (!user_id) return res.status(400).json({ error: 'user_id requerido' });
  try {
    await pool.query('DELETE FROM user_favorites_nat WHERE user_id=$1 AND product_id=$2', [user_id, id]);
    res.json({ success: true });
  } catch (err) { handleNatError(res, err, 'DELETE /natmarket/products/:id/favorite'); }
});

app.get('/natmarket/users/:userId/favorites', async (req, res) => {
  const { userId } = req.params;
  try {
    const { rows } = await pool.query(`
      SELECT p.*, u.username
      FROM user_favorites_nat f
      JOIN products_nat p ON p.id = f.product_id
      JOIN users_nat u ON u.id = p.user_id
      WHERE f.user_id = $1
      ORDER BY COALESCE(p.published_at, p.created_at) DESC
    `, [userId]);

    const products = await Promise.all(rows.map(async p => {
      const { rows: imgs } = await pool.query('SELECT url FROM product_images_nat WHERE product_id=$1 ORDER BY created_at ASC', [p.id]);
      let vids = [];
      try {
        const { rows: v } = await pool.query('SELECT url FROM product_videos_nat WHERE product_id=$1 ORDER BY created_at ASC', [p.id]);
        vids = v;
      } catch (_) {}
      return { ...p, image_urls: imgs.map(i => i.url), video_urls: vids.map(v => v.url) };
    }));

    res.json(products);
  } catch (err) { handleNatError(res, err, 'GET /natmarket/users/:userId/favorites'); }
});

app.get('/natmarket/users/:userId/favorites/count', async (req, res) => {
  const { userId } = req.params;
  try {
    const { rows } = await pool.query('SELECT COUNT(*)::int AS count FROM user_favorites_nat WHERE user_id=$1', [userId]);
    res.json({ count: rows[0]?.count || 0 });
  } catch (err) { handleNatError(res, err, 'GET /natmarket/users/:userId/favorites/count'); }
});

app.post('/natmarket/products/:id/wish', async (req, res) => {
  const { id } = req.params;
  const { user_id } = req.body;
  if (!user_id) return res.status(400).json({ error: 'user_id requerido' });
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_wishlist_nat (
        user_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL REFERENCES products_nat(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT NOW(),
        PRIMARY KEY (user_id, product_id)
      )
    `);
    await pool.query('INSERT INTO user_wishlist_nat (user_id, product_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [user_id, id]);
    res.json({ success: true });
  } catch (err) { handleNatError(res, err, 'POST /natmarket/products/:id/wish'); }
});

app.delete('/natmarket/products/:id/wish', async (req, res) => {
  const { id } = req.params;
  const { user_id } = req.body;
  if (!user_id) return res.status(400).json({ error: 'user_id requerido' });
  try {
    await pool.query('DELETE FROM user_wishlist_nat WHERE user_id=$1 AND product_id=$2', [user_id, id]);
    res.json({ success: true });
  } catch (err) { handleNatError(res, err, 'DELETE /natmarket/products/:id/wish'); }
});

app.get('/natmarket/users/:userId/wishlist', async (req, res) => {
  const { userId } = req.params;
  try {
    const { rows } = await pool.query(`
      SELECT p.*, u.username
      FROM user_wishlist_nat w
      JOIN products_nat p ON p.id = w.product_id
      JOIN users_nat u ON u.id = p.user_id
      WHERE w.user_id = $1
      ORDER BY COALESCE(p.published_at, p.created_at) DESC
    `, [userId]);

    const products = await Promise.all(rows.map(async p => {
      const { rows: imgs } = await pool.query('SELECT url FROM product_images_nat WHERE product_id=$1 ORDER BY created_at ASC', [p.id]);
      let vids = [];
      try {
        const { rows: v } = await pool.query('SELECT url FROM product_videos_nat WHERE product_id=$1 ORDER BY created_at ASC', [p.id]);
        vids = v;
      } catch (_) {}
      return { ...p, image_urls: imgs.map(i => i.url), video_urls: vids.map(v => v.url) };
    }));

    res.json(products);
  } catch (err) { handleNatError(res, err, 'GET /natmarket/users/:userId/wishlist'); }
});

app.get('/natmarket/users/:userId/wishlist/count', async (req, res) => {
  const { userId } = req.params;
  try {
    const { rows } = await pool.query('SELECT COUNT(*)::int AS count FROM user_wishlist_nat WHERE user_id=$1', [userId]);
    res.json({ count: rows[0]?.count || 0 });
  } catch (err) { handleNatError(res, err, 'GET /natmarket/users/:userId/wishlist/count'); }
});

/* ---------- RESTAURAR CONTRASEÑA ---------- */
app.post('/natmarket/reset-password', async (req, res) => {
  const { user_unique_id } = req.body;
  if (!user_unique_id) return res.status(400).json({ error: 'Se requiere el ID de Usuario Único para recuperar la contraseña' });

  try {
    // Buscar usuario por user_unique_id
    const { rows } = await pool.query(
      'SELECT id, password FROM users_nat WHERE user_unique_id = $1',
      [user_unique_id]
    );

    if (rows.length === 0) {
      // No revelamos si existe o no por seguridad
      return res.status(404).json({ 
        error: 'ID de Usuario Único no encontrado. Verifica que lo hayas escrito correctamente.' 
      });
    }

    const userId = rows[0].id;
    
    // Generar nueva contraseña aleatoria
    const newPass = Math.random().toString(36).slice(-10) + Math.random().toString(36).slice(-6); // 16 caracteres
    const hashed = await bcrypt.hash(newPass, 10);
    
    // Actualizar contraseña
    await pool.query('UPDATE users_nat SET password = $1 WHERE id = $2', [hashed, userId]);
    
    res.json({
      success: true,
      message: 'Contraseña restablecida exitosamente. Guarda esta nueva contraseña.',
      newPassword: newPass, // Se muestra solo una vez
      userId: userId
    });
  } catch (err) {
    handleNatError(res, err, 'POST /reset-password');
  }
});

/* ---------- OBTENER ID ÚNICO DE USUARIO (solo una vez con confirmación de contraseña) ---------- */
app.post('/natmarket/users/:id/get-unique-id', async (req, res) => {
  try {
    const { id } = req.params;
    const { password } = req.body;
    
    if (!password) return res.status(400).json({ error: 'Se requiere confirmar la contraseña' });
    
    const { rows } = await pool.query('SELECT password, user_unique_id, unique_id_shown FROM users_nat WHERE id=$1', [id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
    
    // Verificar contraseña
    const ok = await bcrypt.compare(password, rows[0].password);
    if (!ok) return res.status(401).json({ error: 'Contraseña incorrecta' });
    
    // Si ya se mostró el ID, no permitir verlo de nuevo por seguridad
    if (rows[0].unique_id_shown) {
      return res.status(403).json({ 
        error: 'El ID de Usuario Único ya fue mostrado anteriormente. Si lo perdiste, no podrás recuperarlo.',
        already_shown: true
      });
    }
    
    // Marcar como mostrado y devolver el ID
    await pool.query('UPDATE users_nat SET unique_id_shown = true WHERE id = $1', [id]);
    
    res.json({
      success: true,
      user_unique_id: rows[0].user_unique_id,
      message: '⚠️ IMPORTANTE: Guarda este ID de Usuario Único en un lugar seguro. Solo se mostrará esta vez. Será necesario para recuperar tu contraseña.'
    });
  } catch (err) {
    handleNatError(res, err, 'POST /natmarket/users/:id/get-unique-id');
  }
});


/* ---------- NOVEDAD DESTACADA ---------- */
app.get('/api/featured-update', async (_req, res) => {
  try {
    // Primero intentar obtener de la base de datos
    const { rows } = await pool.query(
      `SELECT version, news, date, sections
       FROM updates_natmarket
       ORDER BY date DESC
       LIMIT 1`
    );
    
    if (rows.length && rows[0]) {
      // Si hay actualización en BD, devolverla
      const dbUpdate = rows[0];
      // Si tiene sections como JSON, parsearlo
      if (dbUpdate.sections && typeof dbUpdate.sections === 'string') {
        try {
          dbUpdate.sections = JSON.parse(dbUpdate.sections);
        } catch (e) {
          // Si falla, dejarlo como está
        }
      }
      return res.json(dbUpdate);
    }
  } catch (err) {
    console.error('Error obteniendo update de BD:', err);
  }
  
  // Si no hay en BD, enviar actualización actual con todas las mejoras
  const update = {
    version: 'v2.0.0 - Gran Actualización',
    date: new Date().toISOString().split('T')[0],
    sections: [
      {
        title: '🔍 Búsqueda Inteligente',
        icon: '🔍',
        items: [
          'Nueva búsqueda en tiempo real con sugerencias automáticas',
          'Filtros avanzados: Precio, Rating, Vistos, Nuevos',
          'Búsqueda por nombre, descripción, vendedor y precio',
          'Contador de resultados con animaciones'
        ]
      },
      {
        title: '🎨 Header Rediseñado',
        icon: '✨',
        items: [
          'Nuevo diseño premium con mejor organización',
          'Botones de usuario mejorados con layout vertical',
          'Separación clara entre acciones y búsqueda',
          'Diseño completamente responsive para móvil y PC'
        ]
      },
      {
        title: '📱 Layout Mejorado',
        icon: '🎨',
        items: [
          'Sistema de diseño responsive mejorado en todo NatMarket',
          'Nuevas animaciones y transiciones fluidas',
          'Mejor jerarquía visual y espaciado',
          'Colores y sombras premium actualizados',
          'Optimización para todos los dispositivos'
        ]
      },
      {
        title: '👥 Sistema de Seguidores',
        icon: '❤️',
        items: [
          'Seguir y dejar de seguir usuarios',
          'Ver seguidores y usuarios que sigues',
          'Notificaciones de nuevos seguidores',
          'Perfil público mejorado'
        ]
      },
      {
        title: '🔄 Funciones de Republicar',
        icon: '🔄',
        items: [
          'Republicar productos manteniendo el original',
          'Borrar y republicar con opción de editar',
          'Badge "NUEVO" basado en fecha de publicación',
          'Modales mejorados con mejor organización'
        ]
      }
    ]
  };
  res.json(update);
});

/* ---------- TOP LECTORES ---------- */


/* ----------  SUBIR TIEMPO + LIBRO  ---------- */
app.post("/api/leaderboard/incr", async (req, res) => {
  const { userId, username, seconds = 0 } = req.body;
  if (!userId || !username) return res.status(400).json({ error: "Faltan datos" });

  await pool.query(
    `INSERT INTO reader_leaderboard (user_id, username, books_read, total_time, updated_at)
     VALUES ($1, $2, 1, $3, NOW())
     ON CONFLICT (user_id)
     DO UPDATE SET
       books_read = reader_leaderboard.books_read + 1,
       total_time = reader_leaderboard.total_time + EXCLUDED.total_time,
       updated_at = NOW()`,
    [userId, username, seconds]
  );
  res.json({ success: true });
});

/* ----------  TOP LECTORES (por tiempo + libros)  ---------- */
app.get("/api/leaderboard", async (_req, res) => {
  const { rows } = await pool.query(`
    SELECT username,
           books_read,
           total_time,
           TO_CHAR(updated_at, 'DD/MM/YY') AS last_read
    FROM reader_leaderboard
    ORDER BY total_time DESC, books_read DESC, updated_at ASC
    LIMIT 20
  `);
  res.json(rows);
});

/* ----------  REGISTER  ---------- */
app.post('/np/auth/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Faltan datos' });
  const hash = await bcrypt.hash(password, 10);
  try {
    const { rows } = await pool.query(
      `INSERT INTO np_users (username, pwd_hash)
       VALUES ($1, $2) RETURNING id, username`,
      [username, hash]
    );
    res.status(201).json({ id: rows[0].id, username: rows[0].username });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Usuario ya existe' });
    return res.status(500).json({ error: 'Error interno' });
  }
});

/* ----------  LOGIN  ---------- */
app.post('/np/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Faltan datos' });
  const { rows } = await pool.query('SELECT id, pwd_hash FROM np_users WHERE username=$1', [username]);
  if (!rows.length) return res.status(401).json({ error: 'Credenciales incorrectas' });
  const ok = await bcrypt.compare(password, rows[0].pwd_hash);
  if (!ok) return res.status(401).json({ error: 'Credenciales incorrectas' });

  /* JWT simple (sin refresh) */
  const token = jwt.sign({ uid: rows[0].id, un: username }, process.env.STUDIO_SECRET, { expiresIn: '7d' });
  res.json({ token, id: rows[0].id, username });
});

/* ----------  DATOS DEL TOKEN  ---------- */
app.get('/np/auth/me', async (req, res) => {
  const hdr = req.headers.authorization;
  if (!hdr) return res.status(401).json({ error: 'Sin token' });
  try {
    const payload = jwt.verify(hdr.split(' ')[1], process.env.STUDIO_SECRET);
    const { rows } = await pool.query('SELECT id, username FROM np_users WHERE id=$1', [payload.uid]);
    if (!rows.length) return res.status(404).json({ error: 'Usuario no existe' });
    res.json(rows[0]);
  } catch {
    return res.status(401).json({ error: 'Token inválido' });
  }
});

/* ----------  CONTAR VISTA (1 por usuario)  ---------- */
app.patch('/natmarket/products/:id/view', async (req, res) => {
  const { id } = req.params;               // productId
  let userId = req.headers['x-user-id'];   // puede venir del header (para usuarios no autenticados)
  
  // Si hay un usuario autenticado, usar su ID en lugar del header
  // Esto asegura que las vistas se cuenten correctamente por usuario
  const authUserId = req.headers['x-auth-user-id'];
  if (authUserId && authUserId !== 'undefined' && authUserId !== 'null') {
    userId = authUserId;
  }
  
  // Si no hay userId, usar 'anon-' + IP o un identificador único
  if (!userId || userId === 'anon' || userId === 'undefined' || userId === 'null') {
    // Para usuarios no autenticados, usar una combinación de IP y user-agent
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    const userAgent = req.headers['user-agent'] || 'unknown';
    userId = `anon-${Buffer.from(ip + userAgent).toString('base64').substring(0, 20)}`;
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1. Verificar si el producto existe
    const { rows: productCheck } = await client.query(
      'SELECT id FROM products_nat WHERE id = $1',
      [id]
    );
    if (productCheck.length === 0) {
      await client.query('COMMIT');
      return res.status(404).json({ error: 'Producto no encontrado' });
    }

    // 2. ¿ya vio este usuario este producto?
    const { rows: existingView } = await client.query(
      `SELECT 1 FROM product_views_unique
       WHERE user_id = $1 AND product_id = $2`,
      [userId, id]
    );
    
    if (existingView.length > 0) {
      // Ya contó -> solo devolver total actual
      const { rows: total } = await client.query(
        'SELECT views FROM products_nat WHERE id = $1', [id]
      );
      await client.query('COMMIT');
      return res.json({ views: total[0].views || 0, firstTime: false });
    }

    // 3. Es la primera vez - insertar registro usando INSERT ... ON CONFLICT
    // Usamos RETURNING para saber si realmente se insertó
    const { rows: insertedRow } = await client.query(
      `INSERT INTO product_views_unique(user_id, product_id) 
       VALUES ($1,$2)
       ON CONFLICT (user_id, product_id) DO NOTHING
       RETURNING id`,
      [String(userId), parseInt(id)]
    );
    
    // Si no se insertó nada (ya existía), no incrementar contador
    if (!insertedRow || insertedRow.length === 0) {
      await client.query('COMMIT');
      const { rows: total } = await client.query(
        'SELECT views FROM products_nat WHERE id = $1', [id]
      );
      return res.json({ views: total[0].views || 0, firstTime: false });
    }

    // 4. Incrementar contador de vistas del producto
    const { rows: total } = await client.query(
      `UPDATE products_nat
         SET views = COALESCE(views, 0) + 1
       WHERE id = $1
       RETURNING views`,
      [id]
    );
    
    await client.query('COMMIT');
    res.json({ views: total[0].views || 1, firstTime: true });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[VIEW-UNIQUE] Error:', err);
    res.status(500).json({ error: 'Error interno', details: err.message });
  } finally {
    client.release();
  }
});


/* ---------- ENDPOINTS de demo: Registrar Empresa ---------- */
app.get('/enterprise', (_req, res) => {
  // sirve el index.html de la carpeta "Enterprise Registration"
  res.sendFile(path.join(process.cwd(), 'Enterprise Registration', 'index.html'));
});

app.post('/api/companies/register', upload.single('logo'), async (req, res) => {
  try {
    const {
      name, industry = null, type = null, email = null,
      phone = null, address = null, description = null, source = null
    } = req.body;

    if (!name || !email) return res.status(400).json({ error: 'Faltan name o email' });

    // Moderación ligera (usa containsInappropriate del archivo)
    if (containsInappropriate(name + ' ' + description)) {
      // guardamos pero sin publicar (para demo solo devolvemos 202)
      await pool.query(
        `INSERT INTO companies_nat (name, industry, type, email, phone, address, description, source)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [name, industry, type, email, phone, address, description, source]
      );
      // notificar moderador (función existente)
      await notifyModerator('product', null, name, null);
      return res.status(202).json({ warning: 'Nombre o descripción pendiente de revisión' });
    }

    // url del logo si hubo archivo
    const host = process.env.BACKEND_URL || `http://${process.env.HOST || 'localhost'}:${process.env.PORT || 3000}`;
    const logo_url = req.file ? `${host}/uploads/nat/${req.file.filename}` : null;

    const { rows } = await pool.query(
      `INSERT INTO companies_nat (name, industry, type, email, phone, address, description, logo_url, source)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id, name, logo_url, created_at`,
      [name, industry, type, email, phone, address, description, logo_url, source]
    );

    res.json(rows[0]);
  } catch (err) {
    console.error('Error /api/companies/register', err.message);
    res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/ocean-pay/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Faltan datos' });

  const hash = await bcrypt.hash(password, 10);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

const { rows: [u] } = await client.query(
    `INSERT INTO ocean_pay_users (username, pwd_hash, aquabux, ecoxionums, appbux)
   VALUES ($1, $2, 10000, 50000, 0)
   RETURNING id, username, aquabux, ecoxionums, appbux`,
  [username, hash]
);

    // 2. Crear en users (para EcoCoreBits)
    await client.query(
      `INSERT INTO users (id, username, password, balance)
       VALUES ($1, $2, $3, 0)
       ON CONFLICT (id) DO NOTHING`,
      [u.id, username, 'nopass']
    );

    await client.query('COMMIT');
    res.json({ success: true, user: { id: u.id, username: u.username, aquabux: u.aquabux } });

  } catch (e) {
    await client.query('ROLLBACK');
    if (e.code === '23505') return res.status(409).json({ error: 'Usuario ya existe' });
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

/* ----------  LOGIN  ---------- */
app.post('/ocean-pay/login', async (req,res)=>{
  const {username,password}=req.body;
  if(!username||!password) return res.status(400).json({error:'Faltan datos'});
  
  // Unimos ocean_pay_users con user_currency para obtener todo en una sola consulta
  const {rows}=await pool.query(`
    SELECT opu.id, opu.pwd_hash, opu.aquabux, opu.ecoxionums, opu.appbux, COALESCE(uc.amount, 0) as ecorebits
    FROM ocean_pay_users opu
    LEFT JOIN user_currency uc ON opu.id::text = uc.user_id AND uc.currency_type = 'ecocorebits'
    WHERE opu.username = $1
  `,[username]);

  if(rows.length===0) return res.status(401).json({error:'Credenciales incorrectas'});
  
  const ok=await bcrypt.compare(password,rows[0].pwd_hash);
  if(!ok) return res.status(401).json({error:'Credenciales incorrectas'});
  
  const token=jwt.sign({uid:rows[0].id,un:username},process.env.STUDIO_SECRET,{expiresIn:'7d'});
  
  // Intentar obtener wildCredits desde la tabla de metadatos
  let wildCredits = 0;
  try {
    const { rows: metaRows } = await pool.query(`
      SELECT value FROM ocean_pay_metadata
      WHERE user_id = $1 AND key = 'wildcredits'
    `, [rows[0].id]);
    
    if (metaRows.length > 0) {
      wildCredits = parseInt(metaRows[0].value || '0');
    }
  } catch (e) {
    // Si la tabla no existe, wildCredits queda en 0
  }
  
  // Obtener AppBux de la columna appbux
  const appbux = rows[0].appbux || 0;
  
  res.json({
  token,
  user: {
    id: rows[0].id,
    username,
    aquabux: rows[0].aquabux,
    ecoxionums: rows[0].ecoxionums,
    ecorebits: Number(rows[0].ecorebits), // ✨ Devolvemos el saldo de EcoCoreBits directamente
    wildcredits: wildCredits,
    appbux: appbux
  }
});
});

/* ----------  CURRENT BALANCE  ---------- */
app.get('/ocean-pay/balance/:userId', async (req,res)=>{
  const {userId}=req.params;
  const {rows}=await pool.query('SELECT aquabux FROM ocean_pay_users WHERE id=$1',[userId]);
  if(rows.length===0) return res.status(404).json({error:'Usuario no encontrado'});
  res.json({balance:rows[0].aquabux});
});

app.post('/ocean-pay/change', async (req, res) => {
  const { userId, amount, concepto = 'Operación', origen = 'Ocean Pay' } = req.body;
  console.log('📥 origen recibido:', origen); // ← depuración

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1. lock & read
    const { rows } = await client.query(
      'SELECT aquabux FROM ocean_pay_users WHERE id = $1 FOR UPDATE',
      [userId]
    );
    if (rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    const newBux = rows[0].aquabux + amount;
    if (newBux < 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Saldo insuficiente' });
    }

    // 2. update balance
    await client.query(
      'UPDATE ocean_pay_users SET aquabux = $1 WHERE id = $2',
      [newBux, userId]
    );

    // 3. save transaction
    await client.query(
      'INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen) VALUES ($1,$2,$3,$4)',
      [userId, concepto, amount, origen]
    );

    await client.query('COMMIT');
    res.json({ success: true, newBalance: newBux });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error(e); res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});


/* ----------  WHO AM I ?  (validates JWT)  ---------- */
app.get('/ocean-pay/me', async (req,res)=>{
  const auth=req.headers.authorization;            // Bearer <token>
  if(!auth) return res.status(401).json({error:'Sin token'});
  try{
    const payload=jwt.verify(auth.split(' ')[1], process.env.STUDIO_SECRET);
    const {rows}=await pool.query(
      'SELECT id,username,aquabux FROM ocean_pay_users WHERE id=$1',
      [payload.uid]
    );
    if(rows.length===0) return res.status(404).json({error:'Usuario no encontrado'});
    res.json(rows[0]);
  }catch(e){res.status(401).json({error:'Token inválido'});}
});

app.get('/ocean-pay/txs/:userId', async (req, res) => {
  const { userId } = req.params;

  // 1. Transacciones de Ocean Pay (AquaBux, Ecoxionums, WildCredits, WildGems, etc.)
  let oceanRows;
  try {
    // Verificar si la columna moneda existe
    const { rows: columnCheck } = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'ocean_pay_txs' AND column_name = 'moneda'
    `);
    const hasMonedaColumn = columnCheck.length > 0;
    
    // Obtener transacciones con o sin columna moneda
    let result;
    if (hasMonedaColumn) {
      result = await pool.query(
        `SELECT concepto, monto, origen, created_at, moneda
         FROM ocean_pay_txs
         WHERE user_id = $1
         ORDER BY created_at DESC
         LIMIT 50`,
        [userId]
      );
      // No asignar 'AB' por defecto si es NULL, dejar que el frontend lo infiera del origen
      oceanRows = result.rows;
    } else {
      result = await pool.query(
        `SELECT concepto, monto, origen, created_at
         FROM ocean_pay_txs
         WHERE user_id = $1
         ORDER BY created_at DESC
         LIMIT 50`,
        [userId]
      );
      // No asignar moneda por defecto, dejar que el frontend lo infiera del origen
      oceanRows = result.rows;
    }
  } catch (e) {
    // Si falla, intentar obtener sin la columna moneda
    try {
      const result = await pool.query(
        `SELECT concepto, monto, origen, created_at
         FROM ocean_pay_txs
         WHERE user_id = $1
         ORDER BY created_at DESC
         LIMIT 50`,
        [userId]
      );
      // No asignar moneda por defecto, dejar que el frontend lo infiera del origen
      oceanRows = result.rows;
    } catch (innerError) {
      console.error('Error obteniendo transacciones:', innerError);
      oceanRows = [];
    }
  }

  // 2. EcoCoreBits
  const { rows: ecbRows } = await pool.query(
    `SELECT concepto, monto, origen, created_at
     FROM ecocore_txs
     WHERE user_id = $1
     ORDER BY created_at DESC
     LIMIT 50`,
    [userId]
  );

  // 3. Unificar y etiquetar
  const all = [
    ...oceanRows.map(r => ({ ...r, moneda: r.moneda || 'AB' })),
    ...ecbRows.map(r => ({ ...r, moneda: 'ECB' }))
  ]
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
    .slice(0, 50);

  res.json(all);
});

// ----------  ECOCOREBITS  ----------

// 🔍 Obtener bits del usuario (protegido)
app.get('/ecocore/bits/:userId', async (req, res) => {
  const { userId } = req.params;
  const { rows } = await pool.query(
    `SELECT amount FROM user_currency WHERE user_id = $1 AND currency_type = 'ecocorebits'`,
    [userId]
  );
  console.log('[DEBUG] Saldo de EcoCoreBits encontrado para userId', userId, ':', rows);
  res.json({ bits: rows[0]?.amount ?? 0 });
});

// 💰 Modificar bits (protegido)
app.post('/ecocore/change', async (req, res) => {
  const { userId, amount, concepto = 'Operación', origen = 'Ocean Pay' } = req.body;
  if (!userId || amount === undefined) return res.status(400).json({ error: 'Faltan datos' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Leer saldo de user_currency (ecocorebits)
    const { rows } = await client.query(
      `SELECT amount FROM user_currency WHERE user_id = $1 AND currency_type = 'ecocorebits' FOR UPDATE`,
      [userId]
    );
    // CORRECCIÓN: Asegurar que ambos valores sean números antes de sumar
    const current = parseFloat(rows[0]?.amount || 0);
    const next = Math.round(current + parseFloat(amount));

    if (next < 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Saldo insuficiente' });
    }

    // Upsert nuevo saldo
    await client.query(
      `INSERT INTO user_currency (user_id, currency_type, amount)
       VALUES ($1,'ecocorebits',$2)
       ON CONFLICT (user_id, currency_type)
       DO UPDATE SET amount = EXCLUDED.amount`,
      [userId, next]
    );

    // Log en EcoCore
    await client.query(
      'INSERT INTO ecocore_txs (user_id, concepto, monto, origen) VALUES ($1,$2,$3,$4)',
      [userId, concepto, amount, origen]
    );

    await client.query('COMMIT');
    res.json({ success: true, newBalance: next });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error(e);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

/* -------  Ecoxionums ⇄ Ocean Pay  ------- */

app.get('/ocean-pay/ecoxionums/:userId', async (req, res) => {
  const { userId } = req.params;

  try {
    const { rows } = await pool.query(
      'SELECT ecoxionums FROM ocean_pay_users WHERE id::text = $1', // <-- cast a texto
      [userId]
    );
    res.json({ ecoxionums: rows[0]?.ecoxionums ?? 0 });
  } catch (err) {
    console.error('❌ Error en /ocean-pay/ecoxionums/:userId', err);
    res.status(500).json({ error: 'Error interno' });
  }
});


// 1.b  Movimiento Ecoxionums (origen = "Ecoxion")
app.post('/ocean-pay/ecoxionums/change', async (req, res) => {
  const { userId, amount, concepto = 'Operación', origen = 'Ecoxion' } = req.body;
  if (amount === undefined) return res.status(400).json({ error: 'Falta amount' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // lock & read desde ocean_pay_users (donde se guardan los ecoxionums)
    const { rows } = await client.query(
      'SELECT ecoxionums FROM ocean_pay_users WHERE id::text = $1 FOR UPDATE',
      [userId]
    );
    if (!rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    
    const currentEcoxionums = rows[0].ecoxionums || 0;
    const newBal = currentEcoxionums + amount;
    if (newBal < 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Saldo insuficiente' });
    }

    // update ecoxionums en ocean_pay_users
    await client.query(
      'UPDATE ocean_pay_users SET ecoxionums = $1 WHERE id::text = $2',
      [newBal, userId]
    );

    // log en Ocean Pay
    // Intentar con moneda si existe la columna
    try {
      await client.query(
        `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
         VALUES ($1, $2, $3, $4, 'EX')`,
        [userId, concepto, amount, origen]
      );
    } catch (e) {
      // Si falla por falta de columna moneda, insertar sin ella
      await client.query(
        `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen)
         VALUES ($1, $2, $3, $4)`,
        [userId, concepto, amount, origen]
      );
    }

    await client.query('COMMIT');
    res.json({ success: true, newBalance: newBal });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('❌ Error en /ocean-pay/ecoxionums/change:', e);
    res.status(500).json({ error: e.message || 'Error interno' });
  } finally {
    client.release();
  }
});

/* ----------  APPBUX ENDPOINTS  ---------- */
// Obtener balance de AppBux
app.get('/ocean-pay/appbux/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const { rows } = await pool.query(
      'SELECT appbux FROM ocean_pay_users WHERE id = $1',
      [userId]
    );
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    
    res.json({ appbux: rows[0].appbux || 0 });
  } catch (err) {
    console.error('❌ Error en /ocean-pay/appbux/:userId', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Cambiar balance de AppBux
app.post('/ocean-pay/appbux/change', async (req, res) => {
  const { userId, amount, concepto = 'Operación', origen = 'AllApp' } = req.body;
  
  if (!userId || amount === undefined) {
    return res.status(400).json({ error: 'Faltan datos' });
  }
  
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    // Lock & read
    const { rows } = await client.query(
      'SELECT appbux FROM ocean_pay_users WHERE id = $1 FOR UPDATE',
      [userId]
    );
    
    if (rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    
    const currentAppBux = rows[0].appbux || 0;
    const newBalance = currentAppBux + amount;
    
    if (newBalance < 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Saldo insuficiente' });
    }
    
    // Update balance
    await client.query(
      'UPDATE ocean_pay_users SET appbux = $1 WHERE id = $2',
      [newBalance, userId]
    );
    
    // Registrar transacción
    try {
      await client.query(
        `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
         VALUES ($1, $2, $3, $4, 'ABX')`,
        [userId, concepto, amount, origen]
      );
    } catch (e) {
      // Si falla por falta de columna moneda, hacer rollback y reintentar todo sin ella
      await client.query('ROLLBACK');
      await client.query('BEGIN');
      
      // Volver a leer el balance (porque hicimos rollback)
      const { rows: balanceRows } = await client.query(
        'SELECT appbux FROM ocean_pay_users WHERE id = $1 FOR UPDATE',
        [userId]
      );
      
      if (balanceRows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'Usuario no encontrado' });
      }
      
      const currentAppBuxRetry = balanceRows[0].appbux || 0;
      const newBalanceRetry = currentAppBuxRetry + amount;
      
      if (newBalanceRetry < 0) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Saldo insuficiente' });
      }
      
      // Volver a hacer el UPDATE
      await client.query(
        'UPDATE ocean_pay_users SET appbux = $1 WHERE id = $2',
        [newBalanceRetry, userId]
      );
      
      try {
        // Intentar INSERT sin la columna moneda
        await client.query(
          `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen)
           VALUES ($1, $2, $3, $4)`,
          [userId, concepto, amount, origen]
        );
        await client.query('COMMIT');
        return res.json({ success: true, newBalance: newBalanceRetry });
      } catch (e2) {
        // Si también falla el segundo INSERT, hacer rollback y lanzar error
        await client.query('ROLLBACK');
        throw e2;
      }
    }
    
    await client.query('COMMIT');
    res.json({ success: true, newBalance });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('❌ Error en /ocean-pay/appbux/change:', err);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

/* ----------  WILDCREDITS TRANSACTIONS  ---------- */
app.post('/ocean-pay/wildcredits/transaction', async (req, res) => {
  const { userId, amount, concepto = 'Operación', origen = 'Wild Explorer' } = req.body;
  if (!userId || amount === undefined) {
    return res.status(400).json({ error: 'Faltan datos' });
  }

  try {
    // Insertar transacción en ocean_pay_txs con moneda 'WC'
    await pool.query(
      `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
       VALUES ($1, $2, $3, $4, 'WC')`,
      [userId, concepto, amount, origen]
    );
    
    res.json({ success: true });
  } catch (e) {
    console.error('❌ Error en /ocean-pay/wildcredits/transaction:', e);
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

/* ========== OCEANIC ETHERNET ========== */
// Registro separado para OceanicEthernet
app.post('/oceanic-ethernet/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Faltan datos' });

  const hash = await bcrypt.hash(password, 10);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Crear usuario en tabla propia de OceanicEthernet
    const { rows: [u] } = await client.query(
      `INSERT INTO oceanic_ethernet_users (username, pwd_hash)
       VALUES ($1, $2)
       RETURNING id, username, created_at`,
      [username, hash]
    );

    // Inicializar saldo de internet en 0 usando ocean_pay_metadata (compartida)
    await client.query(`
      INSERT INTO ocean_pay_metadata (user_id, key, value)
      VALUES ($1, 'internet_gb', '0')
      ON CONFLICT (user_id, key) DO NOTHING
    `, [u.id]);

    await client.query('COMMIT');
    res.json({ success: true, user: { id: u.id, username: u.username } });

  } catch (e) {
    await client.query('ROLLBACK');
    if (e.code === '23505') {
      return res.status(409).json({ 
        error: 'Este usuario ya existe. Si es tu cuenta, usa la opción "Iniciar sesión".' 
      });
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
      return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    }
    
    const ok = await bcrypt.compare(password, rows[0].pwd_hash);
    if (!ok) {
      return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
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
      // Ignorar errores de inicialización
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
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    userId = decoded.uid;
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token inválido' });
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
  let userId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    userId = decoded.uid;
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token inválido' });
  }
  
  const { userId: paramUserId } = req.params;
  const paramUserIdNum = parseInt(paramUserId);
  
  // Verificar que el usuario del token coincida con el parámetro
  if (userId !== paramUserIdNum) {
    return res.status(403).json({ error: 'No autorizado' });
  }
  
  try {
    // Intentar obtener desde metadata primero (como wildcredits)
    const { rows: metaRows } = await pool.query(`
      SELECT value FROM ocean_pay_metadata
      WHERE user_id = $1 AND key = 'internet_gb'
    `, [userId]);
    
    if (metaRows.length > 0) {
      const balance = parseFloat(metaRows[0].value || '0');
      return res.json({ balance });
    }
    
    // Si no existe en metadata, crear registro con 0
    await pool.query(`
      INSERT INTO ocean_pay_metadata (user_id, key, value)
      VALUES ($1, 'internet_gb', '0')
      ON CONFLICT (user_id, key) DO NOTHING
    `, [userId]);
    
    res.json({ balance: 0 });
  } catch (err) {
    console.error('❌ Error en /oceanic-ethernet/balance/:userId', err);
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
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    opUserId = decoded.uid;
    opUserId = parseInt(opUserId) || opUserId;
  } catch (e) {
    return res.status(401).json({ error: 'Token inválido' });
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
    console.error('❌ Error en /oceanic-ethernet/ocean-pay-balances:', err);
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
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    userId = decoded.uid;
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token inválido' });
  }
  
  const { userId: bodyUserId, amount, currency, cost } = req.body;
  const opToken = req.headers['x-ocean-pay-token'];
  
  if (!bodyUserId || amount === undefined || amount <= 0) {
    return res.status(400).json({ error: 'Datos inválidos' });
  }
  
  // Si hay opToken vinculado, obtener su userId para validación
  let opUserId = null;
  if (opToken && opToken.trim() !== '') {
    try {
      const decoded = jwt.verify(opToken, process.env.STUDIO_SECRET);
      opUserId = decoded.uid;
      opUserId = parseInt(opUserId) || opUserId;
      console.log('✅ Token de Ocean Pay válido, opUserId:', opUserId);
    } catch (e) {
      console.error('❌ Error verificando token de Ocean Pay:', e.message);
      // Si el token es inválido, continuar sin opUserId
    }
  }
  
  // Validar autorización:
  // IMPORTANTE: El saldo de internet es específico de cada cuenta de OceanicEthernet
  // Siempre validamos que el bodyUserId coincida con el userId del token de OceanicEthernet
  // El token de Ocean Pay solo se usa para procesar el pago, no para determinar a qué cuenta se aplica el saldo
  const bodyUserIdInt = parseInt(bodyUserId);
  
  // Validar que el usuario está recargando su propia cuenta de OceanicEthernet
  if (userId !== bodyUserIdInt) {
    console.error('❌ Error de autorización en recarga:', {
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
  
  // Si hay opToken, validar que sea válido (para procesar el pago)
  if (opToken && opToken.trim() !== '' && currency && cost) {
    if (!opUserId) {
      console.error('❌ Token de Ocean Pay inválido o no decodificable');
      return res.status(401).json({ error: 'Token de Ocean Pay inválido. Por favor, vuelve a vincular tu cuenta de Ocean Pay.' });
    }
  }
  
  console.log('✅ Autorización exitosa para recarga:', {
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
      // opUserId ya fue obtenido arriba en la validación
      if (!opUserId) {
        await client.query('ROLLBACK');
        return res.status(401).json({ error: 'Token de Ocean Pay inválido' });
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
        // Si falla la verificación, asumir que no existe
        hasMonedaColumn = false;
      }
      
      // Procesar pago según la divisa
      let paymentSuccess = false;
      
      // IMPORTANTE: Redondear el costo al entero más cercano para divisas INTEGER
      // Las divisas en ocean_pay_users (aquabux, appbux) son INTEGER, no aceptan decimales
      let roundedCost = Math.round(cost);
      if (roundedCost <= 0 && cost > 0) {
        // Si el costo es mayor que 0 pero se redondea a 0, usar 1 como mínimo
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
        return res.status(400).json({ error: 'Divisa no válida' });
      }
    }
    
    // Obtener balance actual de internet
    // IMPORTANTE: Siempre usar el userId de OceanicEthernet para el saldo de internet
    // El saldo de internet es específico de cada cuenta de OceanicEthernet
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
    
    // Registrar transacción en tabla propia de OceanicEthernet (usar userId de OceanicEthernet para el historial)
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
    console.error('❌ Error en /oceanic-ethernet/recharge:', err);
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
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    userId = decoded.uid;
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token inválido' });
  }
  
  const { userId: bodyUserId, amount, concepto = 'Uso de internet', origen = 'AllApp' } = req.body;
  
  if (!bodyUserId || amount === undefined || amount <= 0) {
    return res.status(400).json({ error: 'Datos inválidos' });
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
    
    // Registrar transacción en tabla propia de OceanicEthernet
    await client.query(
      `INSERT INTO oceanic_ethernet_txs (user_id, concepto, monto, origen)
       VALUES ($1, $2, $3, $4)`,
      [userId, concepto, -amount, origen]
    );
    
    await client.query('COMMIT');
    res.json({ success: true, newBalance });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('❌ Error en /oceanic-ethernet/consume:', err);
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
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    userId = decoded.uid;
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token inválido' });
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
    console.error('❌ Error en /oceanic-ethernet/transactions/:userId', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Obtener historial reciente (último minuto) para tiempo real
app.get('/oceanic-ethernet/recent/:userId', async (req, res) => {
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
  
  const { userId: paramUserId } = req.params;
  const paramUserIdNum = parseInt(paramUserId);
  
  if (userId !== paramUserIdNum) {
    return res.status(403).json({ error: 'No autorizado' });
  }
  
  try {
    // Obtener transacciones de los últimos 60 segundos de la tabla propia
    const { rows } = await pool.query(`
      SELECT concepto, monto as amount, origen, created_at
      FROM oceanic_ethernet_txs
      WHERE user_id = $1 
        AND created_at > NOW() - INTERVAL '1 minute'
      ORDER BY created_at DESC
    `, [userId]);
    
    res.json(rows);
  } catch (err) {
    console.error('❌ Error en /oceanic-ethernet/recent/:userId', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

app.post('/api/report-error', async (req,res)=>{
  const {userId, type, description, extensions, userAgent, url, timestamp} = req.body;
  if(!type || !description) return res.status(400).json({error:'Faltan campos'});

  try{
    await pool.query(
     `INSERT INTO error_reports (user_id, type, description, extensions, user_agent, url, created_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [userId, type, description, extensions, userAgent, url, timestamp]
    );
    res.json({ok:true});
  }catch(e){
    console.error('❌ report-error',e);
    res.status(500).json({error:'No se pudo guardar'});
  }
});

app.get('/admin/error-reports', async (req,res)=>{
  const secret = req.headers['x-admin-secret'];
  if(secret !== process.env.STUDIO_SECRET) return res.status(401).json({error:'No autorizado'});

  const {rows} = await pool.query(
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
  emoji: ev.emoji || '🎁',
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

  // Entregar extensión día 7
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

  // 1. ¿Hay evento activo?
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

  // 🕓 Próximo reinicio diario (medianoche UTC o local)
  const nextReset = new Date(now);
  nextReset.setUTCHours(24, 0, 0, 0); // medianoche UTC siguiente día
  const msLeft = Math.max(0, nextReset - now);

  // 2. ¿Cuántos días ha reclamado este usuario?
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
        const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
        const userId = decoded.uid || decoded.id || decoded.userId;

        // Get user info
        const userResult = await pool.query(
            'SELECT id, username FROM users WHERE id = $1',
            [userId]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }

        const userData = userResult.rows[0];
        
        // Get the balance
        const balanceResult = await pool.query(
            `SELECT amount 
             FROM user_currency 
             WHERE user_id = $1 AND currency_type = 'ecocorebits'`,
            [userId]
        );

        const balance = balanceResult.rows[0]?.amount || 0;

        // Return in the same format as Ocean Pay
        res.json({
            success: true,
            user: {
                id: userData.id,
                username: userData.username,
                ecorebits: {
                    balance: parseInt(balance, 10)
                }
            }
        });

    } catch (error) {
        console.error('Error in /api/ecorebits/user:', error);
        res.status(500).json({ 
            success: false,
            message: 'Error del servidor',
            error: error.message 
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
        const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
        // El token de Ocean Pay usa 'uid', no 'userId'
        const userId = String(decoded.uid || decoded.userId || decoded.id || decoded.user?.id || '');

        if (!userId || userId === 'undefined' || userId === 'null') {
            console.error('Token decodificado:', decoded);
            return res.status(401).json({ error: 'Token inválido: falta userId. Campos disponibles: ' + Object.keys(decoded).join(', ') });
        }

        // Verificar que el usuario existe
        const { rows: userCheck } = await pool.query(
            'SELECT id FROM users WHERE id = $1',
            [userId]
        );

        if (!userCheck || userCheck.length === 0) {
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
            // El límite se maneja en el frontend, no en la BD
            result = {
                success: true,
                newLimit: null, // Se calculará en el frontend
                ecocorebits: newBalance
            };

        } else if (option === 'credits') {
            // Obtener créditos desde ecocore_credits
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
                    error: 'No tienes suficientes créditos' 
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
                newLimit: null, // Se calculará en el frontend
                credits: newCredits
            };

        } else {
            return res.status(400).json({ error: 'Opción no válida' });
        }

            // Log the transaction (asegurar que userId es string)
        await pool.query(
            `INSERT INTO command_limit_extensions 
             (user_id, extension_type, commands_added, cost, extended_at)
             VALUES ($1, $2, $3, $4, $5)`,
            [
                String(userId),
                option,
                option === 'ecocorebits' ? 10 : 5,
                option === 'ecocorebits' ? 100 : 1,
                now
            ]
        );

        res.json(result);

    } catch (error) {
        console.error('Error extending command limit:', error);
        
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ error: 'Token inválido' });
        }
        
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Sesión expirada' });
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
    const d = jwt.verify(token, process.env.STUDIO_SECRET);
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
      const daysRemaining = Math.ceil(msRemain / (1000*60*60*24));
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
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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
       DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP`,
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
    const concept = `Suscripción Pro (DeepDive) - ${plan === 'weekly' ? 'Semanal' : 'Mensual'}`;
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
    } catch {}

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
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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
       DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP`,
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
    const concept = `Renovación Pro (DeepDive) - ${plan === 'weekly' ? 'Semanal' : 'Mensual'}`;
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