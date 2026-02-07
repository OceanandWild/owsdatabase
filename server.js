import dotenv from "dotenv";
dotenv.config();

// 1️⃣ Después el resto
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

// Configuración de MercadoPago
const mpClient = new MercadoPagoConfig({ accessToken: 'APP_USR-5761093164230281-020117-8a36b5725093b330c07cf54699b7edb1-3171975745' }); // PRODUCCIÓN
// const mpClient = new MercadoPagoConfig({ accessToken: 'TEST-5761093164230281-020117-88b51453f4f07dd0e52e6ae5bb580609-3171975745' }); // PRUEBA (Comentado)

/* ===== NAT-MARKET VARS ===== */
let storage;
const uploadDir = path.join(process.cwd(), 'uploads');

// HARDCODED CREDENTIALS (TEMPORAL - Para asegurar que funcione en Render)
const CLOUD_NAME = 'dwoxdneqa';
const API_KEY = '572422228753764';
const API_SECRET = 'ORuFuHJqy82NxGlHshZo3SBrC8E';

// Configuración INCONDICIONAL de Cloudinary
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
console.log('☁️ Usando Cloudinary (Hardcoded) para almacenamiento de imágenes');

const upload = multer({ storage });

// Función para generar ID único de usuario (100 caracteres)
function generateUserUniqueId() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < 100; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// Función para generar datos de tarjeta
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

app.use(cors());
app.use(express.json());

/* =========================================
   WORD BATTLE MULTIPLAYER LOGIC
   ========================================= */
const wbRooms = {};

io.on('connection', (socket) => {
  console.log('🔌 Nuevo cliente conectado:', socket.id);

  // --- Crear Sala ---
  socket.on('wb_create_room', ({ playerName }) => {
    try {
      const roomCode = Math.random().toString(36).substring(2, 8).toUpperCase();
      wbRooms[roomCode] = {
        code: roomCode,
        host: socket.id,
        players: [{
          id: socket.id,
          name: playerName || 'Jugador 1',
          lives: 3,
          score: 0,
          avatar: '😎',
          eliminated: false
        }],
        state: 'lobby',
        round: 0,
        currentLetters: '',
        turnIndex: 0,
        timer: null,
        timeLeft: 0
      };

      socket.join(roomCode);
      socket.emit('wb_joined', { roomCode, isHost: true });
      io.to(roomCode).emit('wb_room_update', wbRooms[roomCode]);
      console.log(`Sala creada: ${roomCode} por ${playerName}`);
    } catch (e) {
      console.error(e);
    }
  });

  // --- Unirse a Sala ---
  socket.on('wb_join_room', ({ roomCode, playerName }) => {
    roomCode = roomCode?.toUpperCase();
    const room = wbRooms[roomCode];

    if (!room) {
      socket.emit('wb_error', 'Sala no encontrada');
      return;
    }

    if (room.state !== 'lobby') {
      socket.emit('wb_error', 'La partida ya comenzó');
      return;
    }

    if (room.players.length >= 8) {
      socket.emit('wb_error', 'Sala llena');
      return;
    }

    const newPlayer = {
      id: socket.id,
      name: playerName || `Jugador ${room.players.length + 1}`,
      lives: 3,
      score: 0,
      avatar: '👤',
      eliminated: false
    };

    room.players.push(newPlayer);
    socket.join(roomCode);

    socket.emit('wb_joined', { roomCode, isHost: false });
    io.to(roomCode).emit('wb_room_update', room);
    console.log(`${playerName} se unió a ${roomCode}`);
  });

  // --- Iniciar Partida ---
  socket.on('wb_start_game', ({ roomCode }) => {
    const room = wbRooms[roomCode];
    if (!room || room.host !== socket.id) return;

    room.state = 'playing';
    room.round = 1;
    room.turnIndex = 0; // Empieza el host

    io.to(roomCode).emit('wb_game_started');
    startTurn(roomCode);
  });

  // --- Enviar Palabra ---
  socket.on('wb_submit_word', ({ roomCode, word }) => {
    const room = wbRooms[roomCode];
    if (!room || room.state !== 'playing') return;

    // Verificar si es turno del jugador
    const activePlayers = room.players.filter(p => !p.eliminated);
    const currentPlayer = activePlayers[room.turnIndex % activePlayers.length];

    if (currentPlayer.id !== socket.id) return;

    word = word.toLowerCase();
    const letters = room.currentLetters.toLowerCase();

    // Validación básica: debe contener las letras y ser > 2 chars
    if (word.includes(letters) && word.length > 2) {
      // Palabra válida (simplificado para demo)
      stopRoomTimer(room);
      currentPlayer.score += 10 + word.length; // Puntos

      io.to(roomCode).emit('wb_word_accepted', { word, playerId: socket.id, score: currentPlayer.score });

      // Siguiente turno
      room.turnIndex++;
      startTurn(roomCode);
    } else {
      socket.emit('wb_error', `La palabra debe contener "${room.currentLetters.toUpperCase()}"`);
    }
  });

  // --- Desconexión ---
  socket.on('disconnect', () => {
    // Buscar en qué sala estaba y remover
    Object.keys(wbRooms).forEach(code => {
      const room = wbRooms[code];
      const pIndex = room.players.findIndex(p => p.id === socket.id);
      if (pIndex !== -1) {
        room.players.splice(pIndex, 1);
        if (room.players.length === 0) {
          delete wbRooms[code]; // Eliminar sala vacía
        } else {
          // Si era host, asignar nuevo
          if (room.host === socket.id) {
            room.host = room.players[0].id;
          }
          io.to(code).emit('wb_room_update', room);
        }
      }
    });
  });
});

// --- Helpers Word Battle ---
function startTurn(roomCode) {
  const room = wbRooms[roomCode];
  if (!room) return;

  const activePlayers = room.players.filter(p => !p.eliminated);

  // Verificar condiciones de fin
  if (activePlayers.length <= 1 && room.players.length > 1) { // Si queda 1 y había más de 1
    endGame(roomCode, activePlayers[0]);
    return;
  }

  // Generar letras aleatorias
  const syllables = ['CAR', 'TER', 'QUE', 'SOL', 'MAR', 'CON', 'EST', 'VER', 'SAL', 'PAN', 'LUZ', 'RIO', 'TRA', 'PLA', 'DIS'];
  room.currentLetters = syllables[Math.floor(Math.random() * syllables.length)];
  room.timeLeft = 10; // 10 segundos para responder (Rápido!)

  const currentPlayer = activePlayers[room.turnIndex % activePlayers.length];

  io.to(roomCode).emit('wb_new_turn', {
    letters: room.currentLetters,
    playerId: currentPlayer.id,
    playerName: currentPlayer.name,
    timeLeft: room.timeLeft
  });

  // Iniciar timer
  clearInterval(room.timer);
  room.timer = setInterval(() => {
    room.timeLeft--;

    if (room.timeLeft <= 0) {
      clearInterval(room.timer);
      handlePlayerFail(roomCode, currentPlayer.id);
    }
  }, 1000);
}

function handlePlayerFail(roomCode, playerId) {
  const room = wbRooms[roomCode];
  if (!room) return;

  const player = room.players.find(p => p.id === playerId);
  if (player) {
    player.lives--;
    io.to(roomCode).emit('wb_player_damage', { playerId, lives: player.lives });

    if (player.lives <= 0) {
      player.eliminated = true;
      io.to(roomCode).emit('wb_player_eliminated', { playerId });
    }
  }

  room.turnIndex++;
  startTurn(roomCode); // Siguiente turno
}

function stopRoomTimer(room) {
  if (room && room.timer) clearInterval(room.timer);
}

function endGame(roomCode, winner) {
  const room = wbRooms[roomCode];
  if (!room) return;
  stopRoomTimer(room);
  room.state = 'ended';
  io.to(roomCode).emit('wb_game_over', { winner });

  // Limpiar después de un tiempo
  setTimeout(() => {
    delete wbRooms[roomCode];
  }, 60000);
}

import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/* ========== MIGRACIÓN AUTOMÁTICA DE BASE DE DATOS ========== */
async function runDatabaseMigrations() {
  console.log('🔄 Ejecutando migraciones de base de datos...');

  try {
    // 0. Corregir nombres de columnas en users_nat (necesario para Supabase / NatMarket)
    console.log('🔧 Corrigiendo esquema de users_nat...');
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
    `).catch(err => console.log('⚠️ Aviso: Migración de nombres de columna users_nat:', err.message));

    // 1. Agregar columna comment a user_ratings_nat si no existe
    await pool.query(`
      ALTER TABLE user_ratings_nat 
      ADD COLUMN IF NOT EXISTS comment TEXT
    `).catch(() => console.log('⚠️ Columna comment ya existe en user_ratings_nat'));

    // 2. Eliminar y recrear foreign keys con ON DELETE CASCADE
    console.log('🔧 Arreglando foreign keys...');

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
    `).catch(() => console.log('⚠️ FK ai_product_generations ya existe'));

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
    `).catch(() => console.log('⚠️ FK messages_nat ya existe'));

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
    `).catch(() => console.log('⚠️ FK user_favorites_nat ya existe'));

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
    `).catch(() => console.log('⚠️ FK user_wishlist_nat ya existe'));

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

    // 3. Limpiar registros huérfanos (datos que referencian usuarios inexistentes)
    console.log('🧹 Limpiando datos huérfanos...');

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
    `).catch(() => console.log('⚠️ Tabla reviews_nat ya existe'));

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
    `).catch(() => console.log('⚠️ Columna unique_id ya existe en ocean_pay_users'));

    // 6. Agregar columnas de monedas si no existen
    await pool.query(`
      ALTER TABLE ocean_pay_users 
      ADD COLUMN IF NOT EXISTS ecoxionums INTEGER DEFAULT 0,
      ADD COLUMN IF NOT EXISTS aquabux INTEGER DEFAULT 0,
      ADD COLUMN IF NOT EXISTS appbux INTEGER DEFAULT 0
    `).catch(() => console.log('⚠️ Columnas de monedas ya existen en ocean_pay_users'));

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
    `).catch(err => console.log('⚠️ Aviso: Migración command_limit_extensions:', err.message));

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
    `).catch(() => console.log('⚠️ Tabla ocean_pay_cards ya existe'));

    // 9. Crear tabla ocean_pay_card_balances para saldos por tarjeta
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ocean_pay_card_balances (
        id SERIAL PRIMARY KEY,
        card_id INTEGER NOT NULL REFERENCES ocean_pay_cards(id) ON DELETE CASCADE,
        currency_type VARCHAR(50) NOT NULL,
        amount DECIMAL(20, 2) DEFAULT 0,
        UNIQUE(card_id, currency_type)
      )
    `).catch(() => console.log('⚠️ Tabla ocean_pay_card_balances ya existe'));

    // 10. Añadir columnas faltantes a ocean_pay_cards
    await pool.query(`
      ALTER TABLE ocean_pay_cards 
      ADD COLUMN IF NOT EXISTS is_primary BOOLEAN DEFAULT false,
      ADD COLUMN IF NOT EXISTS card_name VARCHAR(50) DEFAULT 'Mi Tarjeta'
    `).catch(() => { });

    // 11. Crear tabla ocean_pay_pos si no existe (POS Virtual)
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
        status VARCHAR(20) DEFAULT 'pending', -- pending, completed, expired, cancelled
        created_at TIMESTAMP DEFAULT NOW(),
        completed_at TIMESTAMP
      )
    `).catch(() => console.log('⚠️ Tabla ocean_pay_pos ya existe'));

    // 12. Generar tarjetas para usuarios existentes que no tengan una
    const usersWithoutCard = await pool.query(`
      SELECT id FROM ocean_pay_users 
      WHERE id NOT IN (SELECT user_id FROM ocean_pay_cards)
    `);

    for (const user of usersWithoutCard.rows) {
      const { cardNumber, cvv, expiryDate } = generateCardDetails();
      const cardResult = await pool.query(
        'INSERT INTO ocean_pay_cards (user_id, card_number, cvv, expiry_date, is_primary, card_name) VALUES ($1, $2, $3, $4, true, $5) RETURNING id',
        [user.id, cardNumber, cvv, expiryDate, 'Tarjeta Principal']
      ).catch(e => { console.error('Error generando tarjeta para usuario:', user.id, e.message); return null; });

      if (cardResult && cardResult.rows[0]) {
        // Inicializar saldos para la nueva tarjeta
        const currencies = ['aquabux', 'ecoxionums', 'ecorebits', 'wildcredits', 'wildgems', 'appbux', 'ecobooks', 'ecotokens', 'ecopower'];
        for (const curr of currencies) {
          await pool.query(
            'INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount) VALUES ($1, $2, 0) ON CONFLICT DO NOTHING',
            [cardResult.rows[0].id, curr]
          );
        }
      }
    }

    // 11. Establecer tarjeta principal para usuarios que no tengan una (CRÍTICO: Hacer esto ANTES de migrar saldos)
    await pool.query(`
      UPDATE ocean_pay_cards c SET is_primary = true
      WHERE c.id = (
        SELECT MIN(id) FROM ocean_pay_cards WHERE user_id = c.user_id
      ) AND NOT EXISTS (
        SELECT 1 FROM ocean_pay_cards WHERE user_id = c.user_id AND is_primary = true
      )
    `);

    // 12. Migrar saldos existentes (AquaBux, Ecoxionums, AppBux, EcoCoreBits) a la tarjeta principal
    console.log('🔄 Sincronizando saldos históricos con el sistema de tarjetas...');

    await pool.query(`
      INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount)
      SELECT c.id, 'aquabux', u.aquabux
      FROM ocean_pay_cards c JOIN ocean_pay_users u ON c.user_id = u.id WHERE c.is_primary = true
      ON CONFLICT (card_id, currency_type) DO UPDATE SET amount = EXCLUDED.amount WHERE ocean_pay_card_balances.amount = 0;

      INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount)
      SELECT c.id, 'appbux', u.appbux
      FROM ocean_pay_cards c JOIN ocean_pay_users u ON c.user_id = u.id WHERE c.is_primary = true
      ON CONFLICT (card_id, currency_type) DO UPDATE SET amount = EXCLUDED.amount WHERE ocean_pay_card_balances.amount = 0;

      INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount)
      SELECT c.id, 'ecorebits', COALESCE(uc.amount, 0)
      FROM ocean_pay_cards c
      JOIN ocean_pay_users u ON c.user_id = u.id
      LEFT JOIN user_currency uc ON u.id = uc.user_id AND uc.currency_type = 'ecocorebits'
      WHERE c.is_primary = true
      ON CONFLICT (card_id, currency_type) DO UPDATE SET amount = EXCLUDED.amount WHERE ocean_pay_card_balances.amount = 0;

      INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount)
      SELECT c.id, 'ecopower', 100
      FROM ocean_pay_cards c WHERE c.is_primary = true
      ON CONFLICT (card_id, currency_type) DO NOTHING;
    `);

    /* 
    // 13. LIMPIEZA DE SALDOS - Resetear todos a 0 (excepto ecopower = 100)
    // Se limpian tanto los nuevos saldos por tarjeta como los antiguos saldos globales
    console.log('🧹 Iniciando limpieza profunda de saldos...');

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
      WHERE key IN ('wildcredits', 'ecoxionums', 'ecobooks')
    `);

    console.log('✅ Limpieza de saldos completada. Todos los sistemas en cero.');
    */
    console.log('✅ Sistema de persistencia de saldos activo.');

    console.log('✅ Migraciones completadas exitosamente!');

  } catch (err) {
    console.error('❌ Error en migraciones:', err.message);
  }
}

// Ejecutar migraciones al iniciar el servidor
runDatabaseMigrations();

/* ===== HEALTH CHECK / STATUS ENDPOINT ===== */
// Este endpoint se usa para verificar que el servidor esté funcionando
// y proporciona el estado de los servicios principales.
app.get('/status', async (_req, res) => {
  const services = {
    server: { status: 'up', name: 'OWS Database Server' },
    ecoconsole: { status: 'up', name: 'EcoConsole' },
    ecoxion: { status: 'up', name: 'Ecoxion' },
    natmarket: { status: 'up', name: 'NatMarket' },
    naturepedia: { status: 'up', name: 'Naturepedia' }
  };

  // Verificar conexión a base de datos
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

// Autenticación directa con Ocean Pay
app.post('/ecoconsole/auth', async (req, res) => {
  const { token } = req.body;
  // TODO: Validar token con Ocean Pay system
  res.json({ success: true, message: "Placeholder: Autenticación exitosa" });
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

// Estadísticas del usuario
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
// Registro
app.post('/floret/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Usuario y contraseña son requeridos' });
  }
  try {
    const hashed = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      `INSERT INTO floret_users (username, email, password) VALUES ($1, $2, $3) RETURNING id, username, email, created_at`,
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
app.post('/floret/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Usuario y contraseña son requeridos' });
  }
  try {
    const { rows } = await pool.query('SELECT * FROM floret_users WHERE username = $1', [username]);
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Usuario no encontrado' });
    }
    const valid = await bcrypt.compare(password, rows[0].password);
    if (!valid) {
      return res.status(401).json({ error: 'Contraseña incorrecta' });
    }
    const { id, email, created_at } = rows[0];
    res.json({ success: true, user: { id, username, email, created_at } });
  } catch (e) {
    console.error('Error en login Floret:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Endpoint para crear preferencia de MercadoPago
app.post('/floret/create_preference', async (req, res) => {
  try {
    const { items, back_url } = req.body;

    // ⚠️ FIX CRÍTICO: MercadoPago rechaza localhost/http en auto_return.
    // Forzamos SIEMPRE la URL de producción (HTTPS) para evitar el error 400.
    const returnUrl = 'https://floretshop.netlify.app';

    console.log(`[MP Preference] Creando preferencia. Return URL forzada: ${returnUrl}`);

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

// Obtener productos
app.get('/floret/products', async (_req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT id, name, description, price, condition, images, requires_size, sizes, measurements, created_at 
      FROM floret_products ORDER BY created_at DESC
    `);
    const products = rows.map(r => ({
      id: r.id,
      name: r.name,
      description: r.description,
      price: parseFloat(r.price),
      condition: r.condition,
      images: r.images || [],
      requiresSize: r.requires_size,
      sizes: r.sizes || [],
      measurements: r.measurements
    }));
    res.json(products);
  } catch (e) {
    console.error('Error obteniendo productos Floret:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Crear producto (admin)
app.post('/floret/products', async (req, res) => {
  const { name, description, price, condition, images, requiresSize, sizes, measurements } = req.body;
  if (!name || !price) {
    return res.status(400).json({ error: 'Nombre y precio son requeridos' });
  }
  try {
    const { rows } = await pool.query(`
      INSERT INTO floret_products (name, description, price, condition, images, requires_size, sizes, measurements)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *
    `, [name, description || '', price, condition || 'Nuevo', images || [], requiresSize || false, sizes || [], measurements || '']);
    res.json({ success: true, product: rows[0] });
  } catch (e) {
    console.error('Error creando producto Floret:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Eliminar producto
app.delete('/floret/products/:id', async (req, res) => {
  const { id } = req.params;
  try {
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

// Servir archivos estáticos de Ocean Pay
app.use('/ocean-pay', express.static(join(__dirname, 'Ocean Pay')));

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
      INSERT INTO ocean_pay_metadata(user_id, key, value)
    VALUES($1, 'wildgems', $2)
      ON CONFLICT(user_id, key) 
      DO UPDATE SET value = $2
      `, [userId, newBalance.toString()]);

    // Registrar transacción
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

/* ===== WILD SAVAGE - ECOTOKENS ===== */
// Endpoint para obtener balance de EcoTokens
app.get('/wild-savage/ecotokens/balance', async (req, res) => {
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
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    userId = decoded.uid;
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token inválido' });
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
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    userId = decoded.uid;
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.status(401).json({ error: 'Token inválido' });
  }

  const { amount, concepto = 'Operación', origen = 'Wild Savage' } = req.body;
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

    // Registrar transacción
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

      // Registrar transacción
      await client.query(`
        INSERT INTO ocean_pay_txs(user_id, concepto, monto, origen, moneda)
    VALUES($1, $2, $3, $4, 'WG')
      `, [userId, `Suscripción ${planId} (WildShorts) - Semanal`, -planPrice, 'WildShorts']).catch(async () => {
        await client.query(`
          INSERT INTO ocean_pay_txs(user_id, concepto, monto, origen)
    VALUES($1, $2, $3, $4)
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

    // Crear nueva suscripción
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
    AND(ends_at IS NULL OR ends_at > NOW())
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
      CREATE TABLE IF NOT EXISTS wildgems_claims(
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
      ON wildgems_claims(user_id, claim_type)
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
        error: `Ya reclamaste tu recompensa diaria hoy.Próxima recompensa en ${hoursUntil} horas.`,
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

  // Verificar límite de anuncios (máximo 5 por día)
  if (type === 'ad_watch') {
    const { rows: adRows } = await pool.query(`
      SELECT COUNT(*) as count FROM wildgems_claims
      WHERE user_id = $1 AND claim_type = 'ad_watch' 
      AND DATE(claimed_at) = DATE(NOW())
      `, [userId]);

    if (parseInt(adRows[0].count) >= 5) {
      return res.status(400).json({ error: 'Has alcanzado el límite de 5 anuncios por día.' });
    }
  }

  // Verificar límite de compartir (máximo 3 por día)
  if (type === 'social_share') {
    const { rows: shareRows } = await pool.query(`
      SELECT COUNT(*) as count FROM wildgems_claims
      WHERE user_id = $1 AND claim_type = 'social_share' 
      AND DATE(claimed_at) = DATE(NOW())
      `, [userId]);

    if (parseInt(shareRows[0].count) >= 3) {
      return res.status(400).json({ error: 'Has alcanzado el límite de 3 compartidos por día.' });
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
    return res.status(400).json({ error: 'Cantidad inválida' });
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
      INSERT INTO ocean_pay_metadata(user_id, key, value)
    VALUES($1, 'wildgems', $2)
      ON CONFLICT(user_id, key) 
      DO UPDATE SET value = $2
      `, [userId, newBalance.toString()]);

    // Registrar reclamación
    await client.query(`
      INSERT INTO wildgems_claims(user_id, claim_type, amount)
    VALUES($1, $2, $3)
      `, [userId, type, gemsAmount]);

    // Insertar transacción según la estructura de la tabla (ya sabemos si tiene moneda)
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

/* ===== ECOXION - ECOXIONUMS ===== */

// Endpoint para obtener balance de Ecoxionums
app.get('/ocean-pay/ecoxionums/balance', async (req, res) => {
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
      WHERE user_id = $1 AND key = 'ecoxionums'
      `, [userId]);

    const ecoxionums = rows.length > 0 ? parseInt(rows[0].value || '0') : 0;
    res.json({ ecoxionums });
  } catch (e) {
    if (e.code === '42P01') {
      res.json({ ecoxionums: 0 });
    } else {
      console.error('Error obteniendo ecoxionums:', e);
      res.status(500).json({ error: 'Error interno' });
    }
  }
});

// Endpoint para sincronizar Ecoxionums desde cliente (si aplica)
app.post('/ocean-pay/ecoxionums/sync', async (req, res) => {
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

  const { ecoxionums } = req.body;
  if (ecoxionums === undefined || ecoxionums === null) {
    return res.status(400).json({ error: 'ecoxionums requerido' });
  }

  const amount = parseInt(ecoxionums || '0');

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
    VALUES($1, 'ecoxionums', $2)
      ON CONFLICT(user_id, key) 
      DO UPDATE SET value = $2
      `, [userId, amount.toString()]);

    // También actualizar en la tabla de usuarios para consistencia
    await pool.query(
      `UPDATE ocean_pay_users SET ecoxionums = $1 WHERE id = $2`,
      [amount, userId]
    );

    res.json({ success: true, ecoxionums: amount });
  } catch (e) {
    console.error('Error sincronizando ecoxionums:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Endpoint para cambiar Ecoxionums (ganar/gastar)
app.post('/ocean-pay/ecoxionums/change', async (req, res) => {
  const authHeader = req.headers.authorization;
  // Permitir llamadas sin token si es una acción interna confiable (ej: desde otro backend),
  // pero por ahora requerimos token de usuario o una API Key de servicio (simplificado a token user)
  // TODO: Mejorar seguridad servidor-a-servidor si es necesario.

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    // Check if body has userId and authorized secret (simulation for internal calls)
    // For now, strict user token check
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.substring(7);
  let userId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    userId = decoded.uid;
    userId = parseInt(userId) || userId;
  } catch (e) {
    // Fallback: check body for manual override (NOT SECURE FOR PROD - DEV ONLY)
    if (req.body.userId) userId = req.body.userId;
    else return res.status(401).json({ error: 'Token inválido' });
  }

  const { amount, concepto = 'Operación Ecoxion', origen = 'Ecoxion' } = req.body;
  if (amount === undefined) {
    return res.status(400).json({ error: 'amount requerido' });
  }

  // Si userId viene del body (bypass), usar ese. Si no, el del token.
  // IMPORTANTE: En prod esto es inseguro. Asumimos entorno controlado.
  const targetUserId = req.body.userId || userId;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Obtener saldo actual
    const { rows } = await client.query(`
      SELECT value FROM ocean_pay_metadata
      WHERE user_id = $1 AND key = 'ecoxionums'
      FOR UPDATE
      `, [targetUserId]);

    const current = parseInt(rows[0]?.value || '0');
    const newBalance = current + parseInt(amount);

    if (newBalance < 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Saldo insuficiente' });
    }

    // Actualizar saldo
    await client.query(`
      INSERT INTO ocean_pay_metadata(user_id, key, value)
    VALUES($1, 'ecoxionums', $2)
      ON CONFLICT(user_id, key) 
      DO UPDATE SET value = $2
      `, [targetUserId, newBalance.toString()]);

    // También actualizar en la tabla de usuarios
    await client.query(
      `UPDATE ocean_pay_users SET ecoxionums = $1 WHERE id = $2`,
      [newBalance, targetUserId]
    );

    // Registrar transacción
    await client.query(`
      INSERT INTO ocean_pay_txs(user_id, concepto, monto, origen, moneda)
    VALUES($1, $2, $3, $4, 'ECO')
      ON CONFLICT DO NOTHING
      `, [targetUserId, concepto, amount, origen]).catch(async () => {
      // Compatibilidad si falta columna moneda
      await client.query(`
        INSERT INTO ocean_pay_txs(user_id, concepto, monto, origen)
    VALUES($1, $2, $3, $4)
      `, [targetUserId, concepto, amount, origen]);
    });

    await client.query('COMMIT');
    res.json({ success: true, newBalance });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Error cambiando ecoxionums:', e);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

/* ===== OCEAN PAY - CORE TRANSFER ===== */

// Transferencia P2P Genérica
app.post('/ocean-pay/transfer', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.substring(7);
  let senderId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    senderId = parseInt(decoded.uid) || decoded.uid;
  } catch (e) {
    return res.status(401).json({ error: 'Token inválido' });
  }

  const { recipientUsername, amount, currency = 'ecoxionums', note = '' } = req.body;
  if (!recipientUsername || !amount || amount <= 0) {
    return res.status(400).json({ error: 'Datos inválidos' });
  }

  // Mapeo de moneda a key de metadata
  const currencyKeyMap = {
    'ecoxionums': 'ecoxionums',
    'wildgems': 'wildgems',
    'wildcredits': 'wildcredits',
    'aquabux': 'aquabux', // Si se llega a implementar en metadta
    'tides': 'tides'
  };

  const currencyKey = currencyKeyMap[currency.toLowerCase()] || currency.toLowerCase();
  const currencyCode = currency.toUpperCase().substring(0, 3); // EJ: ECO, GEM, CRE

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1. Buscar receptor en ocean_pay_users (tabla correcta de Ocean Pay)
    const { rows: recipientRows } = await client.query('SELECT id FROM ocean_pay_users WHERE username = $1', [recipientUsername]);
    if (recipientRows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Usuario destinatario no encontrado' });
    }
    const recipientId = recipientRows[0].id;

    // 1.5 Obtener username del remitente para mostrarlo en el historial del receptor
    const { rows: senderRows } = await client.query('SELECT username FROM ocean_pay_users WHERE id = $1', [senderId]);
    const senderUsername = senderRows[0]?.username || `Usuario #${senderId} `;

    if (senderId === recipientId) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'No puedes enviarte dinero a ti mismo' });
    }

    // 2. Verificar saldo remitente
    const { rows: senderBalanceRows } = await client.query(`
      SELECT value FROM ocean_pay_metadata
      WHERE user_id = $1 AND key = $2
      FOR UPDATE
      `, [senderId, currencyKey]);

    const senderBalance = parseInt(senderBalanceRows[0]?.value || '0');
    if (senderBalance < amount) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Saldo insuficiente' });
    }

    // 3. Descontar remitente
    const newSenderBalance = senderBalance - amount;
    await client.query(`
      INSERT INTO ocean_pay_metadata(user_id, key, value)
    VALUES($1, $2, $3)
      ON CONFLICT(user_id, key) DO UPDATE SET value = $3
      `, [senderId, currencyKey, newSenderBalance.toString()]);

    // 4. Sumar receptor
    const { rows: recipientBalanceRows } = await client.query(`
      SELECT value FROM ocean_pay_metadata
      WHERE user_id = $1 AND key = $2
      FOR UPDATE
      `, [recipientId, currencyKey]);

    const recipientBalance = parseInt(recipientBalanceRows[0]?.value || '0');
    const newRecipientBalance = recipientBalance + parseInt(amount);

    await client.query(`
      INSERT INTO ocean_pay_metadata(user_id, key, value)
    VALUES($1, $2, $3)
      ON CONFLICT(user_id, key) DO UPDATE SET value = $3
      `, [recipientId, currencyKey, newRecipientBalance.toString()]);

    // Si la moneda es ecoxionums, actualizar también la tabla ocean_pay_users
    if (currencyKey === 'ecoxionums') {
      await client.query(`UPDATE ocean_pay_users SET ecoxionums = $1 WHERE id = $2`, [newSenderBalance, senderId]);
      await client.query(`UPDATE ocean_pay_users SET ecoxionums = $1 WHERE id = $2`, [newRecipientBalance, recipientId]);
    }

    // 5. Registrar transacciones (Para ambos: gasto e ingreso)
    const conceptoSender = `Transferencia a ${recipientUsername} ${note ? `(${note})` : ''} `;
    const conceptoRecipient = `Transferencia de ${senderUsername} ${note ? `(${note})` : ''} `;

    // Gasto
    await client.query(`
      INSERT INTO ocean_pay_txs(user_id, concepto, monto, origen, moneda)
    VALUES($1, $2, $3, 'P2P', $4)
      `, [senderId, conceptoSender, -amount, currencyCode]).catch(async () => {
      await client.query(`
        INSERT INTO ocean_pay_txs(user_id, concepto, monto, origen)
    VALUES($1, $2, $3, 'P2P')
      `, [senderId, conceptoSender, -amount]);
    });

    // Ingreso
    await client.query(`
      INSERT INTO ocean_pay_txs(user_id, concepto, monto, origen, moneda)
    VALUES($1, $2, $3, 'P2P', $4)
      `, [recipientId, conceptoRecipient, amount, currencyCode]).catch(async () => {
      await client.query(`
        INSERT INTO ocean_pay_txs(user_id, concepto, monto, origen)
    VALUES($1, $2, $3, 'P2P')
      `, [recipientId, conceptoRecipient, amount]);
    });

    await client.query('COMMIT');
    res.json({ success: true, newBalance: newSenderBalance });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Error en transferencia P2P:', e);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

// Historial de Transacciones
app.get('/ocean-pay/history/:userId', async (req, res) => {
  const userId = parseInt(req.params.userId);
  if (isNaN(userId)) {
    return res.status(400).json({ error: 'userId inválido' });
  }

  try {
    // Primero intentar crear la tabla si no existe
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ocean_pay_txs(
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        concepto TEXT,
        monto INTEGER DEFAULT 0,
        origen TEXT DEFAULT 'Ecoxion',
        moneda TEXT DEFAULT 'ECO',
        fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
      `);

    const { rows } = await pool.query(`
    SELECT * FROM ocean_pay_txs 
       WHERE user_id = $1 
       ORDER BY fecha DESC, id DESC 
       LIMIT 50
      `, [userId]);
    res.json(rows);
  } catch (e) {
    // Si la tabla no existe (por alguna razón el CREATE falló)
    if (e.code === '42P01') return res.json([]);
    // Si la columna fecha no existe
    if (e.code === '42703') {
      try {
        const { rows } = await pool.query(`
    SELECT * FROM ocean_pay_txs 
           WHERE user_id = $1 
           ORDER BY id DESC 
           LIMIT 50
      `, [userId]);
        return res.json(rows);
      } catch (e2) {
        console.error('Error historial (fallback):', e2);
        return res.json([]);
      }
    }
    console.error('Error historial:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Endpoint de compatibilidad para Ocean Pay (sin token, solo display)
app.get('/ocean-pay/ecoxionums/:userId', async (req, res) => {
  const userId = parseInt(req.params.userId);
  if (isNaN(userId)) return res.status(400).json({ error: 'userId inválido' });

  try {
    const { rows } = await pool.query(`
      SELECT value FROM ocean_pay_metadata
      WHERE user_id = $1 AND key = 'ecoxionums'
      `, [userId]);

    const ecoxionums = rows.length > 0 ? parseInt(rows[0].value || '0') : 0;
    res.json({ ecoxionums });
  } catch (e) {
    if (e.code === '42P01') res.json({ ecoxionums: 0 });
    else res.status(500).json({ error: 'Error interno' });
  }
});



// Endpoint para sincronizar pólvora cósmica
app.post('/savage-space-animals/dust/sync', async (req, res) => {
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

  const { cosmicDust, highScore, unlockedAnimals } = req.body;

  try {
    // Guardar pólvora cósmica
    if (cosmicDust !== undefined) {
      await pool.query(`
        INSERT INTO ocean_pay_metadata(user_id, key, value)
    VALUES($1, 'ssa_cosmic_dust', $2)
        ON CONFLICT(user_id, key) 
        DO UPDATE SET value = $2
      `, [userId, cosmicDust.toString()]);
    }

    // Guardar high score
    if (highScore !== undefined) {
      await pool.query(`
        INSERT INTO ocean_pay_metadata(user_id, key, value)
    VALUES($1, 'ssa_high_score', $2)
        ON CONFLICT(user_id, key) 
        DO UPDATE SET value = $2
      `, [userId, highScore.toString()]);
    }

    // Guardar animales desbloqueados
    if (unlockedAnimals !== undefined) {
      await pool.query(`
        INSERT INTO ocean_pay_metadata(user_id, key, value)
    VALUES($1, 'ssa_unlocked_animals', $2)
        ON CONFLICT(user_id, key) 
        DO UPDATE SET value = $2
      `, [userId, JSON.stringify(unlockedAnimals)]);
    }

    res.json({ success: true });
  } catch (e) {
    console.error('Error sincronizando datos SSA:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Endpoint para obtener datos del jugador
app.get('/savage-space-animals/player-data', async (req, res) => {
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
      SELECT key, value FROM ocean_pay_metadata
      WHERE user_id = $1 AND key LIKE 'ssa_%'
      `, [userId]);

    const data = {};
    rows.forEach(row => {
      if (row.key === 'ssa_cosmic_dust') data.cosmicDust = parseInt(row.value) || 0;
      if (row.key === 'ssa_high_score') data.highScore = parseInt(row.value) || 0;
      if (row.key === 'ssa_unlocked_animals') {
        try {
          data.unlockedAnimals = JSON.parse(row.value);
        } catch {
          data.unlockedAnimals = ['betta'];
        }
      }
    });

    // Valores por defecto
    if (!data.cosmicDust) data.cosmicDust = 0;
    if (!data.highScore) data.highScore = 0;
    if (!data.unlockedAnimals) data.unlockedAnimals = ['betta'];

    res.json(data);
  } catch (e) {
    console.error('Error obteniendo datos SSA:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Endpoint para verificar suscripción desde Ocean Pay
app.get('/savage-space-animals/verify-subscription', async (req, res) => {
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
    // Verificar plan activo
    const { rows: planRows } = await pool.query(`
      SELECT value FROM ocean_pay_metadata
      WHERE user_id = $1 AND key = 'studio_plan'
      `, [userId]);

    // Verificar fecha de expiración
    const { rows: expiryRows } = await pool.query(`
      SELECT value FROM ocean_pay_metadata
      WHERE user_id = $1 AND key = 'studio_plan_expiry'
      `, [userId]);

    const plan = planRows.length > 0 ? planRows[0].value : 'free';
    const expiry = expiryRows.length > 0 ? new Date(expiryRows[0].value) : null;
    const isActive = plan !== 'free' && (!expiry || expiry > new Date());

    res.json({
      plan,
      expiry: expiry?.toISOString() || null,
      isActive,
      message: isActive
        ? `Tu suscripción ${plan.charAt(0).toUpperCase() + plan.slice(1)} está activa`
        : 'No tienes una suscripción activa'
    });
  } catch (e) {
    console.error('Error verificando suscripción SSA:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

/* ===== HUB SUBSCRIPTIONS (TIDES REMOVED) ===== */
// Tides currency and related subscription logic have been removed.

/* ===== POS VIRTUAL (TRANSFER BY CODE) ===== */

// Generar código aleatorio de 6 caracteres
function generatePosCode() {
  return Math.random().toString(36).substring(2, 8).toUpperCase();
}

// Crear una transacción POS (Sender)
app.post('/pos/create', async (req, res) => {
  const { userId, cardId, amount, currency } = req.body;

  if (!userId || !cardId || !amount || !currency) {
    return res.status(400).json({ error: 'Faltan datos requeridos (userId, cardId, amount, currency)' });
  }

  try {
    const code = generatePosCode();
    const { rows } = await pool.query(
      'INSERT INTO ocean_pay_pos (code, sender_id, sender_card_id, amount, currency, status) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [code, userId, cardId, amount, currency, 'pending']
    );
    res.json({ success: true, pos: rows[0] });
  } catch (e) {
    console.error('Error creando POS:', e);
    res.status(500).json({ error: 'Error al crear POS' });
  }
});

// Obtener info de POS por código
app.get('/pos/:code', async (req, res) => {
  const { code } = req.params;
  try {
    const { rows } = await pool.query(
      `SELECT p.*, u.username as sender_name 
       FROM ocean_pay_pos p 
       JOIN ocean_pay_users u ON p.sender_id = u.id 
       WHERE p.code = $1 AND p.status = 'pending'`,
      [code.toUpperCase()]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Código inválido o ya procesado' });
    }

    res.json({ success: true, pos: rows[0] });
  } catch (e) {
    console.error('Error buscando POS:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Completar transacción POS (Receiver)
app.post('/pos/complete', async (req, res) => {
  const { code, receiverId, receiverCardId } = req.body;

  if (!code || !receiverId || !receiverCardId) {
    return res.status(400).json({ error: 'Faltan datos' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1. Bloquear y obtener transacción POS
    const { rows: posRows } = await client.query(
      'SELECT * FROM ocean_pay_pos WHERE code = $1 AND status = $2 FOR UPDATE',
      [code.toUpperCase(), 'pending']
    );

    if (posRows.length === 0) {
      throw new Error('Transacción no válida o ya completada');
    }

    const pos = posRows[0];

    if (pos.sender_id === receiverId) {
      throw new Error('No puedes recibir dinero de ti mismo mediante POS');
    }

    // 2. Verificar saldo del Sender en la tarjeta especificada
    const { rows: senderBalance } = await client.query(
      'SELECT amount FROM ocean_pay_card_balances WHERE card_id = $1 AND currency_type = $2 FOR UPDATE',
      [pos.sender_card_id, pos.currency]
    );

    if (senderBalance.length === 0 || parseFloat(senderBalance[0].amount) < parseFloat(pos.amount)) {
      throw new Error('El emisor no tiene saldo suficiente en la tarjeta seleccionada');
    }

    // 3. Descontar al Sender
    await client.query(
      'UPDATE ocean_pay_card_balances SET amount = amount - $1 WHERE card_id = $2 AND currency_type = $3',
      [pos.amount, pos.sender_card_id, pos.currency]
    );

    // 4. Aumentar al Receiver (asegurar que tenga el registro de esa divisa)
    await client.query(
      'INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount) VALUES ($1, $2, $3) ON CONFLICT (card_id, currency_type) DO UPDATE SET amount = ocean_pay_card_balances.amount + $3',
      [receiverCardId, pos.currency, pos.amount]
    );

    // 5. Marcar POS como completado
    await client.query(
      'UPDATE ocean_pay_pos SET receiver_id = $1, receiver_card_id = $2, status = $3, completed_at = NOW() WHERE id = $4',
      [receiverId, receiverCardId, 'completed', pos.id]
    );

    // 6. Registrar transacciones formales
    const safeAmount = parseFloat(pos.amount);

    // Sender Transaction (Negative)
    await client.query(
      'INSERT INTO ocean_pay_txs (user_id, concepto, monto, moneda, origen) VALUES ($1, $2, $3, $4, $5)',
      [pos.sender_id, `POS Virtual - Envío (${code})`, -safeAmount, pos.currency.toUpperCase(), 'POS']
    );

    // Receiver Transaction (Positive)
    await client.query(
      'INSERT INTO ocean_pay_txs (user_id, concepto, monto, moneda, origen) VALUES ($1, $2, $3, $4, $5)',
      [receiverId, `POS Virtual - Recepción (${code})`, safeAmount, pos.currency.toUpperCase(), 'POS']
    );

    await client.query('COMMIT');
    res.json({ success: true, message: 'Pago procesado exitosamente' });

  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Error completando POS:', e.message);
    res.status(400).json({ error: e.message });
  } finally {
    client.release();
  }
});

// Endpoint para obtener beneficios de suscripción en SSA

app.get('/savage-space-animals/benefits', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.json({ plan: 'free', benefits: null });
  }

  const token = authHeader.substring(7);
  let userId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    userId = decoded.uid;
    userId = parseInt(userId) || userId;
  } catch (e) {
    return res.json({ plan: 'free', benefits: null });
  }

  try {
    // Buscar suscripción activa del Hub (si la tabla existe)
    let rows = [];
    try {
      const result = await pool.query(`
        SELECT plan_id, ends_at FROM hub_subs
        WHERE user_id = $1 AND active = true
        AND ends_at > NOW()
        ORDER BY created_at DESC
        LIMIT 1
      `, [userId]);
      rows = result.rows;
    } catch (dbError) {
      // Ignore table not found error
      rows = [];
    }

    if (rows.length === 0) {
      return res.json({ plan: 'free', benefits: null });
    }

    const subscription = rows[0];
    const plan = subscription.plan_id; // 'savage' or 'oceanic'

    // Define benefits based on plan
    const benefits = {
      savage: {
        extraLives: 1,
        bossCooldownReduction: 10,
        cosmicDustBonus: 5,
        extendedInvincibility: false,
        earlyAnimalUnlock: false
      },
      oceanic: {
        extraLives: 2,
        bossCooldownReduction: 25,
        cosmicDustBonus: 15,
        extendedInvincibility: true,
        earlyAnimalUnlock: true
      }
    };

    res.json({
      plan: plan,
      benefits: benefits[plan] || null,
      expiresAt: subscription.ends_at
    });
  } catch (e) {
    console.error('Error obteniendo beneficios SSA:', e);
    res.json({ plan: 'free', benefits: null });
  }
});

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
    AND(ends_at IS NULL OR ends_at > NOW())
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
    return res.status(400).json({ error: `Saldo insuficiente.Necesitas ${price} WildGems.` });
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
      return res.status(400).json({ error: `Saldo insuficiente.Necesitas ${price} WildGems.` });
    }

    // Descontar WildGems
    const newBalance = currentGemsLocked - price;
    await client.query(`
      INSERT INTO ocean_pay_metadata(user_id, key, value)
    VALUES($1, 'wildgems', $2)
      ON CONFLICT(user_id, key) 
      DO UPDATE SET value = $2
      `, [userId, newBalance.toString()]);

    // Registrar transacción según la estructura de la tabla (ya sabemos si tiene moneda)
    if (hasMonedaColumn) {
      await client.query(`
        INSERT INTO ocean_pay_txs(user_id, concepto, monto, origen, moneda)
    VALUES($1, $2, $3, $4, 'WG')
      `, [userId, `Episodio ${episodeId} (WildShorts)`, -price, 'WildShorts']);
    } else {
      await client.query(`
        INSERT INTO ocean_pay_txs(user_id, concepto, monto, origen)
    VALUES($1, $2, $3, $4)
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
      SELECT opu.id, opu.pwd_hash, opu.aquabux, opu.appbux,
      COALESCE(uc.amount, 0) as ecorebits
      FROM ocean_pay_users opu
      LEFT JOIN user_currency uc ON opu.id = uc.user_id AND uc.currency_type = 'ecocorebits'
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
        CREATE TABLE IF NOT EXISTS ocean_pay_metadata(
        user_id INTEGER NOT NULL,
        key TEXT NOT NULL,
        value TEXT NOT NULL,
        PRIMARY KEY(user_id, key)
      )
      `);

      // Obtener valores existentes del servidor
      const { rows: existingRows } = await pool.query(`
        SELECT key, value FROM ocean_pay_metadata
        WHERE user_id = $1 AND key IN('wildcredits', 'wildgems')
      `, [rows[0].id]);

      let existingWildCredits = 0;
      let existingWildGems = 0;
      existingRows.forEach(row => {
        if (row.key === 'wildcredits') existingWildCredits = parseInt(row.value || '0');
        if (row.key === 'wildgems') existingWildGems = parseInt(row.value || '0');
      });

      // Usar el valor máximo entre el existente y el nuevo
      const finalWildCredits = Math.max(existingWildCredits, wildCreditsValue);
      const finalWildGems = Math.max(existingWildGems, wildGemsValue);

      console.log(`[Ocean Pay Link]WildCredits: existente = ${existingWildCredits}, nuevo = ${wildCreditsValue}, final = ${finalWildCredits} `);
      console.log(`[Ocean Pay Link]WildGems: existente = ${existingWildGems}, nuevo = ${wildGemsValue}, final = ${finalWildGems} `);

      // Guardar siempre (incluso si es 0) para mantener consistencia
      await pool.query(`
        INSERT INTO ocean_pay_metadata(user_id, key, value)
    VALUES($1, 'wildcredits', $2)
        ON CONFLICT(user_id, key) 
        DO UPDATE SET value = GREATEST(CAST(ocean_pay_metadata.value AS INTEGER), CAST($2 AS INTEGER)):: TEXT
      `, [rows[0].id, finalWildCredits.toString()]);

      await pool.query(`
        INSERT INTO ocean_pay_metadata(user_id, key, value)
    VALUES($1, 'wildgems', $2)
        ON CONFLICT(user_id, key) 
        DO UPDATE SET value = GREATEST(CAST(ocean_pay_metadata.value AS INTEGER), CAST($2 AS INTEGER)):: TEXT
      `, [rows[0].id, finalWildGems.toString()]);

    } catch (e) {
      console.warn('No se pudo guardar wildCredits/wildGems en servidor (continuando):', e.message);
    }

    // Obtener todos los valores actualizados del servidor (incluyendo wildcredits)
    let serverWildCredits = wildCreditsValue;
    let serverWildGems = wildGemsValue;
    let serverEcoxionums = 0;
    try {
      const { rows: metaRows } = await pool.query(`
        SELECT key, value FROM ocean_pay_metadata
        WHERE user_id = $1 AND key IN('wildcredits', 'wildgems', 'ecoxionums')
      `, [rows[0].id]);

      metaRows.forEach(row => {
        if (row.key === 'wildcredits') {
          serverWildCredits = parseInt(row.value || '0');
        } else if (row.key === 'wildgems') {
          serverWildGems = parseInt(row.value || '0');
        } else if (row.key === 'ecoxionums') {
          serverEcoxionums = parseFloat(row.value || '0');
        }
      });

      console.log(`[Ocean Pay Link] Valores finales del servidor: WildCredits = ${serverWildCredits}, WildGems = ${serverWildGems} `);
    } catch (e) {
      console.warn('[Ocean Pay Link] Error obteniendo valores del servidor:', e.message);
      serverWildCredits = wildCreditsValue;
      serverWildGems = wildGemsValue;
    }

    res.json({
      success: true,
      token,
      user: {
        id: rows[0].id,
        username,
        aquabux: rows[0].aquabux || 0,
        ecoxionums: serverEcoxionums,
        ecorebits: Number(rows[0].ecorebits) || 0,
        wildcredits: serverWildCredits,
        wildgems: serverWildGems,
        appbux: rows[0].appbux || 0
      },
      balances: {
        aquabux: rows[0].aquabux || 0,
        ecoxionums: serverEcoxionums,
        ecorebits: Number(rows[0].ecorebits) || 0,
        wildcredits: serverWildCredits,
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

/* ===== DeepDive AI Proxy (Python service) ===== */
const AI_BASE_URL = process.env.AI_BASE_URL || 'https://owsdatabase.onrender.com';

// Sanitize update notes: remove any lines that disclose internal servers/URLs or infra details
function sanitizeNews(raw = '') {
  try {
    const forbidden = /(https?:\/\/[^\s]+)|(onrender\.|localhost|127\.0\.0\.1|internal|AI_BASE_URL|SERVER_BASE|API_BASE|backend_url)/i;
    return String(raw)
      .split(/\r?\n/)
      .filter(line => !forbidden.test(line))
      .join('\n')
      .trim();
  } catch {
    return raw;
  }
}

// Utilities to detect export capabilities at runtime
import { spawn } from 'child_process';
async function hasFfmpeg() {
  return await new Promise(resolve => {
    try {
      const p = spawn(process.platform === 'win32' ? 'ffmpeg.exe' : 'ffmpeg', ['-version']);
      let resolved = false;
      p.on('exit', code => { if (!resolved) { resolved = true; resolve(code === 0); } });
      p.on('error', () => { if (!resolved) { resolved = true; resolve(false); } });
      setTimeout(() => { if (!resolved) { resolved = true; try { p.kill('SIGKILL'); } catch { } resolve(false); } }, 1500);
    } catch { resolve(false); }
  });
}
async function hasPuppeteer() {
  try { await import('puppeteer'); return true; } catch { return false; }
}

function fallbackSlidesFromScript(script = '', style = {}) {
  // Heuristic summarizer (no external APIs)
  const brand = style?.brand || {};
  const theme = style?.theme || 'minimal';
  const bg = brand.background || '#ffffff';
  const font = brand.font || 'Inter';
  const primary = brand.primary || '#0ea5e9';

  const raw = String(script || '').replace(/\s+/g, ' ').trim();
  if (!raw) {
    return {
      slides: [
        {
          aspectRatio: { width: 16, height: 9 },
          backgroundColor: bg,
          durationMs: 3000,
          texts: [
            { content: 'Introducing', x: 40, y: 200, fontSize: 42, fontFamily: font, color: primary, align: 'center', isCenteredX: true },
            { content: 'DeepDive Presentations', x: 40, y: 250, fontSize: 28, fontFamily: font, color: '#1e293b', align: 'center', isCenteredX: true }
          ],
          videos: [], audios: []
        }
      ]
    };
  }

  // 1) Sentence split
  const sentences = raw
    .split(/(?<=[.!?])\s+(?=[A-ZÁÉÍÓÚÑ])/)
    .map(s => s.trim())
    .filter(s => s.length >= 20);

  // 2) Tokenization & stopwords
  const STOP = new Set([
    'a', 'al', 'algo', 'algun', 'algunas', 'algunos', 'ante', 'antes', 'como', 'con', 'contra', 'cuando', 'de', 'del', 'desde', 'donde', 'el', 'ella', 'ellas', 'ellos', 'en', 'entonces', 'entre', 'era', 'eramos', 'eran', 'eras', 'eres', 'es', 'esa', 'esas', 'ese', 'eso', 'esos', 'esta', 'estaba', 'estabais', 'estaban', 'estabas', 'estais', 'estamos', 'estan', 'estar', 'estas', 'este', 'esto', 'estos', 'estoy', 'fue', 'fueron', 'fui', 'fuimos', 'ha', 'haber', 'han', 'has', 'hasta', 'hay', 'la', 'las', 'le', 'les', 'lo', 'los', 'mas', 'me', 'mi', 'mia', 'mias', 'mientras', 'mio', 'mios', 'mis', 'muy', 'nos', 'nosotras', 'nosotros', 'nuestra', 'nuestras', 'nuestro', 'nuestros', 'nunca', 'otra', 'otras', 'otro', 'otros', 'para', 'pero', 'poco', 'pocos', 'por', 'porque', 'primero', 'puede', 'pueden', 'puedo', 'que', 'quien', 'quienes', 'quizas', 'sea', 'seamos', 'sean', 'seas', 'ser', 'si', 'sido', 'siempre', 'siendo', 'sois', 'somos', 'son', 'soy', 'su', 'sus', 'tambien', 'tampoco', 'teneis', 'tenemos', 'tener', 'ti', 'tiempo', 'tiene', 'tienen', 'todo', 'todos', 'tras', 'tu', 'tus', 'un', 'una', 'uno', 'unos', 'usted', 'ustedes', 'y', 'ya',
    'the', 'of', 'and', 'to', 'in', 'for', 'on', 'with', 'as', 'at', 'by', 'from', 'or', 'an', 'is', 'are', 'be', 'this', 'that', 'these', 'those', 'it', 'its'
  ]);
  const WORD_RE = /[A-Za-zÁÉÍÓÚÜÑáéíóúüñ0-9]{2,}/g;

  function normalizeWord(w) { try { return w.normalize('NFD').replace(/[\u0300-\u036f]/g, ''); } catch { return w; } }
  function tokenize(s) {
    return (s.match(WORD_RE) || []).map(w => normalizeWord(w.toLowerCase()));
  }

  // 3) Word frequency (TF) with basic dampening
  const tf = new Map();
  sentences.forEach(s => {
    const seen = new Set();
    tokenize(s).forEach(w => {
      if (STOP.has(w)) return;
      // damp repeated terms per sentence
      if (seen.has(w)) return;
      seen.add(w);
      tf.set(w, (tf.get(w) || 0) + 1);
    });
  });

  // 4) Bigrams to propose a title
  const bigrams = new Map();
  sentences.forEach(s => {
    const toks = tokenize(s).filter(w => !STOP.has(w));
    for (let i = 0; i < toks.length - 1; i++) {
      const bg = `${toks[i]} ${toks[i + 1]} `;
      bigrams.set(bg, (bigrams.get(bg) || 0) + 1);
    }
  });
  const topBigram = Array.from(bigrams.entries()).sort((a, b) => b[1] - a[1])[0]?.[0] || '';

  // 5) Score sentences: sum(tf)/len + positional bonus; bigram bonus
  const scored = sentences.map((s, idx) => {
    const toks = tokenize(s).filter(w => !STOP.has(w));
    const len = Math.max(5, toks.length);
    let score = toks.reduce((acc, w) => acc + (tf.get(w) || 0), 0) / len;
    if (topBigram && s.toLowerCase().includes(topBigram)) score *= 1.2;
    // Positional bonus for first 20% of the document
    const pos = idx / Math.max(1, sentences.length - 1);
    if (pos < 0.2) score *= 1.1;
    return { s, idx, score };
  });
  scored.sort((a, b) => b.score - a.score);

  // 6) Pick bullets spread across the text (respect requested maxSlides)
  const requested = Math.max(3, Math.min(10, Number(style?.options?.maxSlides) || 6));
  const bulletTarget = Math.max(2, requested - 2); // 1 title + bullets + 1 CTA
  const pickCount = Math.min(bulletTarget, Math.max(3, Math.ceil(sentences.length / 4)));
  const taken = [];
  const usedIdx = new Set();
  for (const cand of scored) {
    // avoid sentences that are too close to already selected ones
    if (Array.from(usedIdx).some(i => Math.abs(i - cand.idx) <= 1)) continue;
    taken.push(cand);
    usedIdx.add(cand.idx);
    if (taken.length >= pickCount) break;
  }
  taken.sort((a, b) => a.idx - b.idx);

  // 7) Clean bullet text: shorten; remove trailing punctuation; sentence-case
  function clip(s, n) { return s.length > n ? s.slice(0, n - 1).replace(/[,;:.!\s]+$/, '') + '…' : s; }
  function toSentenceCase(s) { return s ? s.charAt(0).toUpperCase() + s.slice(1) : s; }

  const GENERIC_PREFIX = [/^\s*(en\s+esta\s+presentaci[oó]n|esta\s+presentaci[oó]n|en\s+este\s+video|este\s+video|vamos\s+a|vamos\b|hoy\b|we\s+will|in\s+this\s+presentation)[:,\s]*/i];
  const bullets = taken.map(t => {
    let out = t.s.replace(/\s+/g, ' ').trim();
    out = out.replace(/\([^)]*\)/g, ''); // remove parentheticals
    // remove generic prefaces
    GENERIC_PREFIX.forEach(rx => { out = out.replace(rx, ''); });
    out = clip(out, 110);
    return toSentenceCase(out);
  });

  // 8) Title generation: keyword phrases (RAKE-like) with sanity filters
  const GENERIC_TITLE_BAD = new Set(['presentation', 'introducing', 'introduction', 'intro', 'overview', 'about', 'topic', 'themes']);
  // build phrases by splitting on stopwords
  const tokensAll = tokenize(raw);
  const phrases = [];
  let cur = [];
  tokensAll.forEach(tok => {
    if (STOP.has(tok)) {
      if (cur.length) { phrases.push(cur.slice()); cur = []; }
    } else {
      cur.push(tok);
    }
  });
  if (cur.length) phrases.push(cur);
  // score phrases
  const phraseScores = phrases
    .filter(p => p.length >= 1 && p.length <= 6)
    .map(p => {
      const score = p.reduce((a, w) => a + (tf.get(w) || 0), 0) * (1 + (p.length - 1) * 0.15);
      return { text: p.map(w => w).join(' '), score };
    });
  phraseScores.sort((a, b) => b.score - a.score);
  function goodPhrase(s) {
    if (!s || s.length < 3) return false;
    const parts = s.split(/\s+/);
    if (parts.every(w => GENERIC_TITLE_BAD.has(w))) return false;
    return /[a-z]/i.test(s);
  }
  let topPhrase = phraseScores.find(p => goodPhrase(p.text))?.text || '';
  // fallback to bigram-derived title if needed
  let title = '';
  if (topPhrase) {
    const scriptHasIntro = /\b(introduc|present[a-z]+)/i.test(raw);
    const nice = topPhrase.replace(/\b\w/g, m => m.toUpperCase());
    title = scriptHasIntro ? `Introducing ${nice} ` : nice;
  } else {
    const head = (scored[0]?.s.split(/[\-:–—]/)[0] || '').trim();
    title = head ? clip(toSentenceCase(head), 60) : 'Introducing';
  }

  const slides = [];
  // Title slide
  slides.push({
    aspectRatio: { width: 16, height: 9 },
    backgroundColor: bg,
    durationMs: 3000,
    texts: [
      { content: title, x: 40, y: theme === 'bold' ? 160 : 200, fontSize: theme === 'bold' ? 56 : 42, fontFamily: font, color: primary, align: 'center', isCenteredX: true }
    ],
    videos: [], audios: []
  });

  // Bullet slides
  bullets.forEach(b => {
    slides.push({
      aspectRatio: { width: 16, height: 9 },
      backgroundColor: bg,
      durationMs: 3000,
      texts: [
        { content: b, x: 40, y: 180, fontSize: 28, fontFamily: font, color: '#1e293b', align: 'center', isCenteredX: true }
      ],
      videos: [], audios: []
    });
  });

  // CTA slide
  slides.push({
    aspectRatio: { width: 16, height: 9 },
    backgroundColor: bg,
    durationMs: 3000,
    texts: [
      { content: 'Get Started', x: 40, y: 200, fontSize: 36, fontFamily: font, color: primary, align: 'center', isCenteredX: true }
    ],
    videos: [], audios: []
  });

  return { slides };
}

// Script -> Slides
app.post('/deepdive/ai/script-to-slides', async (req, res) => {
  try {
    const f = globalThis.fetch || (await import('node-fetch')).default;
    const r = await f(`${AI_BASE_URL} /ai/script_to_slides`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body || {})
    });
    if (!r.ok) {
      // Fallback if remote not available
      const fb = fallbackSlidesFromScript(req.body?.script, req.body?.style);
      return res.json(fb);
    }
    const data = await r.json();
    res.json(data);
  } catch (e) {
    console.error('[AI] script-to-slides proxy failed:', e);
    const fb = fallbackSlidesFromScript(req.body?.script, req.body?.style);
    res.json(fb);
  }
});

// Text-to-Speech (streams audio back)
app.post('/deepdive/ai/tts', async (req, res) => {
  try {
    const f = globalThis.fetch || (await import('node-fetch')).default;
    const r = await f(`${AI_BASE_URL} /ai/tts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body || {})
    });
    if (!r.ok) return res.status(r.status).end();
    res.set('Content-Type', r.headers.get('content-type') || 'audio/mpeg');
    res.set('Cache-Control', 'no-store');
    r.body.pipe(res);
  } catch (e) {
    console.error('[AI] TTS proxy failed:', e);
    res.status(501).json({ error: 'TTS not configured. Set AI_BASE_URL to your Python service.' });
  }
});

// Speech-to-Text (forwards multipart body as-is)
app.post('/deepdive/ai/stt', async (req, res) => {
  try {
    const f = globalThis.fetch || (await import('node-fetch')).default;
    const r = await f(`${AI_BASE_URL} /ai/stt`, {
      method: 'POST',
      headers: { 'content-type': req.headers['content-type'] || 'multipart/form-data' },
      body: req
    });
    if (!r.ok) return res.status(r.status).end();
    res.set('Content-Type', r.headers.get('content-type') || 'application/json');
    r.body.pipe(res);
  } catch (e) {
    console.error('[AI] STT proxy failed:', e);
    res.status(501).json({ error: 'STT not configured. Set AI_BASE_URL to your Python service.' });
  }
});

/* ===== DeepDive Media Proxy with CORS and Range ===== */
function isSafeRemote(urlStr) {
  try {
    const u = new URL(urlStr);
    if (!(u.protocol === 'http:' || u.protocol === 'https:')) return false;
    const host = u.hostname.toLowerCase();
    if (host === 'localhost' || host === '127.0.0.1') return false;
    if (host.endsWith('.internal') || host.endsWith('.local')) return false;
    return true;
  } catch { return false; }
}

app.get('/deepdive/proxy/media', async (req, res) => {
  const target = req.query.url;
  if (!target || !isSafeRemote(target)) return res.status(400).send('Invalid URL');
  try {
    const f = globalThis.fetch || (await import('node-fetch')).default;
    const headers = {};
    const range = req.headers['range'];
    if (range) headers['range'] = range;
    const r = await f(target, { method: 'GET', headers });
    // Pass-through status and important headers
    res.status(r.status);
    const passthrough = ['content-type', 'content-length', 'accept-ranges', 'content-range', 'last-modified', 'etag'];
    passthrough.forEach(h => { const v = r.headers.get(h); if (v) res.set(h, v); });
    // Always allow cross-origin for canvas usage
    res.set('Access-Control-Allow-Origin', '*');
    res.set('Cache-Control', 'public, max-age=86400');
    if (!r.body) return res.end();
    r.body.pipe(res);
  } catch (e) {
    console.error('[MediaProxy] error:', e);
    res.status(502).send('Bad gateway');
  }
});

/* ===== DeepDive Export (SSR) ===== */
app.get('/deepdive/export/capabilities', async (_req, res) => {
  const envEnabled = process.env.ENABLE_SSR === '1';
  const okFfmpeg = await hasFfmpeg();
  const okPuppeteer = await hasPuppeteer();
  res.json({ ssr: envEnabled && okFfmpeg && okPuppeteer, ffmpeg: okFfmpeg, puppeteer: okPuppeteer });
});

app.post('/deepdive/export/video', async (req, res) => {
  const envEnabled = process.env.ENABLE_SSR === '1';
  if (!envEnabled) {
    return res.status(501).json({ error: 'Server-side render disabled. Set ENABLE_SSR=1.' });
  }
  const okFfmpeg = await hasFfmpeg();
  const okPuppeteer = await hasPuppeteer();
  if (!okFfmpeg || !okPuppeteer) {
    return res.status(501).json({ error: 'Missing ffmpeg and/or puppeteer on server.' });
  }
  try {
    const { slides = [], fps = 30, scale = 1, pro = true } = req.body || {};
    if (!Array.isArray(slides) || slides.length === 0) {
      return res.status(400).json({ error: 'slides required' });
    }
    const puppeteer = (await import('puppeteer')).default;
    const browser = await puppeteer.launch({ args: ['--no-sandbox', '--disable-setuid-sandbox'] });
    const page = await browser.newPage();

    // Resolve local file URL for DeepDive editor
    const ddPath = path.join(process.cwd(), 'DeepDive Presentations', 'index.html');
    const fileUrl = 'file://' + ddPath.replace(/\\/g, '/');

    const BASE_WIDTH = 800;
    const aspect = slides[0]?.aspectRatio || { width: 16, height: 9 };
    const height = Math.round((BASE_WIDTH * aspect.height) / aspect.width);
    await page.setViewport({ width: BASE_WIDTH, height, deviceScaleFactor: Math.max(1, Math.min(2, scale || 1)) });

    await page.goto(fileUrl, { waitUntil: 'networkidle0' });

    // Ensure webfonts are ready before measuring text/effects
    try { await page.evaluate(() => (window.document.fonts && window.document.fonts.ready) ? window.document.fonts.ready : Promise.resolve()); } catch { }

    // Inject slides and prep render helpers in the page context
    await page.evaluate(({ slides, pro }) => {
      try {
        window.deepdiveIsPro = !!pro;
        window.previewTimes = {};
        window.slides = slides;
        window.currentSlideIndex = 0;
        if (typeof window.updateTimelineUI === 'function') window.updateTimelineUI();
        if (typeof window.renderSlides === 'function') window.renderSlides();
      } catch (e) { console.error('[EXPORT] inject failed', e); }
    }, { slides, pro });

    // Frame capture directory
    const outDir = path.join(process.cwd(), 'exports');
    const framesDir = path.join(outDir, `frames_${Date.now()} `);
    fs.mkdirSync(framesDir, { recursive: true });

    // Compute total ms
    const totalMs = slides.reduce((acc, s) => acc + (s.durationMs || 3000), 0);
    const dt = Math.max(1, Math.round(1000 / Math.max(1, Math.min(60, fps))));

    // Iterate timeline and capture frames
    let slideStartMs = 0; let slideIdx = 0; let lastRenderedSlide = -1;
    for (let t = 0, f = 0; t <= totalMs; t += dt, f++) {
      // Determine current slide and local time
      while (slideIdx < slides.length && t >= slideStartMs + (slides[slideIdx].durationMs || 3000)) {
        slideStartMs += (slides[slideIdx].durationMs || 3000);
        slideIdx++;
        await page.evaluate(() => { try { window.__ddItemPrevVisible = {}; } catch { } });
      }
      const curIdx = Math.min(slideIdx, slides.length - 1);
      const localMs = Math.max(0, t - slideStartMs);

      // Update time and render minimally: full render only on slide change; then per-frame only visuals
      await page.evaluate(({ curIdx, localMs, forceRender }) => {
        try {
          const s = window.slides[curIdx];
          window.currentSlideIndex = curIdx;
          window.previewTimes = window.previewTimes || {};
          window.previewTimes[s.id] = localMs;
          if (forceRender && typeof window.renderSlides === 'function') window.renderSlides();
          if (typeof window.updateTimelineVisuals === 'function') window.updateTimelineVisuals();
        } catch (e) { console.error('[EXPORT] step failed', e); }
      }, { curIdx, localMs, forceRender: (curIdx !== lastRenderedSlide) });

      // If slide changed, mark rendered and warm up layout (allow nested RAFs for measurements)
      if (curIdx !== lastRenderedSlide) {
        lastRenderedSlide = curIdx;
        await page.evaluate(() => new Promise(r => requestAnimationFrame(() => requestAnimationFrame(() => r()))));
        await page.waitForTimeout(80);
      }

      // Flush a frame so styles apply before capture
      await page.evaluate(() => new Promise(r => requestAnimationFrame(() => r())));

      const framePath = path.join(framesDir, `frame_${String(f).padStart(6, '0')}.png`);
      await page.screenshot({ path: framePath, omitBackground: false });

      // Allow CSS animations to progress in real time between captures
      await page.waitForTimeout(dt);
    }

    await browser.close();

    // Assemble video with ffmpeg
    fs.mkdirSync(outDir, { recursive: true });
    const outFile = path.join(outDir, `deepdive_${Date.now()}.mp4`);
    const ff = spawn(process.platform === 'win32' ? 'ffmpeg.exe' : 'ffmpeg', [
      '-y',
      '-framerate', String(fps),
      '-i', path.join(framesDir, 'frame_%06d.png'),
      '-c:v', 'libx264',
      '-pix_fmt', 'yuv420p',
      '-movflags', '+faststart',
      outFile
    ]);

    ff.stderr.on('data', d => { /* optional: log */ });
    ff.on('exit', code => {
      try {
        // cleanup frames
        fs.rmSync(framesDir, { recursive: true, force: true });
      } catch { }
      if (code !== 0) {
        return res.status(500).json({ error: 'ffmpeg failed' });
      }
      const publicUrl = `/ exports / ${path.basename(outFile)} `;
      return res.json({ url: publicUrl, filename: path.basename(outFile) });
    });
  } catch (e) {
    console.error('[SSR] export failed', e);
    return res.status(500).json({ error: 'SSR export failed' });
  }
});
app.use('/exports', express.static(path.join(process.cwd(), 'exports')));

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
      CREATE TABLE IF NOT EXISTS support_chats(
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
      CREATE TABLE IF NOT EXISTS support_messages(
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
      `SELECT id, username FROM users_nat WHERE username IN('OceanandWild', 'Jorge Barboza')`
    );
    let adminId = null, adminUsername = null;
    if (admins.length) {
      const idx = Math.floor(Math.random() * admins.length);
      adminId = admins[idx].id; adminUsername = admins[idx].username;
    }

    const { rows: created } = await pool.query(
      `INSERT INTO support_chats(user_id, admin_id, status) VALUES($1, $2, 'open') RETURNING * `,
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
      `INSERT INTO support_messages(chat_id, sender_id, sender_type, message) VALUES($1, $2, $3, $4)`,
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

/* ===== NatMarket: Recuperación alternativa de cuenta ===== */
// Tabla: recovery_requests_nat
async function ensureRecoveryTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS recovery_requests_nat(
        id BIGSERIAL PRIMARY KEY,
        username TEXT NOT NULL,
        approx_registration_date DATE,
        evidence JSONB NOT NULL,
        oe_username TEXT,
        oe_verified BOOLEAN DEFAULT FALSE,
        status TEXT NOT NULL DEFAULT 'pending',
        reviewer TEXT,
        resolution_note TEXT,
        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMP NOT NULL DEFAULT NOW()
      )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_rr_nat_status ON recovery_requests_nat(status)`);
}

// Verificación opcional contra OceanicEthernet
async function verifyOE(username, password) {
  if (!username || !password) return false;
  try {
    const { rows } = await pool.query(
      `SELECT id, pwd_hash FROM ocean_pay_users WHERE username = $1`,
      [username]
    );
    if (!rows.length) return false;
    const ok = await bcrypt.compare(password, rows[0].pwd_hash);
    return !!ok;
  } catch {
    return false;
  }
}

function scoreAltEvidence(e) {
  let c = 0;
  if (e?.phone) c++;
  if (e?.place) c++;
  if (e?.product1?.name || e?.product1?.price != null) c++;
  if (e?.product2?.name || e?.product2?.price != null) c++;
  if (e?.approx_registration_date) c++;
  return c;
}

// Crear solicitud
app.post('/natmarket/recovery-request', async (req, res) => {
  try {
    await ensureRecoveryTable();
    const { username, approx_registration_date, evidence = {}, oceanic_ethernet = {} } = req.body || {};
    if (!username || typeof username !== 'string') {
      return res.status(400).json({ error: 'username es obligatorio' });
    }
    const evidCount = scoreAltEvidence({
      phone: evidence.phone,
      place: evidence.place,
      product1: evidence.product1,
      product2: evidence.product2,
      approx_registration_date,
    });
    if (evidCount < 2) {
      return res.status(400).json({ error: 'Se requieren al menos 2 evidencias' });
    }

    let oeVerified = false;
    if (oceanic_ethernet?.username && oceanic_ethernet?.password) {
      oeVerified = await verifyOE(oceanic_ethernet.username, oceanic_ethernet.password);
    }

    const { rows } = await pool.query(
      `INSERT INTO recovery_requests_nat(username, approx_registration_date, evidence, oe_username, oe_verified, status)
    VALUES($1, $2, $3, $4, $5, 'pending') RETURNING id`,
      [
        username.trim(),
        approx_registration_date || null,
        JSON.stringify({
          phone: evidence.phone || null,
          place: evidence.place || null,
          product1: evidence.product1 || null,
          product2: evidence.product2 || null,
        }),
        oceanic_ethernet?.username || null,
        oeVerified,
      ]
    );
    res.json({ success: true, id: rows[0].id, oe_verified: oeVerified });
  } catch (err) {
    console.error('POST /natmarket/recovery-request error', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Listar solicitudes (admin, por estado opcional)
app.get('/natmarket/recovery-requests', async (req, res) => {
  try {
    const adminUsername = req.headers['x-user-username'] || '';
    if (!(await isAdminUsername(adminUsername))) return res.status(403).json({ error: 'No autorizado' });
    await ensureRecoveryTable();
    const status = (req.query.status || '').toString();
    const where = status ? 'WHERE status = $1' : '';
    const params = status ? [status] : [];
    const { rows } = await pool.query(
      `SELECT * FROM recovery_requests_nat ${where} ORDER BY created_at DESC`,
      params
    );
    res.json(rows);
  } catch (err) {
    console.error('GET /natmarket/recovery-requests error', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Aprobar: genera nuevo user_unique_id para users_nat.username
app.post('/natmarket/recovery-requests/:id/approve', async (req, res) => {
  const { id } = req.params;
  const { reviewer = 'admin', resolution_note = 'aprobado' } = req.body || {};
  try {
    const adminUsername = req.headers['x-user-username'] || '';
    if (!(await isAdminUsername(adminUsername))) return res.status(403).json({ error: 'No autorizado' });
    await ensureRecoveryTable();

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const { rows: rrRows } = await client.query('SELECT * FROM recovery_requests_nat WHERE id=$1 FOR UPDATE', [id]);
      if (!rrRows.length) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Solicitud no encontrada' }); }
      const rr = rrRows[0];

      const { rows: userRows } = await client.query('SELECT id FROM users_nat WHERE username=$1', [rr.username]);
      if (!userRows.length) {
        await client.query(
          'UPDATE recovery_requests_nat SET status=$1, reviewer=$2, resolution_note=$3, updated_at=NOW() WHERE id=$4',
          ['rejected', reviewer, 'Usuario no existe', id]
        );
        await client.query('COMMIT');
        return res.status(404).json({ error: 'Usuario no existe' });
      }

      const userId = userRows[0].id;
      const newUniqueId = generateUserUniqueId();
      await client.query('UPDATE users_nat SET user_unique_id=$1 WHERE id=$2', [newUniqueId, userId]);
      await client.query(
        'UPDATE recovery_requests_nat SET status=$1, reviewer=$2, resolution_note=$3, updated_at=NOW() WHERE id=$4',
        ['approved', reviewer, resolution_note, id]
      );
      await client.query('COMMIT');
      res.json({ success: true, user_id: userId, new_user_unique_id: newUniqueId });
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch { }
      console.error('approve recovery error', e);
      res.status(500).json({ error: 'Error interno' });
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('POST /natmarket/recovery-requests/:id/approve error', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Rechazar solicitud
app.post('/natmarket/recovery-requests/:id/reject', async (req, res) => {
  const { id } = req.params;
  const { reviewer = 'admin', resolution_note = 'rechazado' } = req.body || {};
  try {
    const adminUsername = req.headers['x-user-username'] || '';
    if (!(await isAdminUsername(adminUsername))) return res.status(403).json({ error: 'No autorizado' });
    await ensureRecoveryTable();
    await pool.query(
      'UPDATE recovery_requests_nat SET status=$1, reviewer=$2, resolution_note=$3, updated_at=NOW() WHERE id=$4',
      ['rejected', reviewer, resolution_note, id]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('POST /natmarket/recovery-requests/:id/reject error', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// ===== NatMarket: Seguimientos de entrega/chat =====
async function ensureTrackingTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS nat_trackings(
      id BIGSERIAL PRIMARY KEY,
      product_id INTEGER NOT NULL REFERENCES products_nat(id) ON DELETE CASCADE,
      seller_id INTEGER NOT NULL REFERENCES users_nat(id) ON DELETE CASCADE,
      buyer_id INTEGER NOT NULL REFERENCES users_nat(id) ON DELETE CASCADE,
      title TEXT,
      status TEXT NOT NULL DEFAULT 'iniciado',
      events JSONB NOT NULL DEFAULT '[]',
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_nat_trackings_seller ON nat_trackings(seller_id)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_nat_trackings_buyer ON nat_trackings(buyer_id)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_nat_trackings_product ON nat_trackings(product_id)`);
}

function appendEventJSON(events, ev) {
  try {
    const arr = Array.isArray(events) ? events.slice() : JSON.parse(events || '[]');
    arr.push({ ...ev, created_at: new Date().toISOString() });
    return JSON.stringify(arr);
  } catch {
    return JSON.stringify([{ ...ev, created_at: new Date().toISOString() }]);
  }
}

// Crear seguimiento (vendedor)
app.post('/natmarket/trackings', async (req, res) => {
  try {
    const { seller_id, product_id, buyer_id, title = 'Seguimiento', first_event = {} } = req.body || {};
    if (!seller_id || !product_id || !buyer_id) return res.status(400).json({ error: 'seller_id, product_id y buyer_id requeridos' });
    await ensureTrackingTables();

    // Validar que el producto pertenece al vendedor
    const { rows: prodRows } = await pool.query('SELECT user_id, name FROM products_nat WHERE id=$1', [product_id]);
    if (!prodRows.length) return res.status(404).json({ error: 'Producto no encontrado' });
    if (Number(prodRows[0].user_id) !== Number(seller_id)) return res.status(403).json({ error: 'No autorizado para este producto' });

    const ev = {
      status: first_event.status || 'iniciado',
      note: first_event.note || 'Seguimiento iniciado',
      location: first_event.location || null,
      eta: first_event.eta || null
    };

    const { rows } = await pool.query(
      `INSERT INTO nat_trackings(product_id, seller_id, buyer_id, title, status, events)
    VALUES($1, $2, $3, $4, $5, $6) RETURNING * `,
      [product_id, seller_id, buyer_id, title, ev.status, JSON.stringify([{ ...ev, created_at: new Date().toISOString() }])]
    );

    res.json(rows[0]);
  } catch (err) {
    console.error('POST /natmarket/trackings', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Agregar evento (vendedor)
app.post('/natmarket/trackings/:id/events', async (req, res) => {
  try {
    const { id } = req.params;
    const { seller_id, status, note, location, eta } = req.body || {};
    if (!seller_id) return res.status(400).json({ error: 'seller_id requerido' });
    await ensureTrackingTables();

    const { rows } = await pool.query('SELECT * FROM nat_trackings WHERE id=$1', [id]);
    if (!rows.length) return res.status(404).json({ error: 'Seguimiento no encontrado' });
    const tr = rows[0];
    if (Number(tr.seller_id) !== Number(seller_id)) return res.status(403).json({ error: 'No autorizado' });

    const ev = { status: status || tr.status, note: note || '', location: location || null, eta: eta || null };
    const newEvents = appendEventJSON(tr.events, ev);
    const newStatus = status || tr.status;

    const { rows: upd } = await pool.query(
      `UPDATE nat_trackings SET events = $1:: jsonb, status = $2, updated_at = NOW() WHERE id = $3 RETURNING * `,
      [newEvents, newStatus, id]
    );
    res.json(upd[0]);
  } catch (err) {
    console.error('POST /natmarket/trackings/:id/events', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Editar/cerrar seguimiento (vendedor)
app.patch('/natmarket/trackings/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { seller_id, status, title, active } = req.body || {};
    if (!seller_id) return res.status(400).json({ error: 'seller_id requerido' });
    await ensureTrackingTables();

    const { rows } = await pool.query('SELECT * FROM nat_trackings WHERE id=$1', [id]);
    if (!rows.length) return res.status(404).json({ error: 'Seguimiento no encontrado' });
    const tr = rows[0];
    if (Number(tr.seller_id) !== Number(seller_id)) return res.status(403).json({ error: 'No autorizado' });

    const { rows: upd } = await pool.query(
      `UPDATE nat_trackings SET
    status = COALESCE($1, status),
      title = COALESCE($2, title),
      active = COALESCE($3, active),
      updated_at = NOW()
       WHERE id = $4 RETURNING * `,
      [status || null, title || null, (active === undefined ? null : !!active), id]
    );
    res.json(upd[0]);
  } catch (err) {
    console.error('PATCH /natmarket/trackings/:id', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Obtener seguimiento por participantes (para chat)
app.get('/natmarket/trackings/by-participants', async (req, res) => {
  try {
    const product_id = Number(req.query.product_id);
    const seller_id = Number(req.query.seller_id);
    const buyer_id = Number(req.query.buyer_id);
    if (!product_id || !seller_id || !buyer_id) return res.status(400).json({ error: 'params requeridos' });
    await ensureTrackingTables();

    const { rows } = await pool.query(
      `SELECT t.*, p.name as product_name, u1.username as seller_username, u2.username as buyer_username
       FROM nat_trackings t
       JOIN products_nat p ON p.id = t.product_id
       JOIN users_nat u1 ON u1.id = t.seller_id
       JOIN users_nat u2 ON u2.id = t.buyer_id
       WHERE t.product_id = $1 AND t.seller_id = $2 AND t.buyer_id = $3
       ORDER BY t.created_at DESC LIMIT 1`,
      [product_id, seller_id, buyer_id]
    );
    res.json(rows[0] || null);
  } catch (err) {
    console.error('GET /natmarket/trackings/by-participants', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Listado por vendedor
app.get('/natmarket/trackings/seller/:sellerId', async (req, res) => {
  try {
    const { sellerId } = req.params;
    const all = req.query.all === '1' || req.query.all === 'true';
    await ensureTrackingTables();
    const { rows } = await pool.query(
      `SELECT t.*, p.name as product_name, p.image_urls, u2.username as buyer_username
       FROM nat_trackings t
       JOIN products_nat p ON p.id = t.product_id
       JOIN users_nat u2 ON u2.id = t.buyer_id
       WHERE t.seller_id = $1 AND($2:: boolean OR t.active = true)
       ORDER BY t.updated_at DESC`,
      [sellerId, all]
    );
    res.json(rows);
  } catch (err) {
    console.error('GET /natmarket/trackings/seller/:sellerId', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Listado por comprador
app.get('/natmarket/trackings/buyer/:buyerId', async (req, res) => {
  try {
    const { buyerId } = req.params;
    const all = req.query.all === '1' || req.query.all === 'true';
    await ensureTrackingTables();
    const { rows } = await pool.query(
      `SELECT t.*, p.name as product_name, p.image_urls, u1.username as seller_username
       FROM nat_trackings t
       JOIN products_nat p ON p.id = t.product_id
       JOIN users_nat u1 ON u1.id = t.seller_id
       WHERE t.buyer_id = $1 AND($2:: boolean OR t.active = true)
       ORDER BY t.updated_at DESC`,
      [buyerId, all]
    );
    res.json(rows);
  } catch (err) {
    console.error('GET /natmarket/trackings/buyer/:buyerId', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Detalle por id
app.get('/natmarket/trackings/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await ensureTrackingTables();
    const { rows } = await pool.query(
      `SELECT t.*, p.name as product_name, u1.username as seller_username, u2.username as buyer_username
       FROM nat_trackings t
       JOIN products_nat p ON p.id = t.product_id
       JOIN users_nat u1 ON u1.id = t.seller_id
       JOIN users_nat u2 ON u2.id = t.buyer_id
       WHERE t.id = $1`,
      [id]
    );
    if (!rows.length) return res.status(404).json({ error: 'No encontrado' });
    res.json(rows[0]);
  } catch (err) {
    console.error('GET /natmarket/trackings/:id', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Keep the existing status page route
app.get('/status', (_req, res) =>
  res.sendFile(join(__dirname, 'Ocean and Wild Studios Status', 'index.html'))
);

/* ===== AI PRODUCT GENERATION ===== */

// Ensure AI generation tables exist
async function ensureAIGenerationTables() {
  try {
    // Create AI generation logs table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ai_product_generations(
        id BIGSERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users_nat(id),
        model_id TEXT NOT NULL,
        input_text TEXT NOT NULL,
        generated_product JSONB NOT NULL,
        validation_result JSONB,
        success BOOLEAN NOT NULL,
        error_message TEXT,
        generation_time_ms INTEGER,
        created_at TIMESTAMP DEFAULT NOW()
      )
      `);

    // Create indexes for performance
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_ai_gen_user ON ai_product_generations(user_id)
      `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_ai_gen_created ON ai_product_generations(created_at)
      `);

    // Add AI-related columns to products_nat table
    await pool.query(`
      ALTER TABLE products_nat 
      ADD COLUMN IF NOT EXISTS ai_generated BOOLEAN DEFAULT FALSE,
      ADD COLUMN IF NOT EXISTS ai_model TEXT,
        ADD COLUMN IF NOT EXISTS ai_confidence JSONB
    `);

    console.log('✅ AI generation tables initialized');
  } catch (err) {
    console.error('❌ Error initializing AI generation tables:', err);
  }
}

// Initialize tables on startup
ensureAIGenerationTables();

// Rate limiting for AI generation (10 per hour per user)
async function checkAIRateLimit(userId) {
  try {
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    const { rows } = await pool.query(
      `SELECT COUNT(*) as count FROM ai_product_generations 
       WHERE user_id = $1 AND created_at > $2`,
      [userId, oneHourAgo]
    );

    const count = parseInt(rows[0]?.count || '0');
    if (count >= 10) {
      const resetAt = new Date(Date.now() + 60 * 60 * 1000);
      return {
        allowed: false,
        remaining: 0,
        resetAt: resetAt.toISOString(),
        message: 'Has alcanzado el límite de 10 generaciones por hora'
      };
    }

    return { allowed: true, remaining: 10 - count };
  } catch (err) {
    console.error('Error checking AI rate limit:', err);
    return { allowed: true, remaining: 10 }; // Fail open
  }
}



/* ===== NATMARKET AI GENERATION V2 (SENTINEL EVOLUTION) ===== */

const AI_MODELS = {
  'genesis-v1': { name: 'Genesis (Básico)', cost: 1, multiplier: 1 },
  'sentinel-evolution': { name: 'Sentinel: Evolution (Premium)', cost: 5, multiplier: 2.0 }
};

const BRAND_TO_CATEGORY = {
  'iphone': 'Tecnología', 'ipad': 'Tecnología', 'macbook': 'Tecnología', 'airpods': 'Tecnología', 'apple': 'Tecnología',
  'samsung': 'Tecnología', 'galaxy': 'Tecnología', 'xiaomi': 'Tecnología', 'redmi': 'Tecnología', 'poco': 'Tecnología',
  'motorola': 'Tecnología', 'moto': 'Tecnología', 'sony': 'Tecnología', 'playstation': 'Juegos y Juguetes', 'ps4': 'Juegos y Juguetes',
  'ps5': 'Juegos y Juguetes', 'xbox': 'Juegos y Juguetes', 'nintendo': 'Juegos y Juguetes', 'switch': 'Juegos y Juguetes',
  'lg': 'Tecnología', 'asus': 'Tecnología', 'lenovo': 'Tecnología', 'hp': 'Tecnología', 'dell': 'Tecnología', 'acer': 'Tecnología',
  'nike': 'Moda y Accesorios', 'adidas': 'Moda y Accesorios', 'puma': 'Moda y Accesorios', 'zara': 'Moda y Accesorios',
  'gucci': 'Moda y Accesorios', 'levis': 'Moda y Accesorios', 'h&m': 'Moda y Accesorios',
  'toyota': 'Vehículos y Repuestos', 'ford': 'Vehículos y Repuestos', 'honda': 'Vehículos y Repuestos', 'chevrolet': 'Vehículos y Repuestos',
  'fiat': 'Vehículos y Repuestos', 'volkswagen': 'Vehículos y Repuestos', 'peugeot': 'Vehículos y Repuestos', 'renault': 'Vehículos y Repuestos',
  'whiskas': 'Mascotas', 'pedigree': 'Mascotas', 'royal canin': 'Mascotas', 'dog chow': 'Mascotas'
};

const CATEGORIES_EXTENDED = {
  'Tecnología': ['iphone', 'samsung', 'xiaomi', 'motorola', 'laptop', 'notebook', 'pc', 'gamer', 'teclado', 'mouse', 'monitor', 'auriculares', 'bluetooth', 'smart', 'watch', 'reloj', 'tablet', 'ipad', 'cargador', 'usb', 'wifi', 'router', 'cámara', 'drone', 'tv', 'televisor', 'audio', 'parlante', 'bocina', 'celular', 'móvil', 'smartphone', 'funda', 'vidrio', 'templado', 'impresora', 'disco', 'ssd', 'ram', 'procesador', 'placa', 'video'],
  'Moda y Accesorios': ['camisa', 'pantalón', 'jean', 'remera', 'camiseta', 'chomba', 'zapatillas', 'zapatos', 'botas', 'sandalias', 'vestido', 'pollera', 'falda', 'campera', 'buzo', 'hoodie', 'gorra', 'sombrero', 'bolso', 'mochila', 'cartera', 'billetera', 'cinturón', 'accesorio', 'joya', 'anillo', 'collar', 'pulsera', 'aritos', 'lentes', 'gafas', 'reloj', 'ropa', 'interior', 'malla', 'bikini'],
  'Hogar y Decoración': ['mesa', 'silla', 'sillón', 'sofá', 'cama', 'colchón', 'almohada', 'mueble', 'placard', 'ropero', 'escritorio', 'lámpara', 'luz', 'led', 'decoración', 'cuadro', 'espejo', 'alfombra', 'cortina', 'sábana', 'acolchado', 'toalla', 'cocina', 'olla', 'sartén', 'cubiertos', 'vaso', 'plato', 'taza', 'mate', 'termo', 'jardín', 'planta', 'maceta', 'herramienta', 'taladro', 'martillo', 'destornillador'],
  'Vehículos y Repuestos': ['auto', 'coche', 'camioneta', 'camión', 'moto', 'motocicleta', 'scooter', 'bicicleta', 'bici', 'rueda', 'neumático', 'cubierta', 'llanta', 'casco', 'repuesto', 'motor', 'aceite', 'filtro', 'batería', 'freno', 'accesorio auto', 'parabrisas', 'espejo retrovisor'],
  'Deportes y Fitness': ['fútbol', 'pelota', 'balón', 'raqueta', 'paleta', 'gimnasio', 'gym', 'pesa', 'mancuerna', 'barra', 'disco', 'bici fija', 'cinta', 'running', 'camiseta', 'short', 'calza', 'botines', 'zapatillas deportivas', 'entrenamiento', 'yoga', 'mat', 'colchoneta', 'suplemento', 'proteína', 'natación', 'boxeo', 'guantes'],
  'Juegos y Juguetes': ['juego', 'juguete', 'muñeco', 'figura', 'acción', 'peluche', 'consola', 'playstation', 'ps4', 'ps5', 'xbox', 'nintendo', 'switch', 'joystick', 'gamepad', 'videojuego', 'juego de mesa', 'cartas', 'colección', 'funko', 'lego', 'bloques', 'puzzle', 'rompecabezas', 'infantil', 'bebé'],
  'Libros y Multimedia': ['libro', 'novela', 'texto', 'manual', 'cómic', 'manga', 'revista', 'enciclopedia', 'diccionario', 'cd', 'dvd', 'vinilo', 'disco', 'película', 'serie', 'instrumento', 'guitarra', 'piano', 'teclado', 'batería', 'bajo', 'micrófono', 'partitura'],
  'Salud y Belleza': ['perfume', 'fragancia', 'colonia', 'crema', 'loción', 'maquillaje', 'base', 'labial', 'sombras', 'esmalte', 'shampoo', 'acondicionador', 'jabón', 'cuidado', 'piel', 'facial', 'corporal', 'pelo', 'cabello', 'uñas', 'afeitadora', 'depiladora', 'secador', 'planchita', 'masajeador'],
  'Inmuebles': ['casa', 'departamento', 'depto', 'ph', 'alquiler', 'venta', 'terreno', 'lote', 'local', 'oficina', 'cochera', 'galpón', 'quinta', 'temporada'],
  'Servicios': ['servicio', 'reparación', 'instalación', 'clases', 'curso', 'flete', 'mudanza', 'limpieza', 'mantenimiento', 'diseño', 'programación', 'fotografía', 'evento'],
  'Mascotas': ['perro', 'gato', 'alimento', 'balanceado', 'piedras', 'cama', 'correa', 'collar', 'juguete', 'ropa', 'acuario', 'pez', 'jaula'],
  'Alimentos y Bebidas': ['comida', 'bebida', 'vino', 'cerveza', 'whisky', 'café', 'té', 'yerba', 'azúcar', 'aceite', 'fideos', 'arroz', 'conserva', 'golosina', 'chocolate', 'snack']
};

function detectCategory(input) {
  const lowerInput = input.toLowerCase();

  // 1. Detección por marca conocida (Prioridad Alta)
  for (const [brand, cat] of Object.entries(BRAND_TO_CATEGORY)) {
    if (lowerInput.includes(brand)) return cat;
  }

  // 2. Detección por palabras clave extendidas
  for (const [cat, keywords] of Object.entries(CATEGORIES_EXTENDED)) {
    if (keywords.some(kw => lowerInput.includes(kw))) {
      return cat;
    }
  }
  return 'Otros';
}

function detectCondition(input) {
  const lower = input.toLowerCase();
  if (lower.includes('nuevo') || lower.includes('sellado') || lower.includes('cerrado') || lower.includes('sin uso') || lower.includes('a estrenar') || lower.includes('caja cerrada')) return 'nuevo';
  if (lower.includes('como nuevo') || lower.includes('impecable') || lower.includes('excelente estado') || lower.includes('igual a nuevo') || lower.includes('sin detalles') || lower.includes('10/10')) return 'como nuevo';
  if (lower.includes('reacondicionado') || lower.includes('refurbished') || lower.includes('restaurado')) return 'reacondicionado';
  if (lower.includes('usado') || lower.includes('segunda mano') || lower.includes('detalle') || lower.includes('funciona bien')) return 'usado';

  // Inferencia inteligente si no se dice nada explícito
  if (lower.includes('en caja') && !lower.includes('usado')) return 'nuevo'; // Probable

  return 'usado'; // Default más seguro
}

function generateProductName(input, category, modelId) {
  const words = input.split(/\s+/).filter(w => w.length > 2);
  const stopWords = ['el', 'la', 'los', 'las', 'un', 'una', 'de', 'del', 'en', 'con', 'para', 'por', 'muy', 'buen', 'buena', 'que', 'y', 'o', 'a', 'al', 'es', 'son', 'se', 'vende', 'vendo', 'funcional', 'estado', 'calidad'];
  const keywords = words.filter(w => !stopWords.includes(w.toLowerCase()));

  // Lógica avanzada para Sentinel Evolution
  if (modelId === 'sentinel-evolution') {
    const brands = Object.keys(BRAND_TO_CATEGORY);
    const foundBrand = brands.find(b => input.toLowerCase().includes(b));
    const brandName = foundBrand ? foundBrand.charAt(0).toUpperCase() + foundBrand.slice(1) : '';

    // Extraer palabras clave principales (sustantivos probables)
    let mainKeywords = keywords.slice(0, 6).map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');

    // Limpiar marca del título si ya se detectó para evitar duplicados (ej: "iPhone Celular iPhone")
    if (brandName) {
      mainKeywords = mainKeywords.replace(new RegExp(brandName, 'gi'), '').trim();
    }

    // Emojis por categoría
    const categoryEmojis = {
      'Tecnología': '📱', 'Moda y Accesorios': '👗', 'Hogar y Decoración': '🏠', 'Vehículos y Repuestos': '🚗',
      'Deportes y Fitness': '⚽', 'Juegos y Juguetes': '🎮', 'Libros y Multimedia': '📚', 'Salud y Belleza': '💄',
      'Inmuebles': '🔑', 'Servicios': '🛠️', 'Mascotas': '🐾', 'Alimentos y Bebidas': '🍔'
    };
    const emoji = categoryEmojis[category] || '✨';

    if (brandName) {
      return `${emoji} ${brandName} ${mainKeywords} | ${category} `;
    }
    return `${emoji} ${mainKeywords} - ${category} Premium`;
  }

  // Lógica básica (Genesis)
  const capitalized = keywords.slice(0, 5).map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
  return capitalized || `Producto de ${category} `;
}

function generateProductDescription(input, name, category, condition, modelId) {
  if (modelId === 'sentinel-evolution') {
    // Generación avanzada con estructura de ventas persuasiva y análisis semántico
    const lowerInput = input.toLowerCase();

    // 1. Detección de Adjetivos y Características
    const adjectives = [];
    if (lowerInput.includes('funcional') || lowerInput.includes('anda bien') || lowerInput.includes('funciona')) adjectives.push('es totalmente funcional');
    if (lowerInput.includes('rápido') || lowerInput.includes('veloz') || lowerInput.includes('potente') || lowerInput.includes('fluido')) adjectives.push('ofrece un rendimiento rápido y fluido');
    if (lowerInput.includes('económico') || lowerInput.includes('barato') || lowerInput.includes('oferta')) adjectives.push('es una excelente oportunidad económica');
    if (lowerInput.includes('garantía')) adjectives.push('cuenta con garantía');
    if (lowerInput.includes('original')) adjectives.push('es un producto 100% original');
    if (lowerInput.includes('caja') || lowerInput.includes('completo')) adjectives.push('se entrega completo con su caja');
    if (lowerInput.includes('batería') || lowerInput.includes('duración')) adjectives.push('tiene muy buena autonomía');

    // 2. Detección de Especificaciones Técnicas (Regex simple)
    const specs = [];
    const gbMatch = input.match(/(\d+)\s*(gb|tb)/i);
    if (gbMatch) specs.push(`Almacenamiento / Memoria: ${gbMatch[0].toUpperCase()} `);
    const ramMatch = input.match(/(\d+)\s*ram/i);
    if (ramMatch) specs.push(`Memoria RAM: ${ramMatch[1]} GB`);
    const inchMatch = input.match(/(\d+(\.\d+)?)\s*("|pulgadas)/i);
    if (inchMatch) specs.push(`Pantalla: ${inchMatch[1]} "`);

    // 3. Detección de Urgencia
    const isUrgent = lowerInput.includes('urgente') || lowerInput.includes('viaje') || lowerInput.includes('mudanza') || lowerInput.includes('hoy');
    const urgentText = isUrgent ? "\n⚠️ ¡Atención! Venta por motivo de viaje/mudanza. Escucho ofertas razonables." : "";

    // Construcción del texto
    const intros = [
      `¡Llegó a NatMarket este increíble ${name}! Un artículo destacado en ${category}.`,
      `¿Buscás ${name}? Tenemos exactamente lo que necesitás.`,
      `Oportunidad única: ${name} disponible ahora mismo.`
    ];

    const conditionText = condition === 'nuevo' ? 'totalmente nuevo y en su empaque original' :
      condition === 'como nuevo' ? 'en estado impecable, cuidado maniáticamente' :
        condition === 'reacondicionado' ? 'reacondicionado a nuevo y verificado' :
          'usado pero en muy buenas condiciones, listo para seguir rindiendo';

    const featuresText = adjectives.length > 0
      ? `Lo más destacado es que este artículo ${adjectives.join(', y además ')}.`
      : `Este producto se encuentra ${conditionText}. Ha sido verificado para tu tranquilidad.`;

    const specsList = specs.length > 0 ? `\n\nEspecificaciones:\n• ${specs.join('\n• ')}` : "";

    const benefits = [
      `✅ Compra segura y protegida.\n✅ Excelente relación precio-calidad.`,
      `🚀 Envío rápido a coordinar.\n⭐ Producto recomendado.`,
      `✨ Diseño y funcionalidad garantizados.`
    ];

    const callToAction = [
      `¡No dudes en consultar! Respondemos a la brevedad.`,
      `¡Aprovechalo antes de que vuele!`,
      `Hacé tu oferta o comprá ahora. ¡Te esperamos!`
    ];

    const intro = intros[Math.floor(Math.random() * intros.length)];
    const benefit = benefits[Math.floor(Math.random() * benefits.length)];
    const cta = callToAction[Math.floor(Math.random() * callToAction.length)];

    return `${intro}\n\n${featuresText}${specsList}${urgentText}\n\nPor qué elegirnos:\n${benefit}\n\n${cta}\n\n(Generado por Sentinel: Evolution AI 🧬)`;
  }

  // Lógica básica (Genesis)
  const templates = {
    'nuevo': [`${name} totalmente nuevo. En caja cerrada.`, `Vendo ${name} a estrenar. Impecable.`],
    'usado': [`${name} usado en buen estado.`, `Vendo ${name}, tiene uso pero funciona bien.`],
    'como nuevo': [`${name} igual a nuevo. Muy poco uso.`, `Oportunidad: ${name} impecable.`],
    'reacondicionado': [`${name} reacondicionado a nuevo. Garantizado.`]
  };
  const template = templates[condition] || templates['usado'];
  return template[Math.floor(Math.random() * template.length)] + `\nCategoría: ${category}. Consultar dudas.`;
}

function estimatePrice(input, category, condition, priceHint, modelId) {
  if (priceHint && priceHint > 0) return Math.round(priceHint);

  const basePrices = {
    'Tecnología': 150000, 'Moda y Accesorios': 25000, 'Hogar y Decoración': 40000,
    'Vehículos y Repuestos': 80000, 'Deportes y Fitness': 30000, 'Juegos y Juguetes': 20000,
    'Libros y Multimedia': 10000, 'Salud y Belleza': 15000, 'Inmuebles': 500000, 'Servicios': 20000,
    'Mascotas': 15000, 'Alimentos y Bebidas': 5000, 'Otros': 15000
  };

  let price = basePrices[category] || 20000;

  // Ajuste por palabras clave de valor
  const lowerInput = input.toLowerCase();
  if (lowerInput.includes('pro') || lowerInput.includes('max') || lowerInput.includes('ultra') || lowerInput.includes('premium') || lowerInput.includes('original')) price *= 1.5;
  if (lowerInput.includes('mini') || lowerInput.includes('lite') || lowerInput.includes('básico') || lowerInput.includes('genérico')) price *= 0.7;
  if (lowerInput.includes('lote') || lowerInput.includes('pack') || lowerInput.includes('combo') || lowerInput.includes('set')) price *= 1.3;

  const conditionMultipliers = { 'nuevo': 1.0, 'como nuevo': 0.85, 'reacondicionado': 0.75, 'usado': 0.6 };
  price *= (conditionMultipliers[condition] || 0.6);

  // Sentinel Evolution es más preciso (menos variación aleatoria)
  const variation = modelId === 'sentinel-evolution' ? (0.9 + Math.random() * 0.2) : (0.7 + Math.random() * 0.6);
  price *= variation;

  return Math.round(price / 100) * 100;
}

function generateTags(input, category, modelId) {
  const lowerInput = input.toLowerCase();
  const words = lowerInput.split(/\s+/).filter(w => w.length > 3);
  const uniqueWords = [...new Set(words)];

  const tags = uniqueWords.slice(0, modelId === 'sentinel-evolution' ? 8 : 5);
  tags.push(category.toLowerCase());

  if (modelId === 'sentinel-evolution') {
    // Añadir marca si se detecta
    const brands = Object.keys(BRAND_TO_CATEGORY);
    const foundBrand = brands.find(b => lowerInput.includes(b));
    if (foundBrand && !tags.includes(foundBrand)) tags.unshift(foundBrand);

    // Añadir estado si es relevante
    if (lowerInput.includes('nuevo')) tags.push('nuevo');
    if (lowerInput.includes('usado')) tags.push('usado');

    tags.push('premium', 'oportunidad');
  }

  return [...new Set(tags)].slice(0, 12);
}

function calculateConfidence(input, category, price, modelId) {
  let baseConf = modelId === 'sentinel-evolution' ? 0.98 : 0.85;
  if (input.length < 20) baseConf -= 0.2;
  if (category === 'Otros') baseConf -= 0.1;
  return { name: baseConf, category: baseConf, price: baseConf - 0.1 };
}

function generateProductWithAI(description, hints = {}, modelId = 'genesis-v1') {
  const category = hints.categoryHint || detectCategory(description);
  const condition = hints.conditionHint || detectCondition(description);
  const name = generateProductName(description, category, modelId);
  const finalDesc = generateProductDescription(description, name, category, condition, modelId);
  const price = estimatePrice(description, category, condition, hints.priceHint, modelId);
  const tags = generateTags(description, category, modelId);
  const confidence = calculateConfidence(description, category, price, modelId);

  return {
    name,
    description: finalDesc,
    price,
    category,
    condition,
    tags,
    aiModel: modelId,
    confidence
  };
}

// Endpoint principal de generación
app.post('/natmarket/ai/generate-product', async (req, res) => {
  const startTime = Date.now();

  try {
    const { userId, modelId, productInput } = req.body;
    const selectedModel = modelId || 'genesis-v1';

    // Validar datos requeridos
    if (!userId || !productInput || !productInput.description) {
      return res.status(400).json({
        success: false,
        error: 'userId y productInput.description son requeridos'
      });
    }

    // Verificar si el usuario está baneado
    const banStatus = await isUserBanned(userId);
    if (banStatus.banned) {
      return res.status(403).json({
        success: false,
        error: `Tu cuenta está suspendida hasta ${new Date(banStatus.banUntil).toLocaleDateString('es-AR')}. Razón: ${banStatus.reason}`
      });
    }

    // Verificar rate limit
    const rateLimit = await checkAIRateLimit(userId);
    if (!rateLimit.allowed) {
      return res.status(429).json({
        success: false,
        error: rateLimit.message,
        resetAt: rateLimit.resetAt,
        remaining: 0
      });
    }

    // Validar longitud del input
    if (productInput.description.length < 10) {
      return res.status(400).json({
        success: false,
        error: 'La descripción debe tener al menos 10 caracteres'
      });
    }

    if (productInput.description.length > 500) {
      return res.status(400).json({
        success: false,
        error: 'La descripción no puede exceder 500 caracteres'
      });
    }

    // Generar producto con IA
    const generatedProduct = generateProductWithAI(
      productInput.description,
      {
        priceHint: productInput.priceHint,
        categoryHint: productInput.categoryHint,
        conditionHint: productInput.conditionHint
      },
      selectedModel
    );

    // Validar contenido generado
    if (containsInappropriate(generatedProduct.name) ||
      containsInappropriate(generatedProduct.description)) {

      // Agregar strike al usuario
      await addStrike(userId, 'Intento de generar producto inapropiado con IA');

      // Registrar intento fallido
      await pool.query(
        `INSERT INTO ai_product_generations 
         (user_id, model_id, input_text, generated_product, validation_result, success, error_message, generation_time_ms)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [
          userId,
          selectedModel,
          productInput.description,
          JSON.stringify(generatedProduct),
          JSON.stringify({ valid: false, reason: 'Contenido inapropiado' }),
          false,
          'Contenido inapropiado detectado',
          Date.now() - startTime
        ]
      );

      return res.status(400).json({
        success: false,
        error: 'El contenido generado no cumple con nuestras políticas. Intenta con una descripción diferente.'
      });
    }

    // Validar precio
    if (generatedProduct.price < 100 || generatedProduct.price > 10000000) {
      generatedProduct.price = Math.max(100, Math.min(10000000, generatedProduct.price));
    }

    // Registrar generación exitosa
    await pool.query(
      `INSERT INTO ai_product_generations 
       (user_id, model_id, input_text, generated_product, validation_result, success, generation_time_ms)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        userId,
        selectedModel,
        productInput.description,
        JSON.stringify(generatedProduct),
        JSON.stringify({ valid: true }),
        true,
        Date.now() - startTime
      ]
    );

    // Responder con el producto generado
    res.json({
      success: true,
      product: {
        name: generatedProduct.name,
        description: generatedProduct.description,
        price: generatedProduct.price,
        category: generatedProduct.category,
        condition: generatedProduct.condition,
        tags: generatedProduct.tags,
        aiGenerated: true,
        aiModel: generatedProduct.aiModel,
        confidence: generatedProduct.confidence
      }
    });

  } catch (err) {
    console.error('Error en generación de producto con IA:', err);
    res.status(500).json({
      success: false,
      error: 'Error interno del servidor al generar el producto'
    });
  }
});



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

/* ===== OCEAN CINEMAS - PRE-RESERVAS ===== */

// Crear tabla de pre-reservas
async function ensurePreReservasTables() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ocean_cinemas_prereservas (
        id BIGSERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        pelicula_id TEXT NOT NULL,
        pelicula_titulo TEXT NOT NULL,
        horario_estreno TIMESTAMP NOT NULL,
        asientos TEXT[] NOT NULL,
        precio_total INTEGER NOT NULL,
        estado TEXT NOT NULL DEFAULT 'PRE-RESERVADO',
        fecha_compra TIMESTAMP DEFAULT NOW(),
        fecha_activacion TIMESTAMP,
        ocean_pay_tx_id TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_prereservas_user ON ocean_cinemas_prereservas(user_id)
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_prereservas_pelicula ON ocean_cinemas_prereservas(pelicula_id)
    `);

    console.log('✅ Ocean Cinemas pre-reservas tables initialized');
  } catch (err) {
    console.error('❌ Error initializing pre-reservas tables:', err);
  }
}

// Inicializar tablas al arrancar
ensurePreReservasTables();

// Endpoint para crear pre-reserva
app.post('/ocean-cinemas/prereserva', async (req, res) => {
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

  const {
    peliculaId,
    peliculaTitulo,
    horarioEstreno,
    asientos,
    precioTotal
  } = req.body;

  if (!peliculaId || !peliculaTitulo || !horarioEstreno || !asientos || !precioTotal) {
    return res.status(400).json({ error: 'Datos incompletos' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Verificar saldo de AquaBux
    const { rows: userRows } = await client.query(
      'SELECT aquabux FROM ocean_pay_users WHERE id = $1 FOR UPDATE',
      [userId]
    );

    if (userRows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Usuario no encontrado en Ocean Pay' });
    }

    const currentBalance = userRows[0].aquabux || 0;
    if (currentBalance < precioTotal) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        error: `Saldo insuficiente. Necesitas ${precioTotal} AquaBux.`,
        currentBalance
      });
    }

    // Descontar AquaBux
    const newBalance = currentBalance - precioTotal;
    await client.query(
      'UPDATE ocean_pay_users SET aquabux = $1 WHERE id = $2',
      [newBalance, userId]
    );

    // Crear pre-reserva
    const fechaActivacion = new Date(horarioEstreno);
    const { rows: prereservaRows } = await client.query(
      `INSERT INTO ocean_cinemas_prereservas 
       (user_id, pelicula_id, pelicula_titulo, horario_estreno, asientos, precio_total, fecha_activacion)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [userId, peliculaId, peliculaTitulo, horarioEstreno, asientos, precioTotal, fechaActivacion]
    );

    // Registrar transacción
    await client.query(
      `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen)
       VALUES ($1, $2, $3, $4)`,
      [userId, `Pre-reserva: ${peliculaTitulo}`, -precioTotal, 'Ocean Cinemas']
    );

    await client.query('COMMIT');

    res.json({
      success: true,
      prereserva: prereservaRows[0],
      newBalance
    });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error creando pre-reserva:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  } finally {
    client.release();
  }
});

// Endpoint para obtener pre-reservas del usuario
app.get('/ocean-cinemas/prereservas/:userId', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.substring(7);
  let tokenUserId;
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    tokenUserId = decoded.uid;
    tokenUserId = parseInt(tokenUserId) || tokenUserId;
  } catch (e) {
    return res.status(401).json({ error: 'Token inválido' });
  }

  const { userId } = req.params;

  // Verificar que el usuario solo pueda ver sus propias pre-reservas
  if (parseInt(userId) !== tokenUserId) {
    return res.status(403).json({ error: 'No autorizado' });
  }

  try {
    const { rows } = await pool.query(
      `SELECT * FROM ocean_cinemas_prereservas 
       WHERE user_id = $1 
       ORDER BY created_at DESC`,
      [userId]
    );

    res.json(rows);
  } catch (err) {
    console.error('Error obteniendo pre-reservas:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Endpoint para activar pre-reservas (ejecutar periódicamente)
app.post('/ocean-cinemas/activar-prereservas', async (req, res) => {
  try {
    const now = new Date();

    const { rows } = await pool.query(
      `UPDATE ocean_cinemas_prereservas 
       SET estado = 'ACTIVO', updated_at = NOW()
       WHERE estado = 'PRE-RESERVADO' 
       AND fecha_activacion <= $1
       RETURNING *`,
      [now]
    );

    res.json({
      success: true,
      activadas: rows.length,
      prereservas: rows
    });

  } catch (err) {
    console.error('Error activando pre-reservas:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Endpoint para verificar disponibilidad de asientos
app.post('/ocean-cinemas/verificar-asientos', async (req, res) => {
  const { peliculaId, horarioEstreno, asientos } = req.body;

  if (!peliculaId || !horarioEstreno || !asientos) {
    return res.status(400).json({ error: 'Datos incompletos' });
  }

  try {
    // Obtener asientos ya reservados para ese horario
    const { rows } = await pool.query(
      `SELECT asientos FROM ocean_cinemas_prereservas 
       WHERE pelicula_id = $1 
       AND horario_estreno = $2 
       AND estado IN ('PRE-RESERVADO', 'ACTIVO')`,
      [peliculaId, horarioEstreno]
    );

    // Combinar todos los asientos reservados
    const asientosReservados = new Set();
    rows.forEach(row => {
      if (row.asientos && Array.isArray(row.asientos)) {
        row.asientos.forEach(asiento => asientosReservados.add(asiento));
      }
    });

    // Verificar si algún asiento solicitado ya está reservado
    const conflictos = asientos.filter(asiento => asientosReservados.has(asiento));

    res.json({
      disponible: conflictos.length === 0,
      conflictos,
      asientosReservados: Array.from(asientosReservados)
    });

  } catch (err) {
    console.error('Error verificando asientos:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Endpoint para obtener estadísticas de pre-reservas
app.get('/ocean-cinemas/stats-prereservas', async (req, res) => {
  try {
    const { rows: totalRows } = await pool.query(
      'SELECT COUNT(*) as total FROM ocean_cinemas_prereservas'
    );

    const { rows: activasRows } = await pool.query(
      "SELECT COUNT(*) as activas FROM ocean_cinemas_prereservas WHERE estado = 'PRE-RESERVADO'"
    );

    const { rows: activadasRows } = await pool.query(
      "SELECT COUNT(*) as activadas FROM ocean_cinemas_prereservas WHERE estado = 'ACTIVO'"
    );

    const { rows: peliculasRows } = await pool.query(
      'SELECT pelicula_id, pelicula_titulo, COUNT(*) as reservas FROM ocean_cinemas_prereservas GROUP BY pelicula_id, pelicula_titulo ORDER BY reservas DESC'
    );

    res.json({
      total: parseInt(totalRows[0].total),
      preReservadas: parseInt(activasRows[0].activas),
      activadas: parseInt(activadasRows[0].activadas),
      porPelicula: peliculasRows
    });

  } catch (err) {
    console.error('Error obteniendo estadísticas:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Servir Ocean Cinemas
app.get('/ocean-cinemas', (_req, res) => {
  try {
    const html = fs.readFileSync(join(__dirname, 'Ocean Cinemas', 'index.html'), 'utf-8');
    res.type('html').send(html);
  } catch (e) {
    res.status(404).send('Ocean Cinemas no encontrado');
  }
});

// Servir archivos estáticos de Ocean Cinemas
app.use('/ocean-cinemas', express.static(join(__dirname, 'Ocean Cinemas')));

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
async function initBlogsTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS blogs (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      author TEXT DEFAULT 'Anónimo',
      likes INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
}

app.post("/api/blogs", async (req, res) => {
  const { title, content, author } = req.body;
  if (!title || !content) return res.status(400).json({ error: "Faltan datos" });

  try {
    const { rows } = await pool.query(
      `INSERT INTO blogs (title, content, author) VALUES ($1, $2, $3) RETURNING *`,
      [title, content, author || "Anónimo"]
    );
    res.json({ success: true, blog: rows[0] });
  } catch (err) {
    if (err.message.includes('does not exist') || err.code === '42P01') {
      await initBlogsTable();
      const { rows } = await pool.query(
        `INSERT INTO blogs (title, content, author) VALUES ($1, $2, $3) RETURNING *`,
        [title, content, author || "Anónimo"]
      );
      return res.json({ success: true, blog: rows[0] });
    }
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/blogs", async (_req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM blogs ORDER BY created_at DESC LIMIT 20`
    );
    res.json(rows);
  } catch (err) {
    if (err.message.includes('does not exist') || err.code === '42P01') {
      await initBlogsTable();
      return res.json([]);
    }
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/blogs/:id/like", async (req, res) => {
  try {
    const { id } = req.params;
    const { rows } = await pool.query(
      `UPDATE blogs SET likes = likes + 1 WHERE id = $1 RETURNING likes`,
      [id]
    );
    res.json({ success: true, likes: rows[0]?.likes || 0 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
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
  } catch (err) {
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Marcar eclipse como anunciado
app.post("/api/eclipse/:id/announce", async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query(`UPDATE eclipses SET announced = TRUE WHERE id = $1`, [id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Marcar eclipse como recompensado
app.post("/api/eclipse/:id/reward", async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query(`UPDATE eclipses SET rewarded = TRUE WHERE id = $1`, [id]);
    res.json({ success: true });
  } catch (err) {
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
  { id: 1, question: "¿Cuál es el planeta más grande del sistema solar?", category: "Ciencia", answer: "Júpiter" },
  { id: 2, question: "¿En qué país nació el tango?", category: "Cultura", answer: "Argentina" },
  { id: 3, question: "¿Qué elemento tiene el símbolo 'Au'?", category: "Química", answer: "Oro" },
  { id: 4, question: "¿Quién pintó 'La noche estrellada'?", category: "Arte", answer: "Van Gogh" },
  { id: 5, question: "¿Cuántos bits hay en un byte?", category: "Tecnología", answer: "8" }
];

/* 1) devuelve pregunta y **marca** como usada ya */
app.get('/api/ia-question/:userId', async (req, res) => {
  const { userId } = req.params;
  const { rows } = await pool.query(
    `SELECT used_today FROM ia_state WHERE user_id = $1`, [userId]
  );
  const used = rows[0]?.used_today || [];
  const avail = QUESTIONS_POOL.filter(q => !used.includes(q.id));
  if (!avail.length) return res.status(404).json(null);
  const q = avail[Math.floor(Math.random() * avail.length)];

  /* guardarla AHORA → no se repite */
  await pool.query(
    `UPDATE ia_state SET used_today = array_append(used_today,$2) WHERE user_id=$1`,
    [userId, q.id]
  );
  res.json(q);
});

/* 2) respuesta SIEMPRE correcta + recompensa + nivel en vivo */
app.post('/api/ia-answer/:userId', async (req, res) => {
  const { userId } = req.params;
  const { questionId } = req.body;

  /* recompensa */
  const roll = Math.random();
  let reward = { type: '', amount: 0 };
  if (roll < 0.65) {              // 65 % Ecoxionums
    reward.type = 'coins';
    reward.amount = 30 + Math.floor(Math.random() * 21);   // 30-50
  } else {                         // 35 % EXP
    reward.type = 'exp';
    reward.amount = 25 + Math.floor(Math.random() * 11);   // 25-35
  }

  /* aplicar recompensa y subir nivel si corresponde */
  const lvl = await getLevelLive(userId);          // nivel actual
  let newExp = lvl.exp + reward.amount;
  let newLvl = lvl.level;
  let needed = expForLevel(newLvl);
  while (newExp >= needed) {                       // sube de nivel
    newExp -= needed;
    newLvl++;
    needed = expForLevel(newLvl);
  }
  await saveLevelLive(userId, newLvl, newExp);    // persiste

  res.json({ success: true, reward, level: { level: newLvl, exp: newExp, nextExp: needed } });
});

/* 3) límite diario */
app.get('/api/ia-limit/:userId', async (req, res) => {
  const { userId } = req.params;
  const now = new Date();
  const { rows } = await pool.query(
    `SELECT reset_at, array_length(used_today,1) AS used
     FROM ia_state WHERE user_id = $1`, [userId]
  );
  let reset = rows[0]?.reset_at;
  if (!reset || new Date(reset) <= now) {
    reset = new Date(Date.now() + 5 * 60 * 60 * 1000).toISOString();
    await pool.query(
      `INSERT INTO ia_state(user_id,used_today,reset_at) VALUES($1,'{}',$2)
       ON CONFLICT(user_id) DO UPDATE SET used_today='{}', reset_at=$2`,
      [userId, reset]
    );
    return res.json({ remaining: 3, nextReset: reset });
  }
  const used = rows[0]?.used || 0;
  res.json({ remaining: Math.max(0, 3 - used), nextReset: reset });
});

/* ----------  HELPERS LIVE  ---------- */
async function getLevelLive(userId) {
  const { rows } = await pool.query(
    `SELECT level, exp FROM user_levels WHERE user_id = $1`, [userId]
  );
  return rows[0] || { level: 1, exp: 0 };
}
async function saveLevelLive(userId, level, exp) {
  await pool.query(
    `INSERT INTO user_levels (user_id, level, exp) VALUES ($1,$2,$3)
     ON CONFLICT (user_id) DO UPDATE SET level=$2, exp=$3`,
    [userId, level, exp]
  );
}
function expForLevel(lvl) {
  return 100 * Math.pow(1.05, lvl - 1);   // igual que tenías
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
// Product-specific; no cross-product fallback to avoid mixing notes
const PRODUCT_TABLES = { deepdive: 'deepdive_updates', natmarket: 'natmarket_updates', ecoconsole: 'updates_ecoconsole' };
app.get("/api/featured-update", async (req, res) => {
  try {
    const product = String(req.query.product || '').toLowerCase();

    // Si no se especifica producto o no es válido, devolver null (no mezclar productos)
    if (!product || !PRODUCT_TABLES[product]) {
      console.log(`⚠️ Producto no especificado o inválido: "${product}"`);
      return res.json(null);
    }

    const table = PRODUCT_TABLES[product];
    console.log(`📋 Consultando actualizaciones de ${product} desde tabla ${table}`);

    // HARDCODED UPDATE FOR NATMARKET (Sentinel: Evolution)
    // Esto asegura que el frontend reciba la estructura 'sections' correcta sin depender de la DB de texto plano
    if (product === 'natmarket') {
      return res.json({
        version: '10.12.2025 - Sentinel: Evolution',
        date: '10 de diciembre de 2025',
        sections: [
          {
            title: '🧠 Nuevo Modelo de IA: Sentinel Evolution',
            icon: '🚀',
            items: [
              'Presentamos Sentinel: Evolution, nuestro modelo de IA más avanzado.',
              'Detección inteligente de marcas y asignación automática de categorías.',
              'Descripciones semánticas que entienden el contexto y generan textos persuasivos.',
              'Generación de tags optimizados para búsqueda con detección de estado (Nuevo/Usado).',
              'Títulos más limpios y atractivos con emojis contextuales.',
              'Disponible ahora en el selector de modelos al crear un producto.'
            ]
          },
          {
            title: '✨ Mejoras en la Experiencia',
            icon: '💎',
            items: [
              'Interfaz de creación de productos rediseñada y más espaciosa.',
              'Selector de modelos de IA visualmente mejorado.',
              'Correcciones de estilo y optimizaciones de rendimiento.'
            ]
          }
        ]
      });
    }

    const { rows } = await pool.query(`SELECT version, news, date FROM ${table} ORDER BY date DESC LIMIT 1`);
    if (!rows[0]) {
      console.log(`ℹ️ No hay actualizaciones en ${table}`);
      return res.json(null);
    }

    console.log(`✅ Actualización encontrada para ${product}: ${rows[0].version}`);
    res.json({ version: rows[0].version, date: rows[0].date, news: sanitizeNews(rows[0].news || '') });
  } catch (err) {
    console.error("❌ Error en /api/featured-update:", err.message);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

// DeepDive-specific latest update endpoint
app.get('/deepdive/updates/latest', async (_req, res) => {
  try {
    const { rows } = await pool.query("SELECT version, news, date FROM deepdive_updates ORDER BY date DESC LIMIT 1");
    if (!rows[0]) return res.json(null);
    const out = { ...rows[0], news: sanitizeNews(rows[0].news || '') };
    res.json(out);
  } catch (e) { res.json(null); }
});

// NatMarket-specific latest update endpoint
app.get('/natmarket/updates/latest', async (_req, res) => {
  try {
    const { rows } = await pool.query("SELECT version, news, date FROM natmarket_updates ORDER BY date DESC LIMIT 1");
    if (!rows[0]) return res.json(null);
    const out = { ...rows[0], news: sanitizeNews(rows[0].news || '') };
    res.json(out);
  } catch (e) { res.json(null); }
});

app.post("/publish-version", async (req, res) => {
  const { secret, version, news, product = 'ecoconsole' } = req.body;
  if (secret !== process.env.STUDIO_SECRET)
    return res.status(401).json({ error: "No autorizado" });

  const cleanNews = sanitizeNews(news || "");
  const prod = String(product || 'ecoconsole').toLowerCase();
  const table = PRODUCT_TABLES[prod] || PRODUCT_TABLES.ecoconsole;
  try {
    // Ensure table exists
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ${table} (
        version TEXT NOT NULL,
        news TEXT NOT NULL,
        date TIMESTAMP DEFAULT NOW()
      )`);
  } catch { }

  await pool.query(
    `INSERT INTO ${table} (version, news, date) VALUES ($1, $2, NOW())`,
    [version, cleanNews]
  );

  res.json({ ok: true, msg: `Versión publicada en ${table}` });
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



// ===== DeepDive: seed update notes and beta announcement (original tables) =====
async function seedDeepDiveUpdateAndBeta() {
  try {
    // 1) Update notes entry – use deepdive_updates (original table)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS deepdive_updates (
        id SERIAL PRIMARY KEY,
        version TEXT,
        news TEXT,
        date TIMESTAMP DEFAULT NOW()
      )`);
    const version = '0.9.0-beta';
    const newsFull = [
      'DeepDive Presentations — 0.9.0-beta',
      '',
      '- Added 10+ new intro templates (App/Game/Platform/Vertical/Square/Gradient/Neon)',
      '- Added 15 new intro text effects (FadeUp, ZoomCenter, BlurIn, SlideBottom, LightSweep, LetterSpaceIn, FlipX, SplitVertical, ZoomCorner, BounceDown, FadeLeftBig, OutlineDraw, NeonPulse, SparkPop, RibbonSlide)',
      '- Background Manager: color, gradient, image (fit/position/dim), with export parity',
      '- Audio Tracks: per-slide music/VO timeline with browser export mixing',
      '- Timeline layers, easing, slide fades; Add panel for Text/Video/Audio',
      '',
      'Beta Announcement: Public beta starts on 11/11. Thank you for testing!'
    ].join('\n');
    await pool.query(
      `INSERT INTO deepdive_updates (version, news, date)
       SELECT $1, $2, NOW()
       WHERE NOT EXISTS (SELECT 1 FROM deepdive_updates WHERE version=$1)`,
      [version, newsFull]
    );

    // 2) Beta event on 11/11 – use deepdive_events (original table)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS deepdive_events (
        id SERIAL PRIMARY KEY,
        name TEXT,
        keyword TEXT UNIQUE,
        musicURL TEXT,
        startAt TIMESTAMP,
        rewardBits INTEGER,
        created TIMESTAMP DEFAULT NOW(),
        finished BOOLEAN
      )`);
    const evName = 'DeepDive Public Beta';
    const evKey = 'deepdive_beta_2025_11_11';
    const startAt = new Date('2025-11-11T09:00:00Z');
    await pool.query(
      `INSERT INTO deepdive_events (name, keyword, musicURL, startAt, rewardBits, created)
       SELECT $1, $2, $3, $4, $5, NOW()
       WHERE NOT EXISTS (SELECT 1 FROM deepdive_events WHERE keyword=$2)`,
      [evName, evKey, '', startAt, 100]
    );
  } catch (e) {
    console.warn('[DeepDive seed] skipped:', e.message);
  }
}
seedDeepDiveUpdateAndBeta();

// One-time scrub: sanitize latest update note to remove internal URLs if present
async function scrubLatestUpdateNews() {
  try {
    // DeepDive table
    await pool.query(`CREATE TABLE IF NOT EXISTS deepdive_updates (id SERIAL PRIMARY KEY, version TEXT, news TEXT, date TIMESTAMP DEFAULT NOW())`);
    const { rows } = await pool.query(`SELECT id, news FROM deepdive_updates ORDER BY date DESC LIMIT 1`);
    if (rows[0]) {
      const clean = sanitizeNews(rows[0].news || '');
      if ((rows[0].news || '') !== clean) {
        await pool.query(`UPDATE deepdive_updates SET news=$1 WHERE id=$2`, [clean, rows[0].id]);
      }
    }
    // Legacy table
    try {
      const r2 = await pool.query(`SELECT id, news FROM updates_ecoconsole ORDER BY date DESC LIMIT 1`);
      if (r2.rows[0]) {
        const clean2 = sanitizeNews(r2.rows[0].news || '');
        if ((r2.rows[0].news || '') !== clean2) {
          await pool.query(`UPDATE updates_ecoconsole SET news=$1 WHERE id=$2`, [clean2, r2.rows[0].id]);
        }
      }
    } catch { }
  } catch (e) {
    console.warn('[DeepDive scrub] skipped:', e.message);
  }
}

scrubLatestUpdateNews();

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

    res.json({
      id: rows[0].id,
      username: rows[0].username,
      needs_unique_id: !rows[0].user_unique_id,
      user_unique_id: !rows[0].user_unique_id ? userUniqueId : undefined
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

    const user = rows[0];
    // Flag para indicar si es Admin (usado por el cliente para mostrar check rojo en el perfil)
    user.is_admin = await isAdminUserById(user.id);

    res.json(user);
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

// Endpoints de vinculación con OceanicEthernet eliminados - ya no se requiere vinculación

// Script de migración: Crear tablas necesarias de NatMarket
async function createNatMarketTables() {
  try {
    console.log('🔄 Verificando tablas de NatMarket...');

    // Crear tabla de imágenes de productos
    await pool.query(`
      CREATE TABLE IF NOT EXISTS product_images_nat (
        id SERIAL PRIMARY KEY,
        product_id INTEGER NOT NULL REFERENCES products_nat(id) ON DELETE CASCADE,
        url TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Crear tabla de videos de productos
    await pool.query(`
      CREATE TABLE IF NOT EXISTS product_videos_nat (
        id SERIAL PRIMARY KEY,
        product_id INTEGER NOT NULL REFERENCES products_nat(id) ON DELETE CASCADE,
        url TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Agregar columna views a products_nat si no existe
    try {
      await pool.query(`
        ALTER TABLE products_nat 
        ADD COLUMN IF NOT EXISTS views INTEGER DEFAULT 0
      `);
    } catch (err) {
      // Ignorar error si la columna ya existe
      console.log('Columna views ya existe o no se pudo agregar');
    }

    console.log('✅ Tablas de NatMarket verificadas/creadas correctamente.');

  } catch (err) {
    console.error('❌ Error creando tablas de NatMarket:', err);
  }
}

// Script de migración: Notificar a usuarios que estaban vinculados con OceanicEthernet
async function notifyUnlinkedUsers() {
  try {
    console.log('🔄 Ejecutando migración: Notificando desvinculación de OceanicEthernet...');

    // Obtener todos los usuarios de NatMarket que estaban vinculados
    const { rows: linkedUsers } = await pool.query(`
      SELECT DISTINCT external_user_id as user_id
      FROM oceanic_ethernet_user_links 
      WHERE external_system = 'NatMarket'
    `);

    if (linkedUsers.length === 0) {
      console.log('✅ No hay usuarios vinculados para notificar.');
      return;
    }

    // Crear notificaciones para cada usuario vinculado
    for (const user of linkedUsers) {
      await pool.query(
        `INSERT INTO notifications_nat (user_id, type, message, created_at)
         VALUES ($1, 'system', $2, NOW())
         ON CONFLICT DO NOTHING`,
        [
          user.user_id,
          '🔄 Actualización del Sistema: La vinculación con OceanicEthernet ha sido eliminada de NatMarket. Ya no necesitas saldo de internet para publicar productos. ¡Ahora es completamente gratuito!'
        ]
      );
    }

    console.log(`✅ Notificaciones enviadas a ${linkedUsers.length} usuarios sobre la desvinculación.`);

    // Opcional: Eliminar las vinculaciones de la base de datos
    await pool.query(`
      DELETE FROM oceanic_ethernet_user_links 
      WHERE external_system = 'NatMarket'
    `);

    console.log('✅ Vinculaciones de NatMarket eliminadas de la base de datos.');

  } catch (err) {
    console.error('❌ Error en migración de desvinculación:', err);
  }
}

// Ejecutar la migración una sola vez al iniciar el servidor
let migrationExecuted = false;

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
    // Guardar rutas relativas para evitar problemas con cambios de host/puerto
    // El frontend deberá prepender API_BASE si es necesario
    // DEBUG: Ver qué archivos llegan y sus propiedades
    if (req.files && req.files.length > 0) {
      console.log('📦 Primer archivo completo:', req.files[0]);
    }
    console.log('📦 Archivos recibidos (resumen):', req.files ? req.files.map(f => ({ path: f.path, filename: f.filename })) : 'Ninguno');

    const urls = (req.files || []).map(f => {
      // Si hay credenciales de Cloudinary configuradas, SIEMPRE intentar usar URL de nube
      if (CLOUD_NAME) {
        // 1. Intentar obtener URL directa del objeto
        if (f.secure_url) return f.secure_url;
        if (f.url && f.url.startsWith('http')) return f.url;
        if (f.path && f.path.startsWith('http')) return f.path;

        // 2. Fallback: Construir URL manualmente
        const publicId = f.filename || f.public_id;
        return `https://res.cloudinary.com/${CLOUD_NAME}/image/upload/${publicId}`;
      }

      // Si NO hay credenciales, usar almacenamiento local
      return `/uploads/nat/${f.filename}`;
    });
    console.log('🔗 URLs a guardar en DB:', urls);
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

    const urls = (req.files || []).map(f => {
      // Si hay credenciales de Cloudinary, usar URL de nube
      if (CLOUD_NAME) {
        if (f.secure_url) return f.secure_url;
        if (f.url && f.url.startsWith('http')) return f.url;
        if (f.path && f.path.startsWith('http')) return f.path;

        // Fallback manual
        const publicId = f.filename || f.public_id;
        return `https://res.cloudinary.com/${CLOUD_NAME}/image/upload/${publicId}`;
      }
      // Local
      return `${host}/uploads/nat/${f.filename}`;
    });

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
      } catch (_) { }

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
    const { user_id, stock, sold, buyer_id, name, description, price, contact_number, category, status } = req.body;

    if (!user_id) return res.status(400).json({ error: 'user_id requerido' });

    // Verificar que el producto existe y pertenece al usuario
    const { rows: productRows } = await pool.query('SELECT user_id, sold FROM products_nat WHERE id=$1', [id]);
    if (productRows.length === 0) return res.status(404).json({ error: 'Producto no encontrado' });
    if (Number(productRows[0].user_id) !== Number(user_id)) return res.status(403).json({ error: 'No autorizado' });

    const currentProduct = productRows[0];

    // Si el producto está vendido, NO permitir modificar el stock (pero sí otros campos si es necesario, aunque con cuidado)
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

    if (name !== undefined) { updates.push(`name = $${paramIndex}`); values.push(name); paramIndex++; }
    if (description !== undefined) { updates.push(`description = $${paramIndex}`); values.push(description); paramIndex++; }
    if (price !== undefined) { updates.push(`price = $${paramIndex}`); values.push(parseFloat(price)); paramIndex++; }
    if (contact_number !== undefined) { updates.push(`contact_number = $${paramIndex}`); values.push(contact_number); paramIndex++; }
    if (category !== undefined) { updates.push(`category = $${paramIndex}`); values.push(category); paramIndex++; }
    if (status !== undefined) { updates.push(`status = $${paramIndex}`); values.push(status); paramIndex++; }

    if (updates.length === 0) return res.status(400).json({ error: 'No hay campos para actualizar' });

    values.push(id);
    const query = `UPDATE products_nat SET ${updates.join(', ')} WHERE id = $${paramIndex} RETURNING *`;

    const { rows: [updated] } = await pool.query(query, values);

    // NOTIFICAR AL COMPRADOR SI SE MARCÓ COMO VENDIDO
    if (sold === true && buyer_id) {
      try {
        // Obtener nombre del vendedor y producto
        const { rows: details } = await pool.query(`
          SELECT u.username as seller_name, p.name as product_name 
          FROM products_nat p
          JOIN users_nat u ON p.user_id = u.id
          WHERE p.id = $1
        `, [id]);

        if (details.length > 0) {
          const { seller_name, product_name } = details[0];

          await pool.query(`
            INSERT INTO notifications_nat (user_id, type, message, product_id, sender_id, created_at)
            VALUES ($1, 'purchase', $2, $3, $4, NOW())
          `, [
            buyer_id,
            `🎉 ¡Compra confirmada! ${seller_name} marcó "${product_name}" como vendido a ti. ¡No olvides calificarlo!`,
            id,
            user_id
          ]);
        }
      } catch (notifErr) {
        console.error('Error enviando notificación de venta:', notifErr);
      }
    }

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

/* ---------- SISTEMA DE REVIEWS/REPUTACIÓN ---------- */

// Crear una review (calificación)
app.post('/natmarket/reviews', async (req, res) => {
  try {
    const { reviewer_id, reviewed_user_id, product_id, rating, comment, review_type } = req.body;

    if (!reviewer_id || !reviewed_user_id || !rating || !review_type) {
      return res.status(400).json({ error: 'reviewer_id, reviewed_user_id, rating y review_type son requeridos' });
    }

    if (rating < 1 || rating > 5) {
      return res.status(400).json({ error: 'rating debe estar entre 1 y 5' });
    }

    if (!['seller', 'buyer'].includes(review_type)) {
      return res.status(400).json({ error: 'review_type debe ser "seller" o "buyer"' });
    }

    // No permitir auto-calificación
    if (Number(reviewer_id) === Number(reviewed_user_id)) {
      return res.status(400).json({ error: 'No puedes calificarte a ti mismo' });
    }

    // Insertar review
    const { rows } = await pool.query(`
      INSERT INTO reviews_nat (reviewer_id, reviewed_user_id, product_id, rating, comment, review_type, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, NOW())
      RETURNING *
    `, [reviewer_id, reviewed_user_id, product_id || null, rating, comment || null, review_type]);

    res.json(rows[0]);
  } catch (err) {
    handleNatError(res, err, 'POST /natmarket/reviews');
  }
});

// Obtener reviews de un usuario
app.get('/natmarket/users/:userId/reviews', async (req, res) => {
  try {
    const { userId } = req.params;
    const { type } = req.query; // 'seller' o 'buyer'

    let query = `
      SELECT 
        r.*,
        reviewer.username as reviewer_username,
        p.name as product_name
      FROM reviews_nat r
      JOIN users_nat reviewer ON r.reviewer_id = reviewer.id
      LEFT JOIN products_nat p ON r.product_id = p.id
      WHERE r.reviewed_user_id = $1
    `;

    const params = [userId];

    if (type === 'seller' || type === 'buyer') {
      query += ` AND r.review_type = $2`;
      params.push(type);
    }

    query += ` ORDER BY r.created_at DESC`;

    const { rows } = await pool.query(query, params);

    res.json(rows);
  } catch (err) {
    handleNatError(res, err, 'GET /natmarket/users/:userId/reviews');
  }
});

// Obtener reputación agregada de un usuario
app.get('/natmarket/users/:userId/reputation', async (req, res) => {
  try {
    const { userId } = req.params;

    // Calcular stats como vendedor
    const { rows: sellerStats } = await pool.query(`
      SELECT 
        COUNT(*) as seller_total_reviews,
        AVG(rating) as seller_avg_rating
      FROM reviews_nat
      WHERE reviewed_user_id = $1 AND review_type = 'seller'
    `, [userId]);

    // Calcular stats como comprador
    const { rows: buyerStats } = await pool.query(`
      SELECT 
        COUNT(*) as buyer_total_reviews,
        AVG(rating) as buyer_avg_rating
      FROM reviews_nat
      WHERE reviewed_user_id = $1 AND review_type = 'buyer'
    `, [userId]);

    // Calcular ventas y compras totales
    const { rows: salesData } = await pool.query(`
      SELECT COUNT(*) as seller_total_sales
      FROM products_nat
      WHERE user_id = $1 AND sold = true
    `, [userId]);

    const { rows: purchasesData } = await pool.query(`
      SELECT COUNT(*) as buyer_total_purchases
      FROM products_nat
      WHERE buyer_id = $1 AND sold = true
    `, [userId]);

    // Determinar badges
    const sellerRating = parseFloat(sellerStats[0].seller_avg_rating) || 0;
    const sellerReviews = parseInt(sellerStats[0].seller_total_reviews) || 0;
    const buyerRating = parseFloat(buyerStats[0].buyer_avg_rating) || 0;
    const buyerReviews = parseInt(buyerStats[0].buyer_total_reviews) || 0;

    const getSellerBadge = (avg, count) => {
      if (count === 0) return '🌱 Vendedor Nuevo';
      if (avg < 3) return '⚠️ Vendedor Regular';
      if (count < 5) return '🌿 Vendedor Básico';
      if (avg >= 4.8 && count >= 50) return '👑 Vendedor Leyenda';
      if (avg >= 4.5 && count >= 20) return '🏆 Vendedor Maestro';
      if (avg >= 4.3 && count >= 10) return '💎 Vendedor Experto';
      if (avg >= 4.0) return '⭐ Vendedor Experimentado';
      return '✅ Vendedor Confiable';
    };

    const getBuyerBadge = (avg, count) => {
      if (count === 0) return '🌱 Comprador Nuevo';
      if (avg < 3) return '⚠️ Comprador Regular';
      if (count < 5) return '🌿 Comprador Básico';
      if (avg >= 4.8 && count >= 50) return '👑 Comprador Leyenda';
      if (avg >= 4.5 && count >= 20) return '🏆 Comprador Maestro';
      if (avg >= 4.3 && count >= 10) return '💎 Comprador Experto';
      if (avg >= 4.0) return '⭐ Comprador Experimentado';
      return '✅ Comprador Confiable';
    };

    res.json({
      user_id: parseInt(userId),
      seller_avg_rating: parseFloat(sellerRating.toFixed(2)),
      seller_total_reviews: sellerReviews,
      seller_total_sales: parseInt(salesData[0].seller_total_sales) || 0,
      buyer_avg_rating: parseFloat(buyerRating.toFixed(2)),
      buyer_total_reviews: buyerReviews,
      buyer_total_purchases: parseInt(purchasesData[0].buyer_total_purchases) || 0,
      badge: {
        seller: getSellerBadge(sellerRating, sellerReviews),
        buyer: getBuyerBadge(buyerRating, buyerReviews)
      }
    });
  } catch (err) {
    handleNatError(res, err, 'GET /natmarket/users/:userId/reputation');
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

    // Verificación de OceanicEthernet eliminada - ya no se requiere vinculación

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

    // Consumo de internet eliminado - ya no se requiere saldo de internet

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

    // Verificación de OceanicEthernet eliminada - ya no se requiere vinculación

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

    // Consumo de internet eliminado - ya no se requiere saldo de internet

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
    const newUrls = (req.files || []).map(f => {
      // Si hay credenciales de Cloudinary, usar URL de nube
      if (CLOUD_NAME) {
        if (f.secure_url) return f.secure_url;
        if (f.url && f.url.startsWith('http')) return f.url;
        if (f.path && f.path.startsWith('http')) return f.path;

        // Fallback manual
        const publicId = f.filename || f.public_id;
        return `https://res.cloudinary.com/${CLOUD_NAME}/image/upload/${publicId}`;
      }
      // Local
      return `${host}/uploads/nat/${f.filename}`;
    });

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
      for (const pid of places) await client.query('INSERT INTO product_places (product_id, place_id) VALUES ($1,$2)', [prod.id, pid]);
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

// ===== ECOXION - QUICK CHAT =====
async function initEcoxionMessagesTable() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ecoxion_messages (
        id SERIAL PRIMARY KEY,
        sender_username VARCHAR(50) NOT NULL,
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('[ECOXION] Tabla ecoxion_messages inicializada');
  } catch (err) {
    if (!err.message.includes('already exists')) throw err;
  }
}

// Inicializar al arrancar
initEcoxionMessagesTable().catch(e => console.error('[ECOXION] Error init:', e));

app.post('/ecoxion/messages', async (req, res) => {
  try {
    const { username, message } = req.body;
    if (!username || !message) return res.status(400).json({ error: 'Faltan datos' });

    const { rows: [msg] } = await pool.query(
      `INSERT INTO ecoxion_messages (sender_username, message) VALUES ($1, $2) RETURNING *`,
      [username.trim().substring(0, 50), message]
    );
    res.json(msg);
  } catch (err) {
    if (err.code === '42P01') {
      await initEcoxionMessagesTable();
      // Reintentar...
    }
    res.status(500).json({ error: err.message });
  }
});

app.get('/ecoxion/messages', async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT * FROM ecoxion_messages ORDER BY created_at ASC LIMIT 100`);
    res.json(rows);
  } catch (err) {
    if (err.code === '42P01') {
      await initEcoxionMessagesTable();
      return res.json([]);
    }
    res.status(500).json({ error: err.message });
  }
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
app.get('/natmarket/chats/:user_id', async (req, res) => {
  try {
    const { user_id } = req.params;
    console.log(`[CHATS] Obteniendo chats para usuario: ${user_id} (como vendedor y comprador)`);

    // 1) Productos donde el usuario es vendedor y hay mensajes
    const { rows: sellerProductRows } = await pool.query(`
      SELECT DISTINCT p.id AS product_id, p.name AS product_name
      FROM products_nat p
      WHERE p.user_id = $1
        AND EXISTS (
          SELECT 1 FROM messages_nat m WHERE m.product_id = p.id
        )
    `, [user_id]);

    // 2) Productos donde el usuario participó como comprador (envió al menos un mensaje)
    const { rows: buyerProductRows } = await pool.query(`
      SELECT DISTINCT p.id AS product_id, p.name AS product_name
      FROM messages_nat m
      JOIN products_nat p ON p.id = m.product_id
      WHERE m.sender_id = $1
        AND p.user_id <> $1
    `, [user_id]);

    // Unificar y deduplicar productos
    const productMap = new Map();
    for (const r of sellerProductRows) productMap.set(r.product_id, r);
    for (const r of buyerProductRows) productMap.set(r.product_id, r);
    const productRows = Array.from(productMap.values());

    console.log(`[CHATS] Productos base encontrados (unificados): ${productRows.length}`);

    // Obtener detalles por producto
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

    console.log(`[CHATS] Encontrados ${rows.length} chats para usuario ${user_id}`);

    if (!rows || rows.length === 0) {
      console.log(`[CHATS] No hay chats, devolviendo array vacío`);
      return res.json([]);
    }

    // Agregar imagen de producto
    const chatsWithImages = await Promise.all(rows.map(async (chat) => {
      try {
        const { rows: imgRows } = await pool.query(
          'SELECT url FROM product_images_nat WHERE product_id = $1 ORDER BY created_at ASC LIMIT 1',
          [chat.product_id]
        );
        return {
          product_id: chat.product_id,
          product_name: chat.product_name,
          product_image: imgRows[0]?.url || null,
          last_message: chat.last_message || null,
          participants_count: chat.participants_count || 0,
          last_activity: chat.last_activity
        };
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

    return res.json(chatsWithImages);
  } catch (err) {
    console.error('[GET /natmarket/chats/:user_id] Error:', err);
    return res.json([]);
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
      WHERE r.product_id = $1
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

    // 2) Leer saldo y descontar
    let current = 0;
    const { cardNumber } = req.body;

    if (cardNumber) {
      // Nueva lógica: Descontar de la tarjeta
      const { rows: cardRows } = await client.query(
        'SELECT id FROM ocean_pay_cards WHERE card_number = $1 AND user_id = $2',
        [cardNumber, userIdStr]
      );

      if (cardRows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'Tarjeta no encontrada o no pertenece al usuario' });
      }

      const cardId = cardRows[0].id;
      const { rows: balanceRows } = await client.query(
        'SELECT amount FROM ocean_pay_card_balances WHERE card_id = $1 AND currency_type = \'ecorebits\' FOR UPDATE',
        [cardId]
      );

      current = parseFloat(balanceRows[0]?.amount || 0);
      if (current < plan.price) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: `Saldo insuficiente en la tarjeta. Faltan ${plan.price - current} ECB.` });
      }

      const next = current - plan.price;
      await client.query(
        'UPDATE ocean_pay_card_balances SET amount = $1 WHERE card_id = $2 AND currency_type = \'ecorebits\'',
        [next, cardId]
      );

      // Registrar tx en el historial de Ocean Pay
      await client.query(
        'INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda) VALUES ($1, $2, $3, $4, $5)',
        [userIdStr, `Suscripción: ${plan.name}`, -plan.price, 'EcoConsole Sub', 'ECOREBITS']
      );

    } else {
      // Lógica antigua: Descontar de user_currency (global)
      const { rows: curRows } = await client.query(
        `SELECT amount FROM user_currency WHERE user_id = $1 AND currency_type = 'ecocorebits' FOR UPDATE`,
        [userIdStr]
      );
      current = curRows[0]?.amount || 0;
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
    }

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

// Publicar posts programados de WildX cada minuto
cron.schedule('*/1 * * * *', async () => {
  try {
    await ensureWildXTables();
    await ensureWildXExtraColumns();
    await pool.query(
      `UPDATE wildx_posts
          SET status = 'published'
        WHERE status = 'scheduled'
          AND scheduled_at <= NOW()
          AND (deleted_at IS NULL)`
    );
  } catch (err) {
    console.error('Error publicando posts programados de WildX:', err);
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
      [userId, username, 'nopass', 0]
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

    // Verificación de OceanicEthernet eliminada - ya no se requiere vinculación

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
    const places = JSON.parse(req.body.places || '[]');
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

    // Consumo de internet eliminado - ya no se requiere saldo de internet

    // archivos subidos (imágenes y videos)
    const host = process.env.BACKEND_URL || `https://${req.get('host')}`;
    const imageFiles = (req.files && req.files.images) ? req.files.images : [];
    const videoFiles = (req.files && req.files.videos) ? req.files.videos : [];

    console.log('📦 [V2] Archivos recibidos:', req.files ? Object.keys(req.files) : 'Ninguno');
    if (imageFiles.length > 0) console.log('📸 [V2] Primer imagen:', imageFiles[0]);

    // imágenes
    const imageUrls = imageFiles.map(f => {
      // Si hay credenciales de Cloudinary, usar URL de nube
      if (CLOUD_NAME) {
        if (f.secure_url) return f.secure_url;
        if (f.url && f.url.startsWith('http')) return f.url;
        if (f.path && f.path.startsWith('http')) return f.path;

        // Fallback manual
        const publicId = f.filename || f.public_id;
        return `https://res.cloudinary.com/${CLOUD_NAME}/image/upload/${publicId}`;
      }
      // Local
      return `${host}/uploads/nat/${f.filename}`;
    });

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

      const videoUrls = videoFiles.map(f => {
        if (CLOUD_NAME) {
          if (f.secure_url) return f.secure_url;
          if (f.url && f.url.startsWith('http')) return f.url;
          if (f.path && f.path.startsWith('http')) return f.path;

          const publicId = f.filename || f.public_id;
          // Asumimos video si viene en el campo videos
          return `https://res.cloudinary.com/${CLOUD_NAME}/video/upload/${publicId}`;
        }
        return `${host}/uploads/nat/${f.filename}`;
      });

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
    const urls = req.files.map(f => {
      if (CLOUD_NAME) {
        if (f.secure_url) return f.secure_url;
        if (f.url && f.url.startsWith('http')) return f.url;
        if (f.path && f.path.startsWith('http')) return f.path;

        const publicId = f.filename || f.public_id;
        return `https://res.cloudinary.com/${CLOUD_NAME}/video/upload/${publicId}`;
      }
      return `${host}/uploads/nat/${f.filename}`;
    });
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
      } catch (_) { }
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
      } catch (_) { }
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

// Métricas por usuario (actividad básica)
app.get('/natmarket/users/:id/metrics', async (req, res) => {
  try {
    const { id } = req.params;

    // Info de usuario (strikes, bans y fecha de alta)
    const { rows: userRows } = await pool.query(
      'SELECT strikes, banned_until, ban_reason, created_at FROM users_nat WHERE id = $1',
      [id]
    );
    if (!userRows.length) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    const user = userRows[0];

    // Productos publicados, vendidos y vistas totales
    const { rows: prodRows } = await pool.query(`
      SELECT 
        COUNT(*)::int AS products_published,
        COUNT(*) FILTER (WHERE sold = true)::int AS products_sold,
        COALESCE(SUM(views), 0)::int AS views_total
      FROM products_nat
      WHERE user_id = $1
    `, [id]);
    const prod = prodRows[0] || { products_published: 0, products_sold: 0, views_total: 0 };

    // Chats como vendedor
    const { rows: sellerChatRows } = await pool.query(`
      SELECT COUNT(DISTINCT p.id)::int AS chats_as_seller
      FROM products_nat p
      WHERE p.user_id = $1
        AND EXISTS (SELECT 1 FROM messages_nat m WHERE m.product_id = p.id)
    `, [id]);
    const chatsAsSeller = sellerChatRows[0]?.chats_as_seller || 0;

    // Chats como comprador
    const { rows: buyerChatRows } = await pool.query(`
      SELECT COUNT(DISTINCT p.id)::int AS chats_as_buyer
      FROM messages_nat m
      JOIN products_nat p ON p.id = m.product_id
      WHERE m.sender_id = $1
        AND p.user_id <> $1
    `, [id]);
    const chatsAsBuyer = buyerChatRows[0]?.chats_as_buyer || 0;

    res.json({
      products_published: prod.products_published || 0,
      products_sold: prod.products_sold || 0,
      views_total: prod.views_total || 0,
      chats_as_seller: chatsAsSeller,
      chats_as_buyer: chatsAsBuyer,
      strikes: user.strikes || 0,
      banned_until: user.banned_until || null,
      ban_reason: user.ban_reason || null,
      member_since: user.created_at
    });
  } catch (err) {
    handleNatError(res, err, 'GET /natmarket/users/:id/metrics');
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

/* ========== SISTEMA DE REPUTACIÓN DUAL (VENDEDOR/COMPRADOR) ========== */

// Crear review para un usuario (como vendedor o comprador)
app.post('/natmarket/reviews', async (req, res) => {
  try {
    const { reviewer_id, reviewed_user_id, product_id, rating, comment, review_type, transaction_id } = req.body;

    // Validaciones
    if (!reviewer_id || !reviewed_user_id || !rating || !review_type) {
      return res.status(400).json({ error: 'Faltan datos requeridos' });
    }

    if (reviewer_id === reviewed_user_id) {
      return res.status(400).json({ error: 'No puedes dejarte una review a ti mismo' });
    }

    if (rating < 1 || rating > 5) {
      return res.status(400).json({ error: 'Rating debe estar entre 1 y 5' });
    }

    if (!['seller', 'buyer'].includes(review_type)) {
      return res.status(400).json({ error: 'review_type debe ser seller o buyer' });
    }

    // Crear tabla si no existe
    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_reviews_nat (
        id SERIAL PRIMARY KEY,
        reviewer_id INTEGER NOT NULL REFERENCES users_nat(id) ON DELETE CASCADE,
        reviewed_user_id INTEGER NOT NULL REFERENCES users_nat(id) ON DELETE CASCADE,
        product_id INTEGER REFERENCES products_nat(id) ON DELETE CASCADE,
        transaction_id INTEGER,
        rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
        comment TEXT,
        review_type VARCHAR(10) NOT NULL CHECK (review_type IN ('seller', 'buyer')),
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Insertar review
    const { rows: [review] } = await pool.query(
      `INSERT INTO user_reviews_nat 
       (reviewer_id, reviewed_user_id, product_id, transaction_id, rating, comment, review_type)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [reviewer_id, reviewed_user_id, product_id, transaction_id, rating, comment, review_type]
    );

    // Actualizar caché de estadísticas
    await updateUserReputationStats(reviewed_user_id);

    res.json({ success: true, review });
  } catch (err) {
    handleNatError(res, err, 'POST /natmarket/reviews');
  }
});

// Obtener reviews de un usuario
app.get('/natmarket/users/:userId/reviews', async (req, res) => {
  try {
    const { userId } = req.params;
    const { type } = req.query; // 'seller', 'buyer', o ambos si no se especifica

    let whereClause = 'WHERE r.reviewed_user_id = $1';
    const params = [userId];

    if (type === 'seller' || type === 'buyer') {
      whereClause += ' AND r.review_type = $2';
      params.push(type);
    }

    const { rows } = await pool.query(
      `SELECT r.*, 
              reviewer.username as reviewer_username,
              p.name as product_name
       FROM user_reviews_nat r
       JOIN users_nat reviewer ON r.reviewer_id = reviewer.id
       LEFT JOIN products_nat p ON r.product_id = p.id
       ${whereClause}
       ORDER BY r.created_at DESC`,
      params
    );

    res.json(rows);
  } catch (err) {
    // Si la tabla no existe, devolver array vacío
    if (err.code === '42P01') {
      return res.json([]);
    }
    handleNatError(res, err, 'GET /natmarket/users/:userId/reviews');
  }
});

// Obtener estadísticas de reputación de un usuario
app.get('/natmarket/users/:userId/reputation', async (req, res) => {
  try {
    const { userId } = req.params;

    // Intentar obtener del caché primero
    const { rows: cachedRows } = await pool.query(
      `SELECT * FROM user_reputation_stats_nat WHERE user_id = $1`,
      [userId]
    ).catch(() => ({ rows: [] }));

    if (cachedRows.length > 0) {
      const stats = cachedRows[0];
      const badge = calculateReputationBadge(stats);
      return res.json({ ...stats, badge });
    }

    // Si no hay caché, calcular en tiempo real
    const stats = await calculateUserReputationStats(userId);
    const badge = calculateReputationBadge(stats);

    res.json({ ...stats, badge });
  } catch (err) {
    // Si hay error, devolver stats vacías
    if (err.code === '42P01') {
      const emptyStats = {
        user_id: userId,
        seller_avg_rating: 0,
        seller_total_reviews: 0,
        seller_total_sales: 0,
        buyer_avg_rating: 0,
        buyer_total_reviews: 0,
        buyer_total_purchases: 0,
        badge: { seller: '🌱 Nuevo', buyer: '🌱 Nuevo' }
      };
      return res.json(emptyStats);
    }
    handleNatError(res, err, 'GET /natmarket/users/:userId/reputation');
  }
});

// Función auxiliar para calcular estadísticas de reputación
async function calculateUserReputationStats(userId) {
  try {
    // Estadísticas como vendedor
    const { rows: sellerRows } = await pool.query(
      `SELECT 
        COUNT(*) as total_reviews,
        COALESCE(AVG(rating), 0) as avg_rating,
        COUNT(DISTINCT product_id) as total_sales
       FROM user_reviews_nat
       WHERE reviewed_user_id = $1 AND review_type = 'seller'`,
      [userId]
    ).catch(() => ({ rows: [{ total_reviews: 0, avg_rating: 0, total_sales: 0 }] }));

    // Estadísticas como comprador
    const { rows: buyerRows } = await pool.query(
      `SELECT 
        COUNT(*) as total_reviews,
        COALESCE(AVG(rating), 0) as avg_rating
       FROM user_reviews_nat
       WHERE reviewed_user_id = $1 AND review_type = 'buyer'`,
      [userId]
    ).catch(() => ({ rows: [{ total_reviews: 0, avg_rating: 0 }] }));

    // Contar compras (productos marcados como vendidos con este usuario como comprador)
    const { rows: purchaseRows } = await pool.query(
      `SELECT COUNT(*) as total_purchases
       FROM products_nat
       WHERE buyer_id = $1 AND sold = true`,
      [userId]
    ).catch(() => ({ rows: [{ total_purchases: 0 }] }));

    return {
      user_id: userId,
      seller_avg_rating: parseFloat(sellerRows[0].avg_rating || 0).toFixed(1),
      seller_total_reviews: parseInt(sellerRows[0].total_reviews || 0),
      seller_total_sales: parseInt(sellerRows[0].total_sales || 0),
      buyer_avg_rating: parseFloat(buyerRows[0].avg_rating || 0).toFixed(1),
      buyer_total_reviews: parseInt(buyerRows[0].total_reviews || 0),
      buyer_total_purchases: parseInt(purchaseRows[0].total_purchases || 0)
    };
  } catch (err) {
    console.error('Error calculando estadísticas de reputación:', err);
    return {
      user_id: userId,
      seller_avg_rating: 0,
      seller_total_reviews: 0,
      seller_total_sales: 0,
      buyer_avg_rating: 0,
      buyer_total_reviews: 0,
      buyer_total_purchases: 0
    };
  }
}

// Función auxiliar para actualizar estadísticas en caché
async function updateUserReputationStats(userId) {
  try {
    // Crear tabla de caché si no existe
    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_reputation_stats_nat (
        user_id INTEGER PRIMARY KEY REFERENCES users_nat(id) ON DELETE CASCADE,
        seller_avg_rating DECIMAL(3,1) DEFAULT 0,
        seller_total_reviews INTEGER DEFAULT 0,
        seller_total_sales INTEGER DEFAULT 0,
        buyer_avg_rating DECIMAL(3,1) DEFAULT 0,
        buyer_total_reviews INTEGER DEFAULT 0,
        buyer_total_purchases INTEGER DEFAULT 0,
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `).catch(() => { });

    const stats = await calculateUserReputationStats(userId);

    await pool.query(
      `INSERT INTO user_reputation_stats_nat 
       (user_id, seller_avg_rating, seller_total_reviews, seller_total_sales, 
        buyer_avg_rating, buyer_total_reviews, buyer_total_purchases, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
       ON CONFLICT (user_id) 
       DO UPDATE SET 
         seller_avg_rating = $2,
         seller_total_reviews = $3,
         seller_total_sales = $4,
         buyer_avg_rating = $5,
         buyer_total_reviews = $6,
         buyer_total_purchases = $7,
         updated_at = NOW()`,
      [
        userId,
        stats.seller_avg_rating,
        stats.seller_total_reviews,
        stats.seller_total_sales,
        stats.buyer_avg_rating,
        stats.buyer_total_reviews,
        stats.buyer_total_purchases
      ]
    ).catch(() => { });
  } catch (err) {
    console.error('Error actualizando stats de reputación:', err);
  }
}

// Función para calcular badge según estadísticas
function calculateReputationBadge(stats) {
  const sellerBadge = getReputationBadge(
    stats.seller_total_reviews || 0,
    stats.seller_avg_rating || 0,
    'seller'
  );

  const buyerBadge = getReputationBadge(
    stats.buyer_total_reviews || 0,
    stats.buyer_avg_rating || 0,
    'buyer'
  );

  return {
    seller: sellerBadge,
    buyer: buyerBadge
  };
}

// Función para obtener el badge basado en transacciones y rating
function getReputationBadge(totalReviews, avgRating, type) {
  const typeLabel = type === 'seller' ? 'Vendedor' : 'Comprador';

  // Nuevo (menos de 5 reviews)
  if (totalReviews < 5) {
    return `🌱 ${typeLabel} Nuevo`;
  }

  // Confiable (5-20 reviews, 4.0+ rating)
  if (totalReviews >= 5 && totalReviews < 20 && avgRating >= 4.0) {
    return `🌿 ${typeLabel} Confiable`;
  }

  // Experimentado (20-50 reviews, 4.3+ rating)
  if (totalReviews >= 20 && totalReviews < 50 && avgRating >= 4.3) {
    return `🍀 ${typeLabel} Experimentado`;
  }

  // Experto (50-100 reviews, 4.5+ rating)
  if (totalReviews >= 50 && totalReviews < 100 && avgRating >= 4.5) {
    return `🌳 ${typeLabel} Experto`;
  }

  // Maestro (100-200 reviews, 4.7+ rating)
  if (totalReviews >= 100 && totalReviews < 200 && avgRating >= 4.7) {
    return `⭐ ${typeLabel} Maestro`;
  }

  // Leyenda (200+ reviews, 4.8+ rating)
  if (totalReviews >= 200 && avgRating >= 4.8) {
    return `👑 ${typeLabel} Leyenda`;
  }

  // Si tiene muchas reviews pero rating bajo
  if (totalReviews >= 20 && avgRating < 4.0) {
    return `⚠️ ${typeLabel} Regular`;
  }

  // Default: Básico
  return `🌱 ${typeLabel} Básico`;
}

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

// =================================================================
// NATUREPEDIA - ECOBOOKS ENDPOINTS
// =================================================================

// Obtener balance de EcoBooks
app.get('/naturepedia/ecobooks/balance', async (req, res) => {
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
    // Intentar obtener el balance existente
    const { rows } = await pool.query(`
      SELECT value FROM ocean_pay_metadata
      WHERE user_id = $1 AND key = 'ecobooks'
    `, [userId]);

    if (rows.length > 0) {
      // El registro existe, devolver el valor
      res.json({ ecobooks: parseInt(rows[0].value || '0') });
    } else {
      // No existe el registro, crearlo con 20 EB iniciales
      await pool.query(`
        INSERT INTO ocean_pay_metadata (user_id, key, value)
        VALUES ($1, 'ecobooks', '20')
        ON CONFLICT (user_id, key) DO NOTHING
      `, [userId]);
      res.json({ ecobooks: 20 });
    }
  } catch (e) {
    if (e.code === '42P01') {
      // Tabla no existe, devolver default
      res.json({ ecobooks: 20 });
    } else {
      console.error('Error obteniendo EcoBooks:', e);
      res.status(500).json({ error: 'Error interno' });
    }
  }
});

// Sincronizar EcoBooks desde Naturepedia
app.post('/naturepedia/ecobooks/sync', async (req, res) => {
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

  const { ecobooks } = req.body;
  if (ecobooks === undefined || ecobooks === null) {
    return res.status(400).json({ error: 'ecobooks requerido' });
  }

  const ecobooksValue = parseInt(ecobooks || '0');

  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ocean_pay_metadata (
        user_id INTEGER NOT NULL,
        key TEXT NOT NULL,
        value TEXT NOT NULL,
        PRIMARY KEY (user_id, key)
      )
    `);

    await pool.query(`
      INSERT INTO ocean_pay_metadata (user_id, key, value)
      VALUES ($1, 'ecobooks', $2)
      ON CONFLICT (user_id, key) 
      DO UPDATE SET value = $2
    `, [userId, ecobooksValue.toString()]);

    res.json({ success: true, ecobooks: ecobooksValue });
  } catch (e) {
    console.error('Error sincronizando EcoBooks:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Cambiar EcoBooks (ganar/gastar)
app.post('/naturepedia/ecobooks/change', async (req, res) => {
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

  const { amount, concepto = 'Operación', origen = 'Naturepedia' } = req.body;
  if (amount === undefined) {
    return res.status(400).json({ error: 'amount requerido' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Obtener saldo actual
    const { rows } = await client.query(`
      SELECT value FROM ocean_pay_metadata
      WHERE user_id = $1 AND key = 'ecobooks'
      FOR UPDATE
    `, [userId]);

    const current = parseInt(rows[0]?.value || '20'); // Default 20 EB
    const newBalance = current + parseInt(amount);

    if (newBalance < 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Saldo insuficiente de EcoBooks' });
    }

    // Actualizar saldo
    await client.query(`
      INSERT INTO ocean_pay_metadata (user_id, key, value)
      VALUES ($1, 'ecobooks', $2)
      ON CONFLICT (user_id, key) 
      DO UPDATE SET value = $2
    `, [userId, newBalance.toString()]);

    // Registrar transacción
    await client.query(`
      INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
      VALUES ($1, $2, $3, $4, 'EB')
      ON CONFLICT DO NOTHING
    `, [userId, concepto, amount, origen]).catch(async () => {
      await client.query(`
        INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen)
        VALUES ($1, $2, $3, $4)
      `, [userId, concepto, amount, origen]);
    });

    await client.query('COMMIT');
    res.json({ success: true, newBalance });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Error cambiando EcoBooks:', e);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

// =================================================================
// NUEVO ENDPOINT DE REGISTRO
// =================================================================

// Endpoint para registrar un nuevo usuario de Ocean Pay
app.post('/ocean-pay/register', async (req, res) => {
  const { username, password } = req.body;

  // 1. Validar datos de entrada
  if (!username || !password) {
    return res.status(400).json({ error: 'Faltan nombre de usuario o contraseña' });
  }

  const client = await pool.connect();
  try {
    // 2. Iniciar transacción
    await client.query('BEGIN');

    // 3. Generar hash de contraseña y ID único
    // Usamos el factor de coste 10, estándar en el proyecto
    const hashedPassword = await bcrypt.hash(password, 10);
    const userUniqueId = generateUserUniqueId();

    // 4. Insertar el nuevo usuario en la tabla principal
    // Asumiendo que tu tabla ocean_pay_users tiene columnas: id (SERIAL), username, pwd_hash, unique_id, aquabux, ecoxionums, appbux
    const opResult = await client.query(
      `INSERT INTO ocean_pay_users (username, pwd_hash, unique_id, aquabux, ecoxionums, appbux) 
       VALUES ($1, $2, $3, 0, 0, 0) RETURNING id`,
      [username, hashedPassword, userUniqueId]
    );
    const opUserId = opResult.rows[0].id;

    // 5. Generar tarjeta automática para el nuevo usuario
    const { cardNumber, cvv, expiryDate } = generateCardDetails();
    const cardResult = await client.query(
      `INSERT INTO ocean_pay_cards (user_id, card_number, cvv, expiry_date, is_primary, card_name) 
       VALUES ($1, $2, $3, $4, true, 'Tarjeta Principal') RETURNING id`,
      [opUserId, cardNumber, cvv, expiryDate]
    );
    const cardId = cardResult.rows[0].id;

    // 6. Inicializar saldos para la tarjeta
    const currencies = [
      { type: 'aquabux', amount: 0 },
      { type: 'ecoxionums', amount: 0 },
      { type: 'ecorebits', amount: 0 },
      { type: 'wildcredits', amount: 0 },
      { type: 'wildgems', amount: 0 },
      { type: 'appbux', amount: 0 },
      { type: 'tides', amount: 0 },
      { type: 'ecobooks', amount: 0 },
      { type: 'ecotokens', amount: 0 },
      { type: 'ecopower', amount: 100 }
    ];

    for (const curr of currencies) {
      await client.query(
        'INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount) VALUES ($1, $2, $3)',
        [cardId, curr.type, curr.amount]
      );
    }

    // 7. Confirmar la transacción
    await client.query('COMMIT');

    // 6. Respuesta exitosa (201 Created)
    res.status(201).json({
      success: true,
      userId: opUserId,
      username: username,
      message: '¡Registro completado! Bienvenido al océano de pagos.'
    });

  } catch (e) {
    // 7. Manejo de errores y rollback
    await client.query('ROLLBACK');

    // Error 23505: Violación de restricción única (ej. nombre de usuario duplicado)
    if (e.code === '23505') {
      return res.status(409).json({ error: 'Este nombre de usuario ya existe. ¡Qué original eres!' });
    }

    // Cualquier otro error se reporta como 500
    console.error('❌ Error en /ocean-pay/register:', e);
    res.status(500).json({ error: 'Error interno del servidor al registrar. Pide ayuda a los ingenieros marinos.' });

  } finally {
    // 8. Liberar el cliente de la pool
    client.release();
  }
});

// =================================================================
// EL RESTO DE TUS RUTAS CONTINÚA AQUÍ...
// =================================================================

/* ----------  LOGIN  ---------- */
app.post('/ocean-pay/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Faltan datos' });

  // Unimos ocean_pay_users con user_currency para obtener todo en una sola consulta
  const { rows } = await pool.query(`
    SELECT opu.id, opu.pwd_hash, opu.aquabux, opu.appbux, COALESCE(uc.amount, 0) as ecorebits
    FROM ocean_pay_users opu
    LEFT JOIN user_currency uc ON opu.id = uc.user_id AND uc.currency_type = 'ecocorebits'
    WHERE opu.username = $1
  `, [username]);

  if (rows.length === 0) return res.status(401).json({ error: 'Credenciales incorrectas' });

  const ok = await bcrypt.compare(password, rows[0].pwd_hash);
  if (!ok) return res.status(401).json({ error: 'Credenciales incorrectas' });

  const token = jwt.sign({ uid: rows[0].id, un: username }, process.env.STUDIO_SECRET, { expiresIn: '7d' });

  // Intentar obtener wildCredits, ecoxionums y ecobooks desde la tabla de metadatos
  let wildCredits = 0;
  let ecoxionums = 0;
  let ecobooks = 0;
  try {
    const { rows: metaRows } = await pool.query(`
      SELECT key, value FROM ocean_pay_metadata
      WHERE user_id = $1 AND key IN ('wildcredits', 'ecoxionums', 'ecobooks')
    `, [rows[0].id]);

    metaRows.forEach(row => {
      if (row.key === 'wildcredits') {
        wildCredits = parseInt(row.value || '0');
      } else if (row.key === 'ecoxionums') {
        ecoxionums = parseFloat(row.value || '0');
      } else if (row.key === 'ecobooks') {
        ecobooks = parseInt(row.value || '0');
      }
    });
  } catch (e) {
    // Si la tabla no existe, quedan en 0
  }

  // Obtener AppBux de la columna appbux
  const appbux = rows[0].appbux || 0;

  // 1. Asegurar que el usuario tenga al menos una tarjeta vinculada
  const { rows: existingCards } = await pool.query('SELECT id FROM ocean_pay_cards WHERE user_id = $1', [rows[0].id]);
  if (existingCards.length === 0) {
    const { cardNumber, cvv, expiryDate } = generateCardDetails ? generateCardDetails() : { cardNumber: '4000' + Math.random().toString().slice(2, 14), cvv: '123', expiryDate: '12/28' };
    await pool.query(
      'INSERT INTO ocean_pay_cards (user_id, card_number, cvv, expiry_date, is_primary, card_name) VALUES ($1, $2, $3, $4, true, $5)',
      [rows[0].id, cardNumber, cvv, expiryDate, 'Tarjeta Principal']
    );
  } else {
    // Asegurar que al menos una sea primaria
    await pool.query(`
      UPDATE ocean_pay_cards SET is_primary = true 
      WHERE id = (SELECT MIN(id) FROM ocean_pay_cards WHERE user_id = $1)
      AND NOT EXISTS (SELECT 1 FROM ocean_pay_cards WHERE user_id = $1 AND is_primary = true)
    `, [rows[0].id]);
  }

  // 2. Sincronización robusta de saldos legado (Cruce por Nombre de Usuario)
  await pool.query(`
    INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount)
    SELECT c.id, 'ecorebits', uc.amount
    FROM ocean_pay_cards c
    JOIN ocean_pay_users opu ON c.user_id = opu.id
    JOIN users u ON LOWER(u.username) = LOWER(opu.username)
    JOIN user_currency uc ON uc.user_id = u.id AND uc.currency_type = 'ecocorebits'
    WHERE opu.id = $1 AND c.is_primary = true AND uc.amount > 0
    ON CONFLICT (card_id, currency_type) DO UPDATE SET amount = EXCLUDED.amount WHERE ocean_pay_card_balances.amount = 0
  `, [rows[0].id]).catch(() => { });

  // 3. Obtener tarjetas del usuario CON sus saldos actualizados
  const { rows: cardRows } = await pool.query(
    `SELECT c.id, c.card_number, c.cvv, c.expiry_date, c.is_active, c.is_primary, c.card_name
     FROM ocean_pay_cards c WHERE c.user_id = $1`,
    [rows[0].id]
  );

  const cardsWithBalances = await Promise.all(cardRows.map(async (card) => {
    const { rows: balanceRows } = await pool.query(
      'SELECT currency_type, amount FROM ocean_pay_card_balances WHERE card_id = $1',
      [card.id]
    );
    const balances = {};
    balanceRows.forEach(b => balances[b.currency_type] = parseFloat(b.amount));
    return { ...card, balances };
  }));

  // CALCULAR BALANCE TOTAL (Sumatoria de todas las tarjetas)
  const totalEcorebits = cardsWithBalances.reduce((sum, card) => sum + parseFloat(card.balances?.ecorebits || 0), 0);
  const ecorebitsBalance = Math.max(totalEcorebits, parseFloat(rows[0].ecorebits || 0));

  const totalAquabux = cardsWithBalances.reduce((sum, card) => sum + parseFloat(card.balances?.aquabux || 0), 0);
  const aquabuxBalance = Math.max(totalAquabux, parseFloat(rows[0].aquabux || 0));

  res.json({
    token,
    user: {
      id: rows[0].id,
      username,
      aquabux: aquabuxBalance,
      cards: cardsWithBalances,
      ecorebits: {
        balance: parseFloat(ecorebitsBalance)
      }
    }
  });
});

/* ----------  MANAGE CARDS  ---------- */
app.post('/ocean-pay/cards/create', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token' });

  const client = await pool.connect();
  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    const userId = decoded.uid;

    const { rows: countRows } = await client.query('SELECT COUNT(*) FROM ocean_pay_cards WHERE user_id = $1', [userId]);
    if (parseInt(countRows[0].count) >= 2) {
      return res.status(400).json({ error: 'Ya tienes el máximo de 2 tarjetas permitidas.' });
    }

    await client.query('BEGIN');

    const { cardNumber, cvv, expiryDate } = generateCardDetails();
    const { rows } = await client.query(
      `INSERT INTO ocean_pay_cards (user_id, card_number, cvv, expiry_date, is_primary, card_name) 
       VALUES ($1, $2, $3, $4, false, 'Tarjeta Secundaria') RETURNING *`,
      [userId, cardNumber, cvv, expiryDate]
    );
    const newCardId = rows[0].id;

    // Inicializar saldos para la nueva tarjeta
    const currencies = [
      { type: 'aquabux', amount: 0 },
      { type: 'ecoxionums', amount: 0 },
      { type: 'ecorebits', amount: 0 },
      { type: 'wildcredits', amount: 0 },
      { type: 'wildgems', amount: 0 },
      { type: 'appbux', amount: 0 },
      { type: 'tides', amount: 0 },
      { type: 'ecobooks', amount: 0 },
      { type: 'ecotokens', amount: 0 },
      { type: 'ecopower', amount: 100 }
    ];

    for (const curr of currencies) {
      await client.query(
        'INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount) VALUES ($1, $2, $3)',
        [newCardId, curr.type, curr.amount]
      );
    }

    await client.query('COMMIT');

    // Obtener los saldos para la respuesta
    const { rows: balanceRows } = await pool.query(
      'SELECT currency_type, amount FROM ocean_pay_card_balances WHERE card_id = $1',
      [newCardId]
    );
    const balances = {};
    balanceRows.forEach(b => { balances[b.currency_type] = parseFloat(b.amount); });

    res.json({ success: true, card: { ...rows[0], balances } });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Error creando tarjeta:', e);
    res.status(500).json({ error: 'Error al crear tarjeta' });
  } finally {
    client.release();
  }
});

app.post('/ocean-pay/cards/renew', async (req, res) => {
  const { cardNumber } = req.body;
  if (!cardNumber) return res.status(400).json({ error: 'Falta número de tarjeta' });

  try {
    const now = new Date();
    const month = (now.getMonth() + 1).toString().padStart(2, '0');
    const year = (now.getFullYear() + 3).toString().slice(-2); // +3 años
    const newExpiry = `${month}/${year}`;

    const { rowCount } = await pool.query(
      'UPDATE ocean_pay_cards SET expiry_date = $1, is_active = true WHERE card_number = $2',
      [newExpiry, cardNumber]
    );

    if (rowCount === 0) return res.status(404).json({ error: 'Tarjeta no encontrada' });
    res.json({ success: true, newExpiry });
  } catch (e) {
    res.status(500).json({ error: 'Error al renovar tarjeta' });
  }
});

/* ----------  CARD BALANCE OPERATIONS  ---------- */
// Cambiar saldo de una tarjeta específica
app.post('/ocean-pay/cards/change-balance', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token' });

  const { cardNumber, currencyType, amount, concepto = 'Operación' } = req.body;

  if (!cardNumber || !currencyType || amount === undefined) {
    return res.status(400).json({ error: 'Faltan datos requeridos' });
  }

  const client = await pool.connect();
  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    const userId = decoded.uid;

    await client.query('BEGIN');

    // Verificar que la tarjeta pertenece al usuario
    const { rows: cardRows } = await client.query(
      'SELECT id FROM ocean_pay_cards WHERE card_number = $1 AND user_id = $2',
      [cardNumber, userId]
    );

    if (cardRows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Tarjeta no encontrada o no pertenece al usuario' });
    }

    const cardId = cardRows[0].id;

    // Obtener saldo actual
    const { rows: balanceRows } = await client.query(
      'SELECT amount FROM ocean_pay_card_balances WHERE card_id = $1 AND currency_type = $2',
      [cardId, currencyType]
    );

    const currentBalance = balanceRows[0]?.amount || 0;
    const newBalance = parseFloat(currentBalance) + parseFloat(amount);

    if (newBalance < 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Saldo insuficiente' });
    }

    // Actualizar o insertar saldo
    await client.query(
      `INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount) 
       VALUES ($1, $2, $3)
       ON CONFLICT (card_id, currency_type) 
       DO UPDATE SET amount = $3`,
      [cardId, currencyType, newBalance]
    );

    // Registrar transacción
    await client.query(
      'INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda) VALUES ($1, $2, $3, $4, $5)',
      [userId, concepto, amount, 'Card Transaction', currencyType.toUpperCase()]
    );

    await client.query('COMMIT');

    res.json({
      success: true,
      newBalance,
      cardNumber,
      currencyType
    });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Error cambiando saldo de tarjeta:', e);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

/* ----------  OCEAN CINEMAS REWARDS SYSTEM  ---------- */

// Verificar estado de recompensas de Ocean Cinemas
app.get('/ocean-cinemas/rewards-status', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token' });

  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    const userId = decoded.uid;

    // Crear tabla si no existe (asegurar existencia antes de consultar)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ocean_cinemas_rewards (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        reward_type TEXT NOT NULL,
        claimed_at TIMESTAMP DEFAULT NOW(),
        amount INTEGER NOT NULL
      );
      
      CREATE UNIQUE INDEX IF NOT EXISTS idx_rewards_daily 
      ON ocean_cinemas_rewards (user_id, reward_type, (claimed_at::date));
    `);

    // Verificar bono de bienvenida
    const { rows: welcomeRows } = await pool.query(
      `SELECT * FROM ocean_cinemas_rewards WHERE user_id = $1 AND reward_type = 'welcome'`,
      [userId]
    );

    // Verificar recompensa diaria
    const { rows: dailyRows } = await pool.query(
      `SELECT * FROM ocean_cinemas_rewards WHERE user_id = $1 AND reward_type = 'daily' AND DATE(claimed_at) = CURRENT_DATE`,
      [userId]
    );

    // Obtener racha de días
    const { rows: streakRows } = await pool.query(
      `SELECT DISTINCT DATE(claimed_at) as claim_date FROM ocean_cinemas_rewards 
       WHERE user_id = $1 AND reward_type = 'daily' 
       ORDER BY claim_date DESC LIMIT 8`,
      [userId]
    );

    // Calcular racha
    let streak = 0;
    if (streakRows.length > 0) {
      const today = new Date().toISOString().split('T')[0];
      const dates = streakRows.map(r => r.claim_date.toISOString().split('T')[0]);

      // Si reclamó hoy, cuenta como día 1 de la racha
      if (dates.includes(today)) {
        streak = 1;
        for (let i = 1; i < dates.length; i++) {
          const prev = new Date(dates[i - 1]);
          const curr = new Date(dates[i]);
          const diff = (prev - curr) / (1000 * 60 * 60 * 24);
          if (diff === 1) streak++;
          else break;
        }
      } else {
        // Verificar si reclamó ayer para mantener la racha
        const yesterday = new Date();
        yesterday.setDate(yesterday.getDate() - 1);
        const yestStr = yesterday.toISOString().split('T')[0];
        if (dates.includes(yestStr)) {
          streak = 1;
          for (let i = 0; i < dates.length - 1; i++) {
            const prev = new Date(dates[i]);
            const curr = new Date(dates[i + 1]);
            const diff = (prev - curr) / (1000 * 60 * 60 * 24);
            if (diff === 1) streak++;
            else break;
          }
        }
      }
    }

    res.json({
      welcome: {
        claimed: welcomeRows.length > 0,
        amount: 500
      },
      daily: {
        claimed: dailyRows.length > 0,
        baseAmount: 50,
        streakBonus: Math.min(streak, 7) * 15,
        totalAmount: 50 + Math.min(streak, 7) * 15,
        streak: Math.min(streak, 7)
      }
    });
  } catch (e) {
    console.error('Error verificando recompensas:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Reclamar bono de bienvenida (500 AquaBux)
app.post('/ocean-cinemas/claim-welcome', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token' });

  const { cardNumber } = req.body;
  if (!cardNumber) return res.status(400).json({ error: 'cardNumber requerido' });

  const client = await pool.connect();
  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    const userId = decoded.uid;

    await client.query('BEGIN');

    // Asegurar tabla (básico)
    await client.query(`
      CREATE TABLE IF NOT EXISTS ocean_cinemas_rewards (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        reward_type TEXT NOT NULL,
        claimed_at TIMESTAMP DEFAULT NOW(),
        amount INTEGER NOT NULL
      )
    `);

    // Verificar si ya reclamó
    const { rows: existingRows } = await client.query(
      `SELECT * FROM ocean_cinemas_rewards WHERE user_id = $1 AND reward_type = 'welcome' FOR UPDATE`,
      [userId]
    );

    if (existingRows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Ya reclamaste tu bono de bienvenida' });
    }

    // Verificar que la tarjeta pertenece al usuario
    const { rows: cardRows } = await client.query(
      'SELECT id FROM ocean_pay_cards WHERE card_number = $1 AND user_id = $2',
      [cardNumber, userId]
    );

    if (cardRows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Tarjeta no encontrada' });
    }

    const cardId = cardRows[0].id;
    const welcomeAmount = 500;

    // Agregar saldo a la tarjeta
    await client.query(
      `INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount) 
       VALUES ($1, 'aquabux', $2)
       ON CONFLICT (card_id, currency_type) 
       DO UPDATE SET amount = ocean_pay_card_balances.amount + $2`,
      [cardId, welcomeAmount]
    );

    // Registrar la recompensa
    await client.query(
      `INSERT INTO ocean_cinemas_rewards (user_id, reward_type, amount) VALUES ($1, 'welcome', $2)`,
      [userId, welcomeAmount]
    );

    // Registrar transacción
    await client.query(
      'INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda) VALUES ($1, $2, $3, $4, $5)',
      [userId, '🎬 Bono de Bienvenida - Ocean Cinemas', welcomeAmount, 'Ocean Cinemas', 'AQUABUX']
    );

    await client.query('COMMIT');
    res.json({ success: true, amount: welcomeAmount, message: '¡Bienvenido a Ocean Cinemas!' });

  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Error reclamando bono de bienvenida:', e);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

// Reclamar recompensa diaria
app.post('/ocean-cinemas/claim-daily', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token' });

  const { cardNumber, streak = 1 } = req.body;
  if (!cardNumber) return res.status(400).json({ error: 'cardNumber requerido' });

  const client = await pool.connect();
  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    const userId = decoded.uid;

    await client.query('BEGIN');

    // Asegurar tabla (básico)
    await client.query(`
      CREATE TABLE IF NOT EXISTS ocean_cinemas_rewards (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        reward_type TEXT NOT NULL,
        claimed_at TIMESTAMP DEFAULT NOW(),
        amount INTEGER NOT NULL
      )
    `);

    // Verificar si ya reclamó hoy
    const { rows: todayRows } = await client.query(
      `SELECT * FROM ocean_cinemas_rewards WHERE user_id = $1 AND reward_type = 'daily' AND DATE(claimed_at) = CURRENT_DATE`,
      [userId]
    );

    if (todayRows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Ya reclamaste tu recompensa diaria hoy' });
    }

    // Verificar que la tarjeta pertenece al usuario
    const { rows: cardRows } = await client.query(
      'SELECT id FROM ocean_pay_cards WHERE card_number = $1 AND user_id = $2',
      [cardNumber, userId]
    );

    if (cardRows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Tarjeta no encontrada' });
    }

    const cardId = cardRows[0].id;
    const baseAmount = 50;
    const streakBonus = Math.min(streak - 1, 6) * 15; // Max 7 días de racha
    const totalAmount = baseAmount + streakBonus;

    // Agregar saldo a la tarjeta
    await client.query(
      `INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount) 
       VALUES ($1, 'aquabux', $2)
       ON CONFLICT (card_id, currency_type) 
       DO UPDATE SET amount = ocean_pay_card_balances.amount + $2`,
      [cardId, totalAmount]
    );

    // Registrar la recompensa
    await client.query(
      `INSERT INTO ocean_cinemas_rewards (user_id, reward_type, amount) VALUES ($1, 'daily', $2)`,
      [userId, totalAmount]
    );

    // Registrar transacción
    await client.query(
      'INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda) VALUES ($1, $2, $3, $4, $5)',
      [userId, `🎬 Recompensa Diaria (Racha: ${streak} días) - Ocean Cinemas`, totalAmount, 'Ocean Cinemas', 'AQUABUX']
    );

    await client.query('COMMIT');
    res.json({ success: true, amount: totalAmount, streak, message: `¡Recompensa diaria reclamada!` });

  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Error reclamando recompensa diaria:', e);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

// Obtener saldo de una tarjeta específica
app.get('/ocean-pay/cards/:cardNumber/balance', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token' });

  const { cardNumber } = req.params;
  const { currencyType } = req.query;

  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    const userId = decoded.uid;

    // Verificar que la tarjeta pertenece al usuario
    const { rows: cardRows } = await pool.query(
      'SELECT id FROM ocean_pay_cards WHERE card_number = $1 AND user_id = $2',
      [cardNumber, userId]
    );

    if (cardRows.length === 0) {
      return res.status(404).json({ error: 'Tarjeta no encontrada' });
    }

    const cardId = cardRows[0].id;

    if (currencyType) {
      // Obtener saldo específico
      const { rows } = await pool.query(
        'SELECT amount FROM ocean_pay_card_balances WHERE card_id = $1 AND currency_type = $2',
        [cardId, currencyType]
      );
      res.json({ balance: rows[0]?.amount || 0, currencyType });
    } else {
      // Obtener todos los saldos
      const { rows } = await pool.query(
        'SELECT currency_type, amount FROM ocean_pay_card_balances WHERE card_id = $1',
        [cardId]
      );
      const balances = {};
      rows.forEach(r => { balances[r.currency_type] = parseFloat(r.amount); });
      res.json({ balances });
    }
  } catch (e) {
    res.status(500).json({ error: 'Error obteniendo saldo' });
  }
});

/* ----------  CURRENT BALANCE  ---------- */
app.get('/ocean-pay/balance/:userId', async (req, res) => {
  const { userId } = req.params;
  const { rows } = await pool.query('SELECT aquabux FROM ocean_pay_users WHERE id=$1', [userId]);
  if (rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
  res.json({ balance: rows[0].aquabux });
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
app.post('/ocean-pay/update-balance', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Sin token' });
  const { aquabux } = req.body;
  try {
    const payload = jwt.verify(auth.split(' ')[1], process.env.STUDIO_SECRET);

    // 1. Actualizar balance global
    await pool.query(
      'UPDATE ocean_pay_users SET aquabux = $1 WHERE id = $2',
      [aquabux, payload.uid]
    );

    // 2. Sincronizar con la tarjeta primaria si existe
    await pool.query(`
      UPDATE ocean_pay_card_balances SET amount = $1
      WHERE card_id = (SELECT id FROM ocean_pay_cards WHERE user_id = $2 AND is_primary = true)
      AND currency_type = 'aquabux'
    `, [aquabux, payload.uid]);

    res.json({ success: true, newBalance: aquabux });
  } catch (e) {
    console.error(e);
    res.status(401).json({ error: 'Token inválido o error de BD' });
  }
});

app.get('/ocean-pay/me', async (req, res) => {
  const auth = req.headers.authorization;            // Bearer <token>
  if (!auth) return res.status(401).json({ error: 'Sin token' });
  try {
    const payload = jwt.verify(auth.split(' ')[1], process.env.STUDIO_SECRET);
    const { rows } = await pool.query(
      'SELECT id, username, aquabux FROM ocean_pay_users WHERE id=$1',
      [payload.uid]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

    // Obtener tarjetas del usuario CON sus saldos
    const { rows: cardRows } = await pool.query(
      `SELECT c.id, c.card_number, c.cvv, c.expiry_date, c.is_active, c.is_primary, c.card_name
       FROM ocean_pay_cards c WHERE c.user_id = $1`,
      [payload.uid]
    );

    // Para cada tarjeta, obtener sus saldos
    const cardsWithBalances = await Promise.all(cardRows.map(async (card) => {
      const { rows: balanceRows } = await pool.query(
        'SELECT currency_type, amount FROM ocean_pay_card_balances WHERE card_id = $1',
        [card.id]
      );

      const balances = {};
      balanceRows.forEach(b => {
        balances[b.currency_type] = parseFloat(b.amount);
      });

      return {
        ...card,
        balances
      };
    }));

    // Obtener el balance de appbux solo de la tarjeta primaria (evita confusión con múltiples tarjetas)
    const primaryCard = cardsWithBalances.find(c => c.is_primary) || cardsWithBalances[0];
    const totalAppBux = primaryCard?.balances?.appbux || 0;

    res.json({ ...rows[0], appbux: totalAppBux, cards: cardsWithBalances });
  } catch (e) { res.status(401).json({ error: 'Token inválido' }); }
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
    // Ecoxionums se almacenan en ocean_pay_metadata
    const { rows } = await pool.query(
      `SELECT value FROM ocean_pay_metadata 
       WHERE user_id = $1 AND key = 'ecoxionums'`,
      [parseInt(userId)]
    );
    const ecoxionums = rows.length > 0 ? parseFloat(rows[0].value || '0') : 0;
    res.json({ ecoxionums });
  } catch (err) {
    console.error('❌ Error en /ocean-pay/ecoxionums/:userId', err);
    // Si la tabla no existe, devolver 0
    if (err.code === '42P01') {
      res.json({ ecoxionums: 0 });
    } else {
      res.status(500).json({ error: 'Error interno' });
    }
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
    console.error('❌ Error en /ocean-pay/appbux/:userId', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Cambiar balance de AppBux
app.post('/ocean-pay/appbux/change', async (req, res) => {
  const { userId, amount, concepto = 'Operación', origen = 'AllApp', cardId } = req.body;

  if (!userId || amount === undefined) {
    return res.status(400).json({ error: 'Faltan datos' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1. Update legacy user table total balance (keep it for compatibility but we won't return it)
    await client.query(
      'UPDATE ocean_pay_users SET appbux = appbux + $1 WHERE id = $2',
      [amount, userId]
    );

    // 2. Update specific card balance if provided, or primary card if not
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

    if (targetCardId) {
      await client.query(`
        INSERT INTO ocean_pay_card_balances (card_id, currency_type, amount)
        VALUES ($1, 'appbux', $2)
        ON CONFLICT (card_id, currency_type)
        DO UPDATE SET amount = ocean_pay_card_balances.amount + $2
      `, [targetCardId, amount]);
    }

    // 3. Register transaction
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

    // 4. Calculate balance of PRIMARY card (source of truth for display)
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
    console.error('❌ Error en /ocean-pay/appbux/change:', err);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

/* ----------  DELETE ACCOUNT  ---------- */
app.delete('/ocean-pay/delete-account', async (req, res) => {
  const auth = req.headers.authorization;
  const { userId, username } = req.body;

  if (!userId || !username) {
    return res.status(400).json({ error: 'Faltan datos' });
  }

  // Verificar token si está presente
  if (auth) {
    try {
      const token = auth.split(' ')[1];
      const payload = jwt.verify(token, process.env.STUDIO_SECRET);

      // Verificar que el token corresponda al usuario
      if (payload.uid !== userId) {
        return res.status(403).json({ error: 'No autorizado' });
      }
    } catch (e) {
      return res.status(401).json({ error: 'Token inválido' });
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

    console.log(`🗑️ Eliminando cuenta de Ocean Pay: ${username} (${userId})`);

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

    console.log(`✅ Cuenta eliminada exitosamente: ${username}`);
    res.json({ success: true, message: 'Cuenta eliminada permanentemente' });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error('❌ Error en /ocean-pay/delete-account:', err);
    res.status(500).json({ error: 'Error interno al eliminar la cuenta' });
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
        if (existingOpUser.rows.length === 0) throw new Error("Error crítico: usuario duplicado pero ID no recuperado.");
        opUserId = existingOpOpUser.rows[0].id;
      } else {
        throw e;
      }
    }

    // 3. [CORRECCIÓN 42P10] SELECT ANTES DE INSERTAR METADATA (EVITA ON CONFLICT)
    const existingMeta = await client.query(
      'SELECT 1 FROM ocean_pay_metadata WHERE user_id = $1 AND key = $2',
      [opUserId, 'internet_gb']
    );

    if (existingMeta.rows.length === 0) {
      await client.query(`
            INSERT INTO ocean_pay_metadata (user_id, key, value)
            VALUES ($1, 'internet_gb', '0')
        `, [opUserId]); // ✅ CORREGIDO: Usamos opUserId
    }


    // 4. Vincular usuario de OceanicEthernet con el de Ocean Pay
    // Nota: Aquí se mantiene ON CONFLICT porque la tabla oceanic_ethernet_user_links tiene un UNIQUE constraint.
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
      return res.status(409).json({ error: 'Este usuario ya existe. Si es tu cuenta, usa la opción "Iniciar sesión".' });
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
  let oeUserId; // Renombramos a oeUserId para mayor claridad
  try {
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    oeUserId = decoded.uid;
    oeUserId = parseInt(oeUserId) || oeUserId;
  } catch (e) {
    return res.status(401).json({ error: 'Token inválido' });
  }

  const { userId: paramUserId } = req.params;
  const paramUserIdNum = parseInt(paramUserId);

  // Verificar que el usuario del token coincida con el parámetro
  if (oeUserId !== paramUserIdNum) {
    return res.status(403).json({ error: 'No autorizado' });
  }

  // =========================================================================
  // 💡 CORRECCIÓN CRÍTICA (Error 23503: Foreign Key Violation)
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
      return res.json({ balance: 0 }); // El usuario no está vinculado, el balance es 0
    }

    opUserId = parseInt(linkResult.rows[0].external_user_id); // ✅ PARSE TO INTEGER

    // A partir de aquí, solo usamos opUserId para las consultas a ocean_pay_metadata

    // Intentar obtener desde metadata primero
    const { rows: metaRows } = await pool.query(`
      SELECT value FROM ocean_pay_metadata
      WHERE user_id = $1 AND key = 'internet_gb'
    `, [opUserId]); // ✅ CORREGIDO: Usando opUserId como INTEGER

    if (metaRows.length > 0) {
      const balance = parseFloat(metaRows[0].value || '0');
      return res.json({ balance });
    }

    // Si no existe en metadata, crear registro con 0
    await pool.query(`
      INSERT INTO ocean_pay_metadata (user_id, key, value)
      VALUES ($1, 'internet_gb', '0')
      ON CONFLICT (user_id, key) DO NOTHING
    `, [opUserId]); // ✅ CORREGIDO: Usando opUserId

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
    console.error('❌ report-error', e);
    res.status(500).json({ error: 'No se pudo guardar' });
  }
});

app.get('/admin/error-reports', async (req, res) => {
  const secret = req.headers['x-admin-secret'];
  if (secret !== process.env.STUDIO_SECRET) return res.status(401).json({ error: 'No autorizado' });

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
    const usernameToken = decoded.un || decoded.username;
    if (!usernameToken) return res.status(401).json({ message: 'Token inválido' });

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

    // 2. Sincronización robusta de saldos legacy (Cruce por Nombre de Usuario)
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
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    // Asegurar que userId sea un número (el id de ocean_pay_users es INTEGER)
    const rawId = decoded.uid || decoded.userId || decoded.id || decoded.user?.id;
    const userId = parseInt(rawId);

    if (!userId || isNaN(userId)) {
      console.error('Token decodificado:', decoded);
      return res.status(401).json({ error: 'Token inválido: falta userId. Campos disponibles: ' + Object.keys(decoded).join(', ') });
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
    // 🔑 TABLA FALTANTE 1: updates_ecoconsole (Ahora debería crearse)
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
    
    -- Tabla de productos pendientes de moderación (NatMarket)
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
    
    -- Tabla de mensajes pendientes de moderación (NatMarket)
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
    
    -- Tabla de métodos de envío recurrentes (NatMarket)
    CREATE TABLE IF NOT EXISTS user_shipping_methods (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users_nat(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
    
    -- Tablas de relación producto-lugar y producto-método (NatMarket)
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

  // 1. Ejecutar la creación de todas las tablas
  for (const q of tableQueries) {
    try {
      await pool.query(q);
    } catch (error) {
      console.error(`❌ Error al ejecutar query de creación de tabla: ${q.substring(0, 50)}...`, error);
      // Lanzamos el error solo si es crítico para que las tablas no se creen
      throw error;
    }
  }

  // =========================================================
  // 🔑 MIGRACIÓN CRÍTICA ocean_pay_metadata (Paso a paso)
  // =========================================================

  try {
    // 1. Verificar y Agregar columna user_id
    const columnCheck = await pool.query(`
        SELECT 1 
        FROM information_schema.columns 
        WHERE table_name = 'ocean_pay_metadata' AND column_name = 'user_id'
    `);

    if (columnCheck.rows.length === 0) {
      console.log('🔄 Agregando columna user_id a ocean_pay_metadata...');
      await pool.query(`ALTER TABLE ocean_pay_metadata ADD COLUMN user_id INTEGER`);
      console.log('✅ Columna user_id agregada.');
    }

    // 2. Verificar y Agregar la llave foránea
    const fkCheck = await pool.query(`
        SELECT 1 
        FROM pg_constraint 
        WHERE conrelid = 'ocean_pay_metadata'::regclass AND conname = 'ocean_pay_metadata_user_id_fkey'
    `);

    if (fkCheck.rows.length === 0) {
      console.log('🔄 Agregando FK a ocean_pay_metadata...');
      await pool.query(`
            ALTER TABLE ocean_pay_metadata 
            ADD CONSTRAINT ocean_pay_metadata_user_id_fkey 
            FOREIGN KEY (user_id) REFERENCES ocean_pay_users(id) ON DELETE CASCADE
        `);
      console.log('✅ FK ocean_pay_metadata_user_id_fkey agregada.');
    }

    // 3. Verificar y Agregar la restricción UNIQUE
    const uniqueCheck = await pool.query(`
        SELECT 1 
        FROM pg_constraint 
        WHERE conrelid = 'ocean_pay_metadata'::regclass AND conname = 'unique_user_key'
    `);

    if (uniqueCheck.rows.length === 0) {
      console.log('🔄 Agregando restricción UNIQUE a ocean_pay_metadata...');
      await pool.query(`
            ALTER TABLE ocean_pay_metadata 
            ADD CONSTRAINT unique_user_key UNIQUE (user_id, key)
        `);
      console.log('✅ Restricción UNIQUE agregada.');
    }

    console.log('✅ Migración de ocean_pay_metadata ejecutada de forma secuencial.');
  } catch (err) {
    console.warn('⚠️ Error al ejecutar migración secuencial de ocean_pay_metadata (puede ser un error menor si ya existe):', err.message);
  }

  // =========================================================
  // Bloque de migraciones restantes (Procedural SQL, ahora más aislado)
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
    console.log('✅ Migración de ocean_pay_users appbux ejecutada.');
  } catch (err) {
    console.warn('⚠️ Error al ejecutar migración de ocean_pay_users appbux:', err.message);
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
    console.log('✅ Migración de users_nat columnas ejecutada.');
  } catch (err) {
    console.warn('⚠️ Error al ejecutar migración de users_nat columnas:', err.message);
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
    console.log('✅ Migración de products_nat columnas ejecutada.');
  } catch (err) {
    console.warn('⚠️ Error al ejecutar migración de products_nat columnas:', err.message);
  }

  // Migración: Si la tabla command_limit_extensions existe con user_id TEXT, cambiarla a INTEGER (Ocean Pay Sync)
  try {
    const checkColumn = await pool.query(`
      SELECT data_type 
      FROM information_schema.columns 
      WHERE table_name = 'command_limit_extensions' 
      AND column_name = 'user_id'
    `);

    if (checkColumn.rows.length > 0 && checkColumn.rows[0].data_type === 'text') {
      console.log('🔄 Migrando command_limit_extensions: cambiando user_id de TEXT a INTEGER (Ocean Pay Sync)...');

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

      console.log('✅ Migración completada: user_id ahora es INTEGER y apunta a ocean_pay_users');
    }
  } catch (err) {
    if (!err.message.includes('relation "command_limit_extensions" does not exist')) {
      console.warn('⚠️ Error en migración de command_limit_extensions:', err.message);
    }
  }

  console.log("✅ Todas las tablas existen o fueron creadas");
}

function handleNatError(res, err, place = '') {
  console.error(`[NAT-MARKET ${place}]`, err?.message || err);

  // Detectar si el error es porque el usuario no existe (Foreign Key Violation)
  if (err?.code === '23503') {
    const detail = err.detail || '';
    // Si el error menciona user_id, sender_id, follower_id, etc. no presente en users_nat
    if (detail.includes('users_nat') || detail.includes('user_id') || detail.includes('sender_id')) {
      return res.status(401).json({
        error: 'Tu sesión ha expirado o el usuario no existe. Por favor inicia sesión nuevamente.',
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


// WildX – mini proyecto tipo X/Twitter
// Sirve la SPA desde carpeta WildX
app.get('/wildx', (_req, res) => {
  res.sendFile(join(__dirname, 'WildX', 'index.html'));
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

  // Asegurar columnas nuevas si la tabla ya existía
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
    const payload = jwt.verify(token, process.env.STUDIO_SECRET);
    return payload?.wid || null;
  } catch {
    return null;
  }
}

// Crear una notificación para un usuario de WildX
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
    console.error('Error creando notificación WildX:', err);
  }
}

// Asegurar columnas extra en wildx_posts (estado, programación, borrado)
async function ensureWildXExtraColumns() {
  try {
    await pool.query(`
      ALTER TABLE wildx_posts
      ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'published',
      ADD COLUMN IF NOT EXISTS scheduled_at TIMESTAMP NULL,
      ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP NULL
    `);
  } catch (err) {
    // Si la tabla aún no existe, se creará en ensureWildXTables
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
app.post('/wildx/api/register', async (req, res) => {
  try {
    await ensureWildXTables();
    const { username, password } = req.body || {};
    const uname = (username || '').toString().trim();
    const pwd = (password || '').toString();
    if (!uname || !pwd) return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
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
    console.error('Error en POST /wildx/api/register:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Login WildX
app.post('/wildx/api/login', async (req, res) => {
  try {
    await ensureWildXTables();
    const { username, password } = req.body || {};
    const uname = (username || '').toString().trim();
    const pwd = (password || '').toString();
    if (!uname || !pwd) return res.status(400).json({ error: 'Usuario y contraseña requeridos' });

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
    console.error('Error en POST /wildx/api/login:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Datos del usuario actual WildX (incluye stats básicas + verificación)
app.get('/wildx/api/me', async (req, res) => {
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
           SELECT tier, reason, started_at, valid_until
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
    if (user.username === 'Ocean and Wild Studios') {
      // Cuenta admin con verificación especial dorada+roja
      user.verify_tier = 'admin';
      user.verify_reason = user.verify_reason || 'Desarrollador de Juegos - +50 Proyectos aumentando en cantidad poco a poco.';
      user.verify_started_at = user.verify_started_at || user.created_at;
      const far = new Date();
      far.setFullYear(far.getFullYear() + 100);
      user.verify_valid_until = far;
    }

    res.json(user);
  } catch (err) {
    console.error('Error en GET /wildx/api/me:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Selección de post promocionado (uno a la vez)
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
    // Sin nuevas, elegir cualquiera (se mantiene el “mismo” en muchos casos)
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
            v.tier AS verify_tier
       FROM wildx_posts p
       LEFT JOIN LATERAL (
         SELECT tier
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
app.get('/wildx/api/posts', async (req, res) => {
  try {
    await ensureWildXTables();
    await ensureWildXExtraColumns();
    const wid = getWildXUserId(req) || 0;
    const postsPromise = pool.query(
      `SELECT p.id, p.user_id, p.username, p.content, p.created_at, p.parent_id,
              p.likes_count,
              (l.user_id IS NOT NULL) AS liked,
              v.tier AS verify_tier
         FROM wildx_posts p
         LEFT JOIN wildx_likes l
           ON l.post_id = p.id AND l.user_id = $1
         LEFT JOIN LATERAL (
           SELECT tier
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
    console.error('Error en GET /wildx/api/posts:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Posts propios (Perfil, solo publicados)
app.get('/wildx/api/my-posts', async (req, res) => {
  try {
    await ensureWildXTables();
    await ensureWildXExtraColumns();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Token requerido' });
    const { rows } = await pool.query(
      `SELECT p.id, p.user_id, p.username, p.content, p.created_at, p.parent_id,
              p.likes_count,
              (l.user_id IS NOT NULL) AS liked,
              v.tier AS verify_tier
         FROM wildx_posts p
         LEFT JOIN wildx_likes l
           ON l.post_id = p.id AND l.user_id = $1
         LEFT JOIN LATERAL (
           SELECT tier
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
    console.error('Error en GET /wildx/api/my-posts:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Suscripción a verificación azul usando WildCredits via Ocean Pay
app.post('/wildx/api/verify/blue/subscribe', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesión en WildX' });

    const { reason, oceanPayToken } = req.body || {};
    const r = (reason || '').toString().trim();
    if (!r || r.length < 5) {
      return res.status(400).json({ error: 'Explica brevemente el motivo de tu verificación' });
    }
    if (!oceanPayToken) {
      return res.status(400).json({ error: 'Token de Ocean Pay requerido' });
    }

    // Validar token de Ocean Pay y obtener user_id de ocean_pay_users
    let opUserId;
    try {
      const decoded = jwt.verify(oceanPayToken, process.env.STUDIO_SECRET);
      opUserId = parseInt(decoded.uid) || decoded.uid;
    } catch (e) {
      return res.status(401).json({ error: 'Token de Ocean Pay inválido' });
    }

    const DAILY_PRICE = 25; // WildCredits por día de verificación azul

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

      // Registrar transacción en Ocean Pay
      await client.query(
        `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
         VALUES ($1, $2, $3, $4, 'WC')`,
        [opUserId, 'Suscripción diaria WildX Blue', -DAILY_PRICE, 'WildX']
      ).catch(async () => {
        await client.query(
          `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen)
           VALUES ($1, $2, $3, $4)`,
          [opUserId, 'Suscripción diaria WildX Blue', -DAILY_PRICE, 'WildX']
        );
      });

      // Crear o extender verificación azul del usuario de WildX
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
                  valid_until = (CASE WHEN valid_until > NOW() THEN valid_until ELSE NOW() END) + INTERVAL '1 day'
            WHERE user_id = $1 AND tier = 'blue'
            RETURNING id, tier, reason, started_at, valid_until`,
          [wid, r]
        );
        verificationRow = upd[0];
      } else {
        const { rows: ins } = await client.query(
          `INSERT INTO wildx_verifications (user_id, tier, reason, started_at, valid_until)
           VALUES ($1, 'blue', $2, NOW(), NOW() + INTERVAL '1 day')
           RETURNING id, tier, reason, started_at, valid_until`,
          [wid, r]
        );
        verificationRow = ins[0];
      }

      await client.query('COMMIT');
      res.json({
        success: true,
        remainingWildcredits: newBalance,
        verification: {
          tier: verificationRow.tier,
          reason: verificationRow.reason,
          started_at: verificationRow.started_at,
          valid_until: verificationRow.valid_until
        }
      });
    } catch (err) {
      await client.query('ROLLBACK');
      console.error('Error en POST /wildx/api/verify/blue/subscribe:', err);
      res.status(500).json({ error: 'Error interno' });
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('Error en POST /wildx/api/verify/blue/subscribe:', err);
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

// Suscripción a verificación azul usando credenciales de Ocean Pay (WildCredits)
app.post('/wildx/api/verify/blue/subscribe-credentials', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesión en WildX' });

    const { reason, opUsername, opPassword } = req.body || {};
    const r = (reason || '').toString().trim();
    if (!r || r.length < 5) {
      return res.status(400).json({ error: 'Explica brevemente el motivo de tu verificación' });
    }

    const uname = (opUsername || '').toString().trim();
    const pwd = (opPassword || '').toString();
    if (!uname || !pwd) {
      return res.status(400).json({ error: 'Usuario y contraseña de Ocean Pay requeridos' });
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

    const DAILY_PRICE = 25; // WildCredits por día de verificación azul

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

      // Registrar transacción en Ocean Pay (aparece en Historial de Transacciones)
      await client.query(
        `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
         VALUES ($1, $2, $3, $4, 'WC')`,
        [opUserId, 'Suscripción diaria WildX Blue', -DAILY_PRICE, 'WildX']
      ).catch(async () => {
        await client.query(
          `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen)
           VALUES ($1, $2, $3, $4)`,
          [opUserId, 'Suscripción diaria WildX Blue', -DAILY_PRICE, 'WildX']
        );
      });

      // Crear o extender verificación azul del usuario de WildX
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
                  valid_until = (CASE WHEN valid_until > NOW() THEN valid_until ELSE NOW() END) + INTERVAL '1 day'
            WHERE user_id = $1 AND tier = 'blue'
            RETURNING id, tier, reason, started_at, valid_until`,
          [wid, r]
        );
        verificationRow = upd[0];
      } else {
        const { rows: ins } = await client.query(
          `INSERT INTO wildx_verifications (user_id, tier, reason, started_at, valid_until)
           VALUES ($1, 'blue', $2, NOW(), NOW() + INTERVAL '1 day')
           RETURNING id, tier, reason, started_at, valid_until`,
          [wid, r]
        );
        verificationRow = ins[0];
      }

      await client.query('COMMIT');
      res.json({
        success: true,
        remainingWildcredits: newBalance,
        verification: {
          tier: verificationRow.tier,
          reason: verificationRow.reason,
          started_at: verificationRow.started_at,
          valid_until: verificationRow.valid_until
        }
      });
    } catch (err) {
      await client.query('ROLLBACK');
      console.error('Error en POST /wildx/api/verify/blue/subscribe-credentials:', err);
      res.status(500).json({ error: 'Error interno' });
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('Error en POST /wildx/api/verify/blue/subscribe-credentials:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Obtener saldo de WildX Tokens (WXT)
app.get('/wildx/api/balance', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesión en WildX' });
    const { rows } = await pool.query(
      'SELECT wxt_balance FROM wildx_balances WHERE user_id = $1',
      [wid]
    );
    const balance = rows.length ? Number(rows[0].wxt_balance) : 0;
    res.json({ wxt: balance });
  } catch (err) {
    console.error('Error en GET /wildx/api/balance:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Resumen de propinas (WXT y equivalente en WildCredits)
app.get('/wildx/api/profile/tips-summary', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesión en WildX' });

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
        // Tabla aún no existe: simplemente devolver ceros
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
    console.error('Error en GET /wildx/api/profile/tips-summary:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Constante de conversión WildCredits → WXT (reducción para que cueste más promocionar)
const WXT_PER_WC = 0.2; // 1 WXT por cada 5 WildCredits

// Endpoint de test para acreditar WXT (solo Admin)
app.post('/wildx/api/wxt/grant', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesión en WildX' });
    if (!(await isWildXAdmin(wid))) {
      return res.status(403).json({ error: 'Solo el administrador puede otorgar WXT de prueba.' });
    }
    const { userId, amount } = req.body || {};
    const targetId = userId ? parseInt(userId, 10) : wid;
    const amt = Number(amount) || 0;
    if (!targetId || amt <= 0) {
      return res.status(400).json({ error: 'Parámetros inválidos' });
    }
    await pool.query(
      `INSERT INTO wildx_balances (user_id, wxt_balance)
         VALUES ($1, $2)
       ON CONFLICT (user_id)
       DO UPDATE SET wxt_balance = wildx_balances.wxt_balance + EXCLUDED.wxt_balance`,
      [targetId, amt]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Error en POST /wildx/api/wxt/grant:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Donar WildCredits a un post (se convierten a WXT para el autor)
app.post('/wildx/api/posts/:id/donate', async (req, res) => {
  const client = await pool.connect();
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) {
      client.release();
      return res.status(401).json({ error: 'Inicia sesión en WildX' });
    }

    const postId = parseInt(req.params.id, 10);
    if (!postId) {
      client.release();
      return res.status(400).json({ error: 'Post inválido' });
    }

    const { amount, oceanPayToken } = req.body || {};
    const wcAmount = parseInt(amount, 10);
    if (!Number.isFinite(wcAmount) || wcAmount <= 0) {
      client.release();
      return res.status(400).json({ error: 'Cantidad de WildCredits inválida' });
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
      const decoded = jwt.verify(oceanPayToken, process.env.STUDIO_SECRET);
      opUserId = parseInt(decoded.uid) || decoded.uid;
    } catch (e) {
      client.release();
      return res.status(401).json({ error: 'Token de Ocean Pay inválido' });
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

    // Registrar transacción en Ocean Pay (historial)
    await client.query(
      `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen, moneda)
       VALUES ($1, $2, $3, $4, 'WC')`,
      [opUserId, `Donación a @${toUsername} en WildX (convertido a WXT)`, -wcAmount, 'WildX']
    ).catch(async () => {
      await client.query(
        `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen)
         VALUES ($1, $2, $3, $4)`,
        [opUserId, `Donación a @${toUsername} en WildX (convertido a WXT)`, -wcAmount, 'WildX']
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

    // Registrar en historial de WXT
    await client.query(
      `INSERT INTO wildx_wxt_txs (from_user_id, to_user_id, post_id, amount_wxt)
       VALUES ($1, $2, $3, $4)`,
      [wid, toUserId, postId, amountWxt]
    );

    await client.query('COMMIT');
    client.release();

    // Notificación para el receptor (fuera de la transacción principal)
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
    console.error('Error en POST /wildx/api/posts/:id/donate:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Promocionar un post usando WXT
app.post('/wildx/api/posts/:id/promote', async (req, res) => {
  const client = await pool.connect();
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) {
      client.release();
      return res.status(401).json({ error: 'Inicia sesión en WildX' });
    }
    const postId = parseInt(req.params.id, 10);
    if (!postId) {
      client.release();
      return res.status(400).json({ error: 'Post inválido' });
    }
    const cost = Number(req.body?.cost || 10); // costo básico 10 WXT
    if (cost <= 0) {
      client.release();
      return res.status(400).json({ error: 'Costo inválido' });
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

    // Crear o actualizar promoción
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

    // Notificación para el propio usuario indicando que la promoción fue registrada
    createWildXNotification(wid, 'promotion', {
      postId,
      amount: cost
    }).catch(() => { });

    res.json({ success: true, remainingWxt: newBal });
  } catch (err) {
    await client.query('ROLLBACK');
    client.release();
    console.error('Error en POST /wildx/api/posts/:id/promote:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Solicitud de verificación dorada (empresas)
app.post('/wildx/api/verify/gold/request', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesión en WildX' });

    const { companyName, reason } = req.body || {};
    const r = (reason || '').toString().trim();
    const company = (companyName || '').toString().trim();
    if (!r || r.length < 10) {
      return res.status(400).json({ error: 'Explica mejor por qué tu empresa merece verificación dorada.' });
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
      return res.status(400).json({ error: 'Ya tienes una solicitud de verificación dorada pendiente.' });
    }

    const { rows } = await pool.query(
      'INSERT INTO wildx_gold_requests (user_id, company_name, reason) VALUES ($1,$2,$3) RETURNING id, status, created_at',
      [wid, company || null, r]
    );
    res.json({ success: true, request: rows[0] });
  } catch (err) {
    console.error('Error en POST /wildx/api/verify/gold/request:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Listado de solicitudes de verificación dorada (Admin)
app.get('/wildx/api/verify/gold/requests', async (req, res) => {
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
    console.error('Error en GET /wildx/api/verify/gold/requests:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Aprobar verificación dorada (Admin)
app.post('/wildx/api/verify/gold/requests/:id/approve', async (req, res) => {
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

    // Crear o actualizar verificación dorada (tier = 'gold') sin expiración cercana
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
    console.error('Error en POST /wildx/api/verify/gold/requests/:id/approve:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Rechazar verificación dorada (Admin)
app.post('/wildx/api/verify/gold/requests/:id/reject', async (req, res) => {
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
    console.error('Error en POST /wildx/api/verify/gold/requests/:id/reject:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Crear post (requiere login, admite programación)
app.post('/wildx/api/posts', async (req, res) => {
  try {
    await ensureWildXTables();
    await ensureWildXExtraColumns();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesión para publicar' });

    const content = (req.body?.content || '').toString().trim();
    const parentIdRaw = req.body?.parentId;
    const parentId = parentIdRaw ? parseInt(parentIdRaw, 10) : null;
    const scheduledAtRaw = req.body?.scheduledAt;

    if (!content) return res.status(400).json({ error: 'Contenido requerido' });

    // Límite de caracteres según verificación: base 280, +150% (700) si tiene verificación azul activa.
    // Los administradores de WildX no tienen límite de caracteres.
    const isAdmin = await isWildXAdmin(wid);
    let maxLen = 280;

    if (!isAdmin) {
      try {
        const { rows: verRows } = await pool.query(
          `SELECT tier, valid_until
             FROM wildx_verifications
            WHERE user_id = $1
              AND valid_until > NOW()
            ORDER BY started_at ASC
            LIMIT 1`,
          [wid]
        );
        if (verRows[0]?.tier === 'blue') {
          maxLen = 700; // 280 + 150% = 700
        }
      } catch (_) {
        // si falla la consulta, mantener límite base
      }

      if (content.length > maxLen) {
        const msg = maxLen === 280
          ? 'Máximo 280 caracteres'
          : 'Máximo 700 caracteres con tu verificación azul';
        return res.status(400).json({ error: msg });
      }
    }

    if (parentId && Number.isNaN(parentId)) {
      return res.status(400).json({ error: 'parentId inválido' });
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
    console.error('Error en POST /wildx/api/posts:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Toggle like en un post WildX
app.post('/wildx/api/posts/:id/like', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesión para dar like' });

    const postId = parseInt(req.params.id, 10);
    if (!postId) return res.status(400).json({ error: 'ID de post inválido' });

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
      console.error('Error en POST /wildx/api/posts/:id/like:', err);
      res.status(500).json({ error: 'Error interno' });
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('Error en POST /wildx/api/posts/:id/like:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Listar notificaciones del usuario actual
app.get('/wildx/api/notifications', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesión en WildX' });

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
    console.error('Error en GET /wildx/api/notifications:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Marcar notificaciones como leídas
app.post('/wildx/api/notifications/read', async (req, res) => {
  try {
    await ensureWildXTables();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesión en WildX' });

    await pool.query(
      `UPDATE wildx_notifications
          SET read_at = NOW()
        WHERE user_id = $1 AND read_at IS NULL`,
      [wid]
    );

    res.json({ success: true });
  } catch (err) {
    console.error('Error en POST /wildx/api/notifications/read:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Obtener hilo completo (post + respuestas recursivas)
app.get('/wildx/api/posts/:id/thread', async (req, res) => {
  try {
    await ensureWildXTables();
    await ensureWildXExtraColumns();
    const wid = getWildXUserId(req) || 0;
    const postId = parseInt(req.params.id, 10);
    if (!postId) return res.status(400).json({ error: 'ID de post inválido' });

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
              v.tier AS verify_tier
         FROM thread t
         LEFT JOIN wildx_likes l
           ON l.post_id = t.id AND l.user_id = $2
         LEFT JOIN LATERAL (
           SELECT tier
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
    console.error('Error en GET /wildx/api/posts/:id/thread:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Listar posts programados del usuario actual
app.get('/wildx/api/scheduled', async (req, res) => {
  try {
    await ensureWildXTables();
    await ensureWildXExtraColumns();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesión en WildX' });
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
    console.error('Error en GET /wildx/api/scheduled:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Eliminar post propio (borrado suave)
app.delete('/wildx/api/posts/:id', async (req, res) => {
  try {
    await ensureWildXTables();
    await ensureWildXExtraColumns();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesión en WildX' });
    const postId = parseInt(req.params.id, 10);
    if (!postId) return res.status(400).json({ error: 'ID de post inválido' });

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
    console.error('Error en DELETE /wildx/api/posts/:id:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Reportar post (visible para admins luego)
app.post('/wildx/api/posts/:id/report', async (req, res) => {
  try {
    await ensureWildXReportsTable();
    const wid = getWildXUserId(req);
    if (!wid) return res.status(401).json({ error: 'Inicia sesión en WildX' });
    const postId = parseInt(req.params.id, 10);
    if (!postId) return res.status(400).json({ error: 'ID de post inválido' });

    const reasonRaw = (req.body?.reason || '').toString().trim();
    if (!reasonRaw || reasonRaw.length < 10) {
      return res.status(400).json({ error: 'Describe mejor el motivo del reporte (mínimo 10 caracteres).' });
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
    console.error('Error en POST /wildx/api/posts/:id/report:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Listar reportes (Admin WildX)
app.get('/wildx/api/admin/post-reports', async (req, res) => {
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
    console.error('Error en GET /wildx/api/admin/post-reports:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Resolver reporte (Admin WildX)
app.post('/wildx/api/admin/post-reports/:id/decide', async (req, res) => {
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
    console.error('Error en POST /wildx/api/admin/post-reports/:id/decide:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// Servir favicon (evitar error 404)
app.get('/favicon.ico', (_req, res) => {
  res.status(204).end();
});

/* ===== WORD BATTLE - JUEGO DE PALABRAS ===== */

// Diccionario básico de palabras en español (se puede expandir)
const SPANISH_WORDS = new Set([
  'CASA', 'PERRO', 'GATO', 'MESA', 'SILLA', 'LIBRO', 'AGUA', 'FUEGO', 'TIERRA', 'AIRE',
  'SOL', 'LUNA', 'ESTRELLA', 'MAR', 'RIO', 'MONTE', 'VALLE', 'BOSQUE', 'CAMPO', 'CIUDAD',
  'AMOR', 'PAZ', 'GUERRA', 'VIDA', 'MUERTE', 'TIEMPO', 'ESPACIO', 'MUNDO', 'CIELO', 'INFIERNO',
  'HOMBRE', 'MUJER', 'NIÑO', 'NIÑA', 'PADRE', 'MADRE', 'HIJO', 'HIJA', 'HERMANO', 'HERMANA',
  'AMIGO', 'ENEMIGO', 'REY', 'REINA', 'PRINCIPE', 'PRINCESA', 'CABALLERO', 'DRAGON', 'MAGO', 'BRUJA',
  'ESPADA', 'ESCUDO', 'ARCO', 'FLECHA', 'LANZA', 'HACHA', 'MARTILLO', 'CUCHILLO', 'DAGA', 'BASTON',
  'ORO', 'PLATA', 'BRONCE', 'HIERRO', 'ACERO', 'DIAMANTE', 'RUBI', 'ESMERALDA', 'ZAFIRO', 'PERLA',
  'ROJO', 'AZUL', 'VERDE', 'AMARILLO', 'NEGRO', 'BLANCO', 'GRIS', 'ROSA', 'MORADO', 'NARANJA',
  'UNO', 'DOS', 'TRES', 'CUATRO', 'CINCO', 'SEIS', 'SIETE', 'OCHO', 'NUEVE', 'DIEZ',
  'LUNES', 'MARTES', 'MIERCOLES', 'JUEVES', 'VIERNES', 'SABADO', 'DOMINGO',
  'ENERO', 'FEBRERO', 'MARZO', 'ABRIL', 'MAYO', 'JUNIO', 'JULIO', 'AGOSTO', 'SEPTIEMBRE', 'OCTUBRE', 'NOVIEMBRE', 'DICIEMBRE',
  'PRIMAVERA', 'VERANO', 'OTOÑO', 'INVIERNO',
  'NORTE', 'SUR', 'ESTE', 'OESTE',
  'ARRIBA', 'ABAJO', 'IZQUIERDA', 'DERECHA', 'ADELANTE', 'ATRAS', 'DENTRO', 'FUERA',
  'GRANDE', 'PEQUEÑO', 'ALTO', 'BAJO', 'LARGO', 'CORTO', 'ANCHO', 'ESTRECHO', 'GORDO', 'FLACO',
  'BUENO', 'MALO', 'BONITO', 'FEO', 'NUEVO', 'VIEJO', 'JOVEN', 'ANCIANO', 'RICO', 'POBRE',
  'FELIZ', 'TRISTE', 'ALEGRE', 'ENOJADO', 'ASUSTADO', 'SORPRENDIDO', 'CANSADO', 'DESPIERTO',
  'COMER', 'BEBER', 'DORMIR', 'DESPERTAR', 'CAMINAR', 'CORRER', 'SALTAR', 'VOLAR', 'NADAR', 'BUCEAR',
  'HABLAR', 'ESCUCHAR', 'VER', 'MIRAR', 'OIR', 'OLER', 'TOCAR', 'SENTIR', 'PENSAR', 'SOÑAR',
  'LEER', 'ESCRIBIR', 'DIBUJAR', 'PINTAR', 'CANTAR', 'BAILAR', 'JUGAR', 'TRABAJAR', 'ESTUDIAR', 'APRENDER',
  'AMAR', 'ODIAR', 'QUERER', 'DESEAR', 'NECESITAR', 'PODER', 'DEBER', 'SABER', 'CONOCER', 'ENTENDER',
  'DAR', 'RECIBIR', 'TOMAR', 'DEJAR', 'PONER', 'QUITAR', 'TRAER', 'LLEVAR', 'BUSCAR', 'ENCONTRAR',
  'ABRIR', 'CERRAR', 'SUBIR', 'BAJAR', 'ENTRAR', 'SALIR', 'LLEGAR', 'PARTIR', 'VENIR', 'IR',
  'HACER', 'CREAR', 'DESTRUIR', 'CONSTRUIR', 'ROMPER', 'ARREGLAR', 'LIMPIAR', 'ENSUCIAR', 'ORDENAR', 'DESORDENAR',
  'COMPRAR', 'VENDER', 'PAGAR', 'COBRAR', 'GANAR', 'PERDER', 'AHORRAR', 'GASTAR', 'PRESTAR', 'DEVOLVER',
  'AYUDAR', 'PROTEGER', 'DEFENDER', 'ATACAR', 'LUCHAR', 'PELEAR', 'GANAR', 'PERDER', 'EMPATAR', 'RENDIR',
  'COMENZAR', 'TERMINAR', 'CONTINUAR', 'PARAR', 'SEGUIR', 'ESPERAR', 'LLEGAR', 'PARTIR', 'QUEDAR', 'VOLVER',
  'DECIR', 'CONTAR', 'PREGUNTAR', 'RESPONDER', 'EXPLICAR', 'ENSEÑAR', 'MOSTRAR', 'DEMOSTRAR', 'PROBAR', 'INTENTAR',
  'CREER', 'DUDAR', 'CONFIAR', 'DESCONFIAR', 'ESPERAR', 'TEMER', 'DESEAR', 'ANHELAR', 'SOÑAR', 'IMAGINAR',
  // Palabras comunes adicionales
  'PALABRA', 'LETRA', 'NUMERO', 'SIGNO', 'SIMBOLO', 'MARCA', 'SEÑAL', 'AVISO', 'MENSAJE', 'NOTA',
  'PAPEL', 'LAPIZ', 'PLUMA', 'TINTA', 'PINCEL', 'COLOR', 'DIBUJO', 'PINTURA', 'CUADRO', 'FOTO',
  'MUSICA', 'CANCION', 'MELODIA', 'RITMO', 'SONIDO', 'RUIDO', 'SILENCIO', 'VOZ', 'GRITO', 'SUSURRO',
  'COMIDA', 'BEBIDA', 'PAN', 'CARNE', 'PESCADO', 'FRUTA', 'VERDURA', 'LECHE', 'QUESO', 'HUEVO',
  'ARROZ', 'PASTA', 'SOPA', 'ENSALADA', 'POSTRE', 'DULCE', 'SALADO', 'AMARGO', 'ACIDO', 'PICANTE',
  'CAFE', 'TE', 'JUGO', 'VINO', 'CERVEZA', 'REFRESCO', 'HELADO', 'CHOCOLATE', 'CARAMELO', 'GALLETA',
  'ROPA', 'CAMISA', 'PANTALON', 'FALDA', 'VESTIDO', 'ZAPATO', 'BOTA', 'SANDALIA', 'SOMBRERO', 'GORRA',
  'ABRIGO', 'CHAQUETA', 'SUETER', 'BUFANDA', 'GUANTE', 'CALCETÍN', 'MEDIA', 'ROPA INTERIOR', 'PIJAMA', 'TRAJE',
  'COCHE', 'CARRO', 'AUTO', 'CAMION', 'AUTOBUS', 'TREN', 'AVION', 'BARCO', 'BICICLETA', 'MOTO',
  'CASA', 'EDIFICIO', 'TORRE', 'PUENTE', 'CALLE', 'AVENIDA', 'PLAZA', 'PARQUE', 'JARDIN', 'PATIO',
  'PUERTA', 'VENTANA', 'PARED', 'TECHO', 'SUELO', 'ESCALERA', 'ASCENSOR', 'BALCON', 'TERRAZA', 'SOTANO',
  'COCINA', 'BAÑO', 'SALA', 'COMEDOR', 'DORMITORIO', 'HABITACION', 'CUARTO', 'OFICINA', 'ESTUDIO', 'BIBLIOTECA',
  'ESCUELA', 'COLEGIO', 'UNIVERSIDAD', 'INSTITUTO', 'ACADEMIA', 'CLASE', 'AULA', 'SALON', 'LABORATORIO', 'GIMNASIO',
  'HOSPITAL', 'CLINICA', 'FARMACIA', 'DOCTOR', 'MEDICO', 'ENFERMERA', 'PACIENTE', 'MEDICINA', 'PASTILLA', 'INYECCION',
  'TIENDA', 'MERCADO', 'SUPERMERCADO', 'CENTRO COMERCIAL', 'ALMACEN', 'BODEGA', 'DEPOSITO', 'FABRICA', 'TALLER', 'EMPRESA',
  'BANCO', 'DINERO', 'MONEDA', 'BILLETE', 'TARJETA', 'CREDITO', 'DEBITO', 'CUENTA', 'AHORRO', 'PRESTAMO',
  'TRABAJO', 'EMPLEO', 'PROFESION', 'OFICIO', 'CARRERA', 'NEGOCIO', 'EMPRESA', 'COMPAÑIA', 'ORGANIZACION', 'INSTITUCION',
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
  'ABEJA', 'AVISPA', 'HORMIGA', 'MOSCA', 'MOSQUITO', 'MARIPOSA', 'POLILLA', 'LIBÉLULA', 'GRILLO', 'SALTAMONTES',
  'ARAÑA', 'ESCORPION', 'CIEMPIES', 'MILPIES', 'CARACOL', 'BABOSA', 'LOMBRIZ', 'SANGUIJUELA', 'GARRAPATA', 'PULGA',
  'PLANTA', 'ARBOL', 'FLOR', 'HIERBA', 'PASTO', 'CESPED', 'HOJA', 'RAMA', 'TRONCO', 'RAIZ',
  'ROSA', 'TULIPAN', 'MARGARITA', 'GIRASOL', 'ORQUIDEA', 'LIRIO', 'CLAVEL', 'JAZMIN', 'VIOLETA', 'AMAPOLA',
  'PINO', 'ROBLE', 'SAUCE', 'OLMO', 'HAYA', 'ABEDUL', 'CEREZO', 'MANZANO', 'NARANJO', 'LIMONERO',
  'FRUTA', 'MANZANA', 'PERA', 'NARANJA', 'LIMON', 'PLATANO', 'UVA', 'FRESA', 'CEREZA', 'MELOCOTON',
  'SANDIA', 'MELON', 'PIÑA', 'MANGO', 'PAPAYA', 'KIWI', 'COCO', 'AGUACATE', 'TOMATE', 'PEPINO',
  'ZANAHORIA', 'PAPA', 'CEBOLLA', 'AJO', 'LECHUGA', 'REPOLLO', 'BROCOLI', 'COLIFLOR', 'ESPARRAGO', 'APIO',
  'PIMIENTO', 'CHILE', 'BERENJENA', 'CALABAZA', 'CALABACIN', 'RABANO', 'NABO', 'REMOLACHA', 'ESPINACA', 'ACELGA',
  // Más palabras comunes
  'COSA', 'OBJETO', 'ARTICULO', 'ELEMENTO', 'PARTE', 'PIEZA', 'TROZO', 'PEDAZO', 'FRAGMENTO', 'PORCION',
  'TODO', 'NADA', 'ALGO', 'ALGUIEN', 'NADIE', 'TODOS', 'ALGUNOS', 'VARIOS', 'MUCHOS', 'POCOS',
  'MAS', 'MENOS', 'MUCHO', 'POCO', 'BASTANTE', 'DEMASIADO', 'SUFICIENTE', 'INSUFICIENTE', 'EXCESO', 'FALTA',
  'BIEN', 'MAL', 'MEJOR', 'PEOR', 'IGUAL', 'DIFERENTE', 'MISMO', 'OTRO', 'DISTINTO', 'SIMILAR',
  'AQUI', 'ALLI', 'AHI', 'CERCA', 'LEJOS', 'JUNTO', 'SEPARADO', 'UNIDO', 'DIVIDIDO', 'ROTO',
  'AHORA', 'ANTES', 'DESPUES', 'LUEGO', 'PRONTO', 'TARDE', 'TEMPRANO', 'SIEMPRE', 'NUNCA', 'JAMAS',
  'HOY', 'AYER', 'MAÑANA', 'ANTEAYER', 'PASADO MAÑANA', 'SEMANA', 'MES', 'AÑO', 'SIGLO', 'MILENIO',
  'MOMENTO', 'INSTANTE', 'SEGUNDO', 'MINUTO', 'HORA', 'DIA', 'NOCHE', 'MAÑANA', 'TARDE', 'MEDIODIA',
  'AMANECER', 'ATARDECER', 'ANOCHECER', 'MEDIANOCHE', 'ALBA', 'OCASO', 'CREPUSCULO', 'AURORA', 'PENUMBRA', 'SOMBRA',
  'LUZ', 'OSCURIDAD', 'BRILLO', 'RESPLANDOR', 'FULGOR', 'DESTELLO', 'RAYO', 'RELAMPAGO', 'TRUENO', 'TORMENTA',
  'LLUVIA', 'NIEVE', 'GRANIZO', 'NIEBLA', 'NEBLINA', 'ROCIO', 'ESCARCHA', 'HIELO', 'VAPOR', 'HUMO',
  'VIENTO', 'BRISA', 'HURACAN', 'TORNADO', 'CICLON', 'TIFON', 'TEMPESTAD', 'VENDAVAL', 'RAFAGA', 'SOPLO',
  'CALOR', 'FRIO', 'TEMPERATURA', 'CLIMA', 'TIEMPO', 'ESTACION', 'EPOCA', 'ERA', 'PERIODO', 'FASE',
  'PRINCIPIO', 'FIN', 'INICIO', 'FINAL', 'COMIENZO', 'TERMINO', 'ORIGEN', 'DESTINO', 'CAUSA', 'EFECTO',
  'RAZON', 'MOTIVO', 'PROPOSITO', 'OBJETIVO', 'META', 'FIN', 'INTENCION', 'DESEO', 'VOLUNTAD', 'DECISION',
  'IDEA', 'PENSAMIENTO', 'CONCEPTO', 'NOCION', 'OPINION', 'JUICIO', 'CRITERIO', 'PUNTO DE VISTA', 'PERSPECTIVA', 'ENFOQUE',
  'VERDAD', 'MENTIRA', 'REALIDAD', 'FICCION', 'FANTASIA', 'ILUSION', 'SUEÑO', 'PESADILLA', 'VISION', 'ALUCINACION',
  'PROBLEMA', 'SOLUCION', 'PREGUNTA', 'RESPUESTA', 'DUDA', 'CERTEZA', 'SEGURIDAD', 'INSEGURIDAD', 'CONFIANZA', 'DESCONFIANZA',
  'MIEDO', 'VALOR', 'VALENTIA', 'COBARDIA', 'CORAJE', 'AUDACIA', 'TEMERIDAD', 'PRUDENCIA', 'CAUTELA', 'PRECAUCION',
  'FUERZA', 'DEBILIDAD', 'PODER', 'IMPOTENCIA', 'CAPACIDAD', 'INCAPACIDAD', 'HABILIDAD', 'TORPEZA', 'DESTREZA', 'MAÑA',
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

// Generar código de sala único
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

    // Intentar generar un código único
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
      return res.status(500).json({ error: 'No se pudo generar código único' });
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
      return res.status(400).json({ error: 'Sala llena (máximo 6 jugadores)' });
    }

    if (players.some(p => p.userId === userId)) {
      return res.status(400).json({ error: 'Ya estás en esta sala' });
    }

    if (players.some(p => p.name === playerName)) {
      return res.status(400).json({ error: 'Este nombre ya está en uso' });
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

// Verificar si una palabra es válida
app.post('/api/word-battle/verify', async (req, res) => {
  try {
    const { word } = req.body;

    if (!word || typeof word !== 'string') {
      return res.json({ valid: false });
    }

    const upperWord = word.toUpperCase().trim();

    // Verificar si la palabra está en el diccionario
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

// ... (Aquí terminan todas tus rutas de app.get/app.post) ...

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
    const decoded = jwt.verify(token, process.env.STUDIO_SECRET);
    req.userId = parseInt(decoded.uid) || decoded.uid;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Token inválido' });
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

    console.log('✅ Tablas de EcoConsole aseguradas');
  } catch (err) {
    console.error('❌ Error creando tablas EcoConsole:', err);
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

      // Reset diario después de 24 horas
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

    // Registrar transacción
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

// Comprar más cuota con EcoCoreBits
app.post('/ecoconsole/purchase-quota', verifyEcoConsoleToken, async (req, res) => {
  const { pack } = req.body; // 'small' (25 por 100 ECB), 'large' (100 por 350 ECB)
  const userId = req.userId;

  const packs = {
    small: { quota: 25, cost: 100 },
    large: { quota: 100, cost: 350 }
  };

  const selectedPack = packs[pack];
  if (!selectedPack) {
    return res.status(400).json({ error: 'Pack inválido' });
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

    // Añadir cuota bonus
    await client.query(
      `INSERT INTO ecoconsole_quota (user_id, bonus_quota) 
       VALUES ($1, $2)
       ON CONFLICT (user_id) 
       DO UPDATE SET bonus_quota = ecoconsole_quota.bonus_quota + $2`,
      [userId, selectedPack.quota]
    );

    // Registrar transacción
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
    return res.status(400).json({ error: 'Datos inválidos' });
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

    // Registrar transacción
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
// FUNCIÓN PARA ASEGURAR TABLA DE MONEDAS DEL USUARIO (user_currency)
// =================================================================
async function ensureUserCurrencyTable() {
  try {
    console.log("Asegurando que la tabla 'user_currency' exista...");

    const client = await pool.connect();
    await client.query(`
      CREATE TABLE IF NOT EXISTS user_currency (
        id SERIAL PRIMARY KEY,
        
        -- Clave foránea para relacionarla con tu tabla de usuarios (ocean_pay_users)
        user_id INT NOT NULL REFERENCES ocean_pay_users(id) ON DELETE CASCADE, 
        
        currency_type VARCHAR(50) NOT NULL,
        amount BIGINT NOT NULL DEFAULT 0,
        
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        
        -- Clave única: Un usuario solo puede tener un registro por tipo de moneda.
        UNIQUE(user_id, currency_type) 
      );
    `);
    client.release();
    console.log("Tabla 'user_currency' asegurada y lista para nadar.");

  } catch (err) {
    console.error("❌ ERROR al asegurar la tabla 'user_currency':", err);
  }
}

// =================================================================
// CÓDIGO DE INICIALIZACIÓN (Al final de server.js)
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

// 💡 CORRECCIÓN 1: Llama a la limpieza DESPUÉS de asegurar que todas las tablas existen.
console.log("Iniciando limpieza de eventos antiguos...");
await cleanupOldEvents(); // <--- ASEGÚRATE DE QUE SE EJECUTA AQUÍ
console.log("Limpieza de eventos antiguos finalizada.");

// ========== FLORET SHOP TABLES ==========
await pool.query(`
  CREATE TABLE IF NOT EXISTS floret_users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100),
    password TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
  )
`).catch(() => console.log('⚠️ Tabla floret_users ya existe'));

await pool.query(`
  CREATE TABLE IF NOT EXISTS floret_products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    price DECIMAL(12,2) NOT NULL,
    condition VARCHAR(50) DEFAULT 'Nuevo',
    images TEXT[] DEFAULT '{}',
    requires_size BOOLEAN DEFAULT FALSE,
    sizes TEXT[] DEFAULT '{}',
    measurements VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW()
  )
`).catch(() => console.log('⚠️ Tabla floret_products ya existe'));

console.log('🌸 Tablas de Floret Shop verificadas');

const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 API corriendo en https://owsdatabase.onrender.com/`);
  console.log(`� Puerto:  ${PORT}`);
  console.log(`🎮 Sistema de Quiz Kahoot activo`);

  // Ejecutar migraciones una sola vez
  if (!migrationExecuted) {
    migrationExecuted = true;
    setTimeout(() => {
      notifyUnlinkedUsers();
    }, 5000); // Esperar 5 segundos después del inicio
  }
});