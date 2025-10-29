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

// URL FOR THIS DATABASE: https://owsdatabase.onrender.com
dotenv.config();

/* ===== NAT-MARKET VARS ===== */
const uploadDir = path.join(process.cwd(), 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

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

// Keep the existing status page route
app.get('/status', (_req, res) =>
  res.sendFile(join(__dirname, 'Ocean and Wild Studios Status', 'index.html'))
);



const FORBIDDEN = [
  /\bcoca[ií]na\b/i, /\bporro\b/i, /\bmari[h]uana\b/i,
  /\bextasi[s]?\b/i, /\blsd\b/i, /\bmdma\b/i,
  /\bput[ao]s?\b/i, /\bpendej[ao]s?\b/i
];

function containsInappropriate(text = '') {
  const t = text.toLowerCase();
  return FORBIDDEN.some(rx => rx.test(t));
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
  const { rows } = await pool.query(`SELECT installed FROM installed_extensions WHERE user_id=$1`, [userId]);
  res.json(rows[0]?.installed || {});
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
    const { rows } = await pool.query(
      'INSERT INTO users_nat (username, password) VALUES ($1,$2) RETURNING id, username',
      [username, hashed]
    );
    res.json(rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'Usuario ya existe' });
    handleNatError(res, err, '/natmarket/register');
  }
});

app.post('/natmarket/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username y password requeridos' });
    const { rows } = await pool.query('SELECT id, username, password FROM users_nat WHERE username=$1', [username]);
    if (rows.length === 0) return res.status(401).json({ error: 'Usuario no encontrado' });
    const ok = await bcrypt.compare(password, rows[0].password);
    if (!ok) return res.status(401).json({ error: 'Contraseña incorrecta' });
    res.json({ id: rows[0].id, username: rows[0].username });
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
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) return res.status(400).json({ error: 'Faltan contraseñas' });
    const { rows } = await pool.query('SELECT password FROM users_nat WHERE id=$1', [id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
    const ok = await bcrypt.compare(oldPassword, rows[0].password);
    if (!ok) return res.status(401).json({ error: 'Contraseña actual incorrecta' });
    const hashed = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users_nat SET password=$1 WHERE id=$2', [hashed, id]);
    res.json({ success: true, message: 'Contraseña actualizada' });
  } catch (err) {
    handleNatError(res, err, 'PUT /natmarket/users/:id/password');
  }
});

// PRODUCTS
app.post('/natmarket/products', upload.array('images', 10), async (req, res) => {
  try {
    const { user_id, name, description = null, price = null, contact_number = null } = req.body;
    if (!user_id || !name) return res.status(400).json({ error: 'user_id y name son requeridos' });
    const { rows: [product] } = await pool.query(
      'INSERT INTO products_nat (user_id, name, description, price, contact_number) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [user_id, name, description, price, contact_number]
    );
    const host = process.env.BACKEND_URL || `https://${req.get('host')}`;
    const urls = (req.files || []).map(f => `${host}/uploads/nat/${f.filename}`);
    for (const url of urls) await pool.query('INSERT INTO product_images_nat (product_id, url) VALUES ($1,$2)', [product.id, url]);
    const { rows: imgs } = await pool.query('SELECT url FROM product_images_nat WHERE product_id=$1 ORDER BY created_at ASC', [product.id]);
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
      ORDER BY p.created_at DESC
    `);
    const products = await Promise.all(rows.map(async p => {
      const { rows: imgs } = await pool.query('SELECT url FROM product_images_nat WHERE product_id=$1 ORDER BY created_at ASC', [p.id]);
      return { ...p, image_urls: imgs.map(i => i.url) };
    }));
    res.json(products);
  } catch (err) {
    handleNatError(res, err, 'GET /natmarket/products');
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
    const { rows: [deleted] } = await pool.query('DELETE FROM products_nat WHERE id=$1 RETURNING *', [id]);
    res.json({ success: true, deleted });
  } catch (err) {
    handleNatError(res, err, 'DELETE /natmarket/products/:id');
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
  const { sender_id, product_id, message } = req.body;
  if (!sender_id || !product_id || !message) return res.status(400).json({ error: 'Faltan datos' });

  const bad = containsInappropriate(message);
  if (bad) {
    await pool.query(
      `INSERT INTO messages_pending (product_id, sender_id, message)
       VALUES ($1,$2,$3)`,
      [product_id, sender_id, message]
    );
    await notifyModerator('message', product_id, message, sender_id);
    return res.status(202).json({
      warning: 'Tu mensaje está en revisión por contenido potencialmente inapropiado.'
    });
  }
  // si está OK, guardar directamente
  const { rows: [msg] } = await pool.query(
    `INSERT INTO messages_nat (sender_id, product_id, message) VALUES ($1,$2,$3) RETURNING *`,
    [sender_id, product_id, message]
  );
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

  const { pending_id, approve } = req.body;
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
      for (const pid of p.places)  await client.query('INSERT INTO product_places (product_id, place_id) VALUES ($1,$2)', [prod.id, pid]);
      for (const mid of p.methods) await client.query('INSERT INTO product_shipping_methods (product_id, shipping_method_id) VALUES ($1,$2)', [prod.id, mid]);
    } else {
      // rechazar → historial en perfil
      await client.query(
        'INSERT INTO products_rejected (user_id, name, reason) VALUES ($1,$2,$3)',
        [p.user_id, p.name, 'Contenido inapropiado']
      );
    }
    await client.query('DELETE FROM products_pending WHERE id = $1', [pending_id]);
    await client.query('COMMIT');
    res.json({ ok: true });
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
    const { rows } = await pool.query(`
      SELECT m.*, u.username AS sender_username
      FROM messages_nat m
      JOIN users_nat u ON m.sender_id = u.id
      WHERE m.product_id = $1
      ORDER BY m.created_at ASC
    `, [product_id]);
    res.json(rows);
  } catch (err) {
    handleNatError(res, err, 'GET /natmarket/messages/:product_id');
  }
});

// RATINGS
app.post('/natmarket/rate-product', async (req, res) => {
  try {
    const { product_id, rater_user_id, rating, comment } = req.body;
    if (!product_id || !rater_user_id || !rating) return res.status(400).json({ error: 'Faltan parámetros' });
    const { rows } = await pool.query('SELECT user_id FROM products_nat WHERE id=$1', [product_id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Producto no encontrado' });
    await pool.query(
      `INSERT INTO user_ratings_nat (rated_user_id, rater_user_id, rating, comment, product_id, type)
       VALUES ($1,$2,$3,$4,$5,'product')`,
      [rows[0].user_id, rater_user_id, rating, comment, product_id]
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
  const plan = PLANS.find(p => p.id === planId);
  if (!plan) return res.status(400).json({ error: "Plan inválido" });

  const now = new Date();
  const end = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1) Verificar si tiene suscripción activa y si es upgrade
    const { rows: activeSub } = await client.query(
      `SELECT * FROM subs WHERE user_id = $1 AND active = true AND ends_at > NOW()`,
      [userId]
    );
    if (activeSub.length > 0) {
      const currentPlan = PLANS.find(p => p.id === activeSub[0].plan_id);
      if (currentPlan && currentPlan.price >= plan.price) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: "Solo puedes suscribirte a un plan superior." });
      }
    }

    // 2) Leer saldo EcoCoreBits desde user_currency
    const { rows: curRows } = await client.query(
      `SELECT amount FROM user_currency WHERE user_id = $1 AND currency_type = 'ecocorebits' FOR UPDATE`,
      [userId]
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
      [userId, next]
    );

    // 3) Registrar transacción en EcoCoreBits
    await client.query(
      `INSERT INTO ecocore_txs (user_id, concepto, monto, origen)
       VALUES ($1, $2, $3, $4)`,
      [userId, 'Suscripción Plan Pro (EcoConsole)', -plan.price, 'EcoConsole']
    );

    // 4) Cerrar suscripción anterior (si existe)
    await client.query(
      `UPDATE subs SET active = false, ends_at = NOW() WHERE user_id = $1 AND active = true`,
      [userId]
    );

    // 5) Crear nueva suscripción
    const { rows } = await client.query(
      `INSERT INTO subs (user_id, plan_id, plan_name, start, ends_at, active)
       VALUES ($1, $2, $3, $4, $5, true) RETURNING *`,
      [userId, plan.id, plan.name, now, end]
    );

    // 6) Ticket/recibo en Ocean Pay (historial)
    await client.query(
      `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen)
       VALUES ($1, $2, $3, $4)`,
      [userId, 'Suscripción Plan Pro (EcoConsole)', 0, 'EcoConsole']
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
app.post('/natmarket/products/v2', upload.array('images', 10), async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { user_id, name, description, price, contact_number } = req.body;

    // ➜ parsear arrays
    const places  = JSON.parse(req.body.places || '[]');
    const methods = JSON.parse(req.body.methods || '[]');

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
      `INSERT INTO products_nat (user_id, name, description, price, contact_number)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [user_id, name, description, price ? parseFloat(price) : null, contact_number || null]
    );

    // imágenes
    const host = process.env.BACKEND_URL || `https://${req.get('host')}`;
    const urls = (req.files || []).map(f => `${host}/uploads/nat/${f.filename}`);
    for (const url of urls) {
      await client.query('INSERT INTO product_images_nat (product_id, url) VALUES ($1,$2)', [product.id, url]);
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

    await client.query('COMMIT');
    res.json({ success: true, product });
  } catch (err) {
    await client.query('ROLLBACK');
    handleNatError(res, err, 'POST /products/v2');
  } finally {
    client.release();
  }
});

/* ---------- RESTAURAR CONTRASEÑA ---------- */
app.post('/natmarket/reset-password', async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Usuario requerido' });

  try {
    // 1. Buscar usuario
    const { rows } = await pool.query(
      'SELECT id FROM users_nat WHERE username = $1',
      [username]
    );

    if (rows.length === 0) {
      // No revelamos si existe o no
      return res.json({
        message: 'Si el usuario existe, la nueva contraseña se mostrará abajo.'
      });
    }

    const userId = rows[0].id;

    // 2. Generar contraseña aleatoria
    const newPass = Math.random().toString(36).slice(-8); // 8 caracteres
    const hashed  = await bcrypt.hash(newPass, 10);

    // 3. Actualizar
    await pool.query(
      'UPDATE users_nat SET password = $1 WHERE id = $2',
      [hashed, userId]
    );

    // 4. Mostramos la nueva clave al cliente
    res.json({
      success: true,
      message: 'Contraseña restablecida. Guárdala bien.',
      newPassword: newPass   // <-- se muestra solo una vez
    });
  } catch (err) {
    handleNatError(res, err, 'POST /reset-password');
  }
});


/* ---------- NOVEDAD DESTACADA ---------- */
app.get('/api/featured-update', async (_req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT version, news, date
       FROM updates_natmarket
       ORDER BY date DESC
       LIMIT 1`
    );
    if (!rows.length) return res.json(null);
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json(null);
  }
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
  const userId = req.headers['x-user-id']; // viene del front (session)
  if (!userId) return res.status(400).json({ error: 'Falta x-user-id' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1. ¿ya vio?
    const { rows } = await client.query(
      `SELECT 1 FROM product_views_unique
       WHERE user_id = $1 AND product_id = $2`,
      [userId, id]
    );
    if (rows.length) {               // ya contó -> solo devolver total
      const { rows: total } = await client.query(
        'SELECT views FROM products_nat WHERE id = $1', [id]
      );
      await client.query('COMMIT');
      return res.json({ views: total[0].views, firstTime: false });
    }

    // 2. insertar par
    await client.query(
      `INSERT INTO product_views_unique(user_id, product_id) VALUES ($1,$2)`,
      [userId, id]
    );

    // 3. incrementar contador
    const { rows: total } = await client.query(
      `UPDATE products_nat
         SET views = views + 1
       WHERE id = $1
       RETURNING views`,
      [id]
    );
    await client.query('COMMIT');
    res.json({ views: total[0].views, firstTime: true });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[VIEW-UNIQUE]', err);
    res.status(500).json({ error: 'Error interno' });
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
  `INSERT INTO ocean_pay_users (username, pwd_hash, aquabux, ecoxionums)
   VALUES ($1, $2, 10000, 50000)
   RETURNING id, username, aquabux, ecoxionums`,
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
    SELECT opu.id, opu.pwd_hash, opu.aquabux, opu.ecoxionums, COALESCE(uc.amount, 0) as ecorebits
    FROM ocean_pay_users opu
    LEFT JOIN user_currency uc ON opu.id::text = uc.user_id AND uc.currency_type = 'ecocorebits'
    WHERE opu.username = $1
  `,[username]);

  if(rows.length===0) return res.status(401).json({error:'Credenciales incorrectas'});
  
  const ok=await bcrypt.compare(password,rows[0].pwd_hash);
  if(!ok) return res.status(401).json({error:'Credenciales incorrectas'});
  
  const token=jwt.sign({uid:rows[0].id,un:username},process.env.STUDIO_SECRET,{expiresIn:'7d'});
  res.json({
  token,
  user: {
    id: rows[0].id,
    username,
    aquabux: rows[0].aquabux,
    ecoxionums: rows[0].ecoxionums,
    ecorebits: Number(rows[0].ecorebits) // ✨ Devolvemos el saldo de EcoCoreBits directamente
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

  // 1. AquaBux
  const { rows: abRows } = await pool.query(
    `SELECT concepto, monto, origen, created_at
     FROM ocean_pay_txs
     WHERE user_id = $1
     ORDER BY created_at DESC
     LIMIT 50`,
    [userId]
  );

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
    ...abRows.map(r => ({ ...r, moneda: 'AB' })),
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
    const current = rows[0]?.amount || 0;
    const next = current + amount;
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
  const { userId, amount, concepto = 'Operación' } = req.body;
  if (amount === undefined) return res.status(400).json({ error: 'Falta amount' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // lock & read
    const { rows } = await client.query(
      'SELECT balance FROM users WHERE id = $1 FOR UPDATE',
      [userId]
    );
    if (!rows.length) throw new Error('Usuario no existe');
    const newBal = rows[0].balance + amount;
    if (newBal < 0) throw new Error('Saldo insuficiente');

    // update
    await client.query(
      'UPDATE users SET balance = balance + $1 WHERE id = $2',
      [amount, userId]
    );

    // log en Ecoxion
    await client.query(
      `INSERT INTO ecocore_txs (user_id, concepto, monto, origen)
       VALUES ($1, $2, $3, 'Ecoxion')`,
      [userId, concepto, amount]
    );

    // log en Ocean Pay
    await client.query(
      `INSERT INTO ocean_pay_txs (user_id, concepto, monto, origen)
       VALUES ($1, $2, $3, 'Ecoxion')`,
      [userId, concepto, amount]
    );

    await client.query('COMMIT');
    res.json({ success: true, newBalance: newBal });
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: e.message });
  } finally {
    client.release();
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
                    balance: Number(balance)
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
    created_at  TIMESTAMP DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS tigertasks_backups (
    user_id TEXT PRIMARY KEY,
    backup_data JSONB NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
  );

`,
  ];

  for (const q of tableQueries) {
    await pool.query(q);
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

await ensureDatabase(); 
await ensureTables();


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 API corriendo en http://localhost:${PORT}`));
