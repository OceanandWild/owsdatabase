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

// 3️⃣ Ruta de salud (para Sentry + cualquier otro monitor)
app.get("/", (req, res) => {
  res.json({ status: "ok", service: "ecoxion-api", uptime: process.uptime() });
});

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
      "SELECT version, news, date FROM updates ORDER BY date DESC LIMIT 1"
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
    "INSERT INTO updates (version, news, date) VALUES ($1, $2, NOW())",
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

// 📌 EVENTOS
app.post("/publish-event", async (req, res) => {
  const { secret, name, keyword, musicURL, startAt, rewardBits = 100 } = req.body;
  if (secret !== process.env.STUDIO_SECRET)
    return res.status(401).json({ error: "No autorizado" });

  await pool.query(
    "INSERT INTO events (name, keyword, musicURL, startAt, rewardBits, created) VALUES ($1,$2,$3,$4,$5,NOW())",
    [name, keyword.toLowerCase(), musicURL, startAt, rewardBits]
  );

  res.json({ ok: true, msg: "Evento programado" });
});

app.get("/active-event", async (_req, res) => {
  const { rows } = await pool.query(
    "SELECT * FROM events WHERE startAt <= NOW() AND finished IS NOT TRUE ORDER BY startAt DESC LIMIT 1"
  );

  if (rows.length === 0) return res.json({ error: "Sin evento activo" });
  res.json(rows[0]);
});

app.patch("/finish-event", async (req, res) => {
  const { secret, eventId } = req.body;
  if (secret !== process.env.STUDIO_SECRET)
    return res.status(401).json({ error: "No autorizado" });

  await pool.query("UPDATE events SET finished=true WHERE id=$1", [eventId]);
  res.json({ ok: true });
});

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


/* planes hardcodeados (podes moverlos a DB) */
const PLANS = [
  { id: 'eco-premium',  name: 'Eco Premium',  price: 500,  perks: ['Extensiones exclusivas', 'Pack mensual sorpresa', 'Sin publicidad'], highlight: true },
  { id: 'eco-basic',    name: 'Eco Basic',    price: 200,  perks: ['1 extensión premium/mes', 'Soporte prioritario'] }
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

/* -----  suscribir / renovar  ----- */
app.post('/subscribe', async (req, res) => {
  const { userId, planId } = req.body;
  const plan = PLANS.find(p => p.id === planId);
  if (!plan) return res.status(400).json({ error: 'Plan inválido' });

  /* tu lógica de cobro / descontar Ecoxionums aquí */
  const now = new Date();
  const end = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000); // 30 días

  /* cancelamos cualquier activa anterior */
  await db.collection('subs').updateMany({ userId, active: true }, { $set: { active: false, end: now } });

  /* insertamos la nueva */
  const newSub = {
    userId,
    planId: plan.id,
    planName: plan.name,
    start: now,
    end,
    active: true
  };
  await db.collection('subs').insertOne(newSub);
  res.json({ success: true, sub: newSub });
});

// GET /api/subscriptions/has-access/:userId/:feature
app.get("/api/subscriptions/has-access/:userId/:feature", async (req, res) => {
  const { userId, feature } = req.params;

  const { rows } = await pool.query(
    `SELECT * FROM subs WHERE user_id = $1 AND active = true AND end > NOW()`,
    [userId]
  );

  if (rows.length === 0) {
    return res.json({ hasAccess: false, message: "Sin suscripción activa" });
  }

  const plan = rows[0];
  const plans = await pool.query(`SELECT perks FROM plans WHERE id = $1`, [plan.planId]);
  const perks = plans.rows[0]?.perks || [];

  const hasAccess = perks.includes(feature);
  res.json({ hasAccess, plan: plan.planName });
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



await ensureDatabase(); 
await ensureTables();

// 2️⃣ Error handler de Sentry (después de rutas)
import * as Sentry from "@sentry/node";
Sentry.setupExpressErrorHandler(app);

// 3️⃣ Fallback
app.use((err, req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: "Algo salió mal", sentry: res.sentry });
});



const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 API corriendo en http://localhost:${PORT}`));



