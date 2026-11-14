// Copia el frontend estático de WaverNote a ./dist para que Tauri lo empaquete.
// No hay bundler: la app es HTML + CSS + JS sin paso de compilación.
import { cp, mkdir, readdir, rm } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const out = path.join(root, "dist");

const FILES = [
  "index.html",
  "app-icon.png",
  "styles.css",
  "library.css",
  "player.css",
  "app.css",
  "recommend.css",
  "trends.css",
  "catalog.css",
  "android.css",
  "audio-engine.js",
  "offline.js",
  "core.js",
  "import-core.js",
  "cloud.js",
  "updater.js",
  "metadata.js",
  "watch-core.js",
  "watched-folder.js",
  "recommend.js",
  "catalog.js",
  "trends.js",
  "views.js",
  "import.js",
  "player.js",
  "app.js",
  "sw.js"
];

await rm(out, { recursive: true, force: true });
await mkdir(out, { recursive: true });

for (const file of FILES) {
  await cp(path.join(root, file), path.join(out, file));
}

// Recursos opcionales (portadas locales, fuentes, etc.) si algún día se suman.
for (const dir of ["assets", "img", "fonts"]) {
  try {
    await readdir(path.join(root, dir));
    await cp(path.join(root, dir), path.join(out, dir), { recursive: true });
  } catch {
    /* no existe: nada que copiar */
  }
}

console.log(`WaverNote: frontend copiado a ${out}`);
