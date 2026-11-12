// Fija la versión de WaverNote en package.json, tauri.conf.json y Cargo.toml.
// Uso: node scripts/set-version.mjs 1.0.0   (o VERSION=1.0.0)
// Se usa desde CI en Windows y Linux: evita el infierno de comillas de `node -e`.
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const version = (process.argv[2] || process.env.VERSION || "").trim();
if (!/^\d+\.\d+\.\d+([-.][0-9A-Za-z.-]+)?$/.test(version)) {
  console.error(`WaverNote: versión inválida "${version}" (esperado algo como 1.0.0)`);
  process.exit(1);
}

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

async function patchJson(rel) {
  const file = path.join(root, rel);
  const data = JSON.parse(await readFile(file, "utf8"));
  data.version = version;
  await writeFile(file, `${JSON.stringify(data, null, 2)}\n`);
  console.log(`  ${rel}: ${version}`);
}

async function patchCargo() {
  const rel = "src-tauri/Cargo.toml";
  const file = path.join(root, rel);
  const text = await readFile(file, "utf8");
  // Solo la versión del paquete propio ([package] es la primera sección del archivo).
  const updated = text.replace(/^version = "[^"]*"/m, `version = "${version}"`);
  if (updated === text && !text.includes(`version = "${version}"`)) {
    throw new Error(`No se pudo actualizar la versión en ${rel}`);
  }
  await writeFile(file, updated);
  console.log(`  ${rel}: ${version}`);
}

async function patchIndexMeta() {
  const rel = "index.html";
  const file = path.join(root, rel);
  const text = await readFile(file, "utf8");
  const pattern = /<meta name="wavernote-version" content="[^"]*" \/>/;
  if (!pattern.test(text)) {
    throw new Error(`No se encontró el meta wavernote-version en ${rel}`);
  }
  await writeFile(
    file,
    text.replace(pattern, `<meta name="wavernote-version" content="${version}" />`)
  );
  console.log(`  ${rel}: ${version}`);
}

await patchJson("package.json");
await patchJson("src-tauri/tauri.conf.json");
await patchCargo();
await patchIndexMeta();

console.log(`WaverNote: versión fijada en ${version}`);
