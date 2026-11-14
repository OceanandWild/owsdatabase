/* ============================================================
   WaverNote · service worker
   Guarda el shell de la app (HTML, CSS, JS e íconos) para que
   abra sin internet. Siempre intenta la red primero: si hay
   conexión, el usuario recibe la última versión.
   ============================================================ */

const WA_SW_VERSION = "1.2.4";
const WA_SW_SHELL = `wavernote-shell-${WA_SW_VERSION}`;
const WA_SW_IMAGES = "wavernote-images-v1";

const WA_SW_FILES = [
  "./",
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
  "recommend.js",
  "catalog.js",
  "trends.js",
  "views.js",
  "import.js",
  "player.js",
  "app.js"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(WA_SW_SHELL)
      .then((cache) => cache.addAll(WA_SW_FILES))
      .then(() => self.skipWaiting())
      .catch(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys
            .filter((key) => key !== WA_SW_SHELL && key !== WA_SW_IMAGES)
            .map((key) => caches.delete(key))
        )
      )
      .then(() => self.clients.claim())
  );
});

const waNetworkFirst = async (request) => {
  const cache = await caches.open(WA_SW_SHELL);

  try {
    const response = await fetch(request);
    if (response && response.ok) {
      cache.put(request, response.clone());
      return response;
    }

    // Un 502/504 del proxy o del hosting también cuenta como "sin red":
    // mejor mostrar la copia guardada que una página de error.
    const cached = await cache.match(request, { ignoreSearch: true });
    if (cached) return cached;
    if (request.mode === "navigate") {
      const fallback = await cache.match("index.html");
      if (fallback) return fallback;
    }
    return response;
  } catch (err) {
    const cached = await cache.match(request, { ignoreSearch: true });
    if (cached) return cached;

    if (request.mode === "navigate") {
      const fallback = await cache.match("index.html");
      if (fallback) return fallback;
    }

    return Response.error();
  }
};

const waImageFirst = async (request) => {
  const cache = await caches.open(WA_SW_IMAGES);
  const cached = await cache.match(request);
  if (cached) return cached;

  const response = await fetch(request);
  if (response && (response.ok || response.type === "opaque")) {
    cache.put(request, response.clone());
  }
  return response;
};

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET") return;

  const url = new URL(request.url);
  if (url.origin === self.location.origin) {
    if (url.pathname.endsWith("/sw.js")) return;
    event.respondWith(waNetworkFirst(request));
    return;
  }

  // Portadas de Cloudinary: se cachean al verlas para que sigan
  // apareciendo cuando no hay conexión.
  if (request.destination === "image") {
    event.respondWith(waImageFirst(request));
  }
});
