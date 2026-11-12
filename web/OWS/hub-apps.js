// OWS Hub Apps — tienda de aplicaciones oficiales del ecosistema.
// El catálogo vive en hub-apps.json para poder actualizarlo sin tocar la app.
// Si el fetch falla (file://, Render despertando, sin red) se usa el fallback.
(function () {
  "use strict";

  const FALLBACK = {
    apps: [
      {
        slug: "wavernote",
        name: "WaverNote",
        category: "Música",
        tagline: "Tu biblioteca musical, en Windows y Android.",
        description:
          "Subí tus propias canciones, ordená tu biblioteca y escuchá todo desde la app. WaverNote guarda el audio en la nube y sincroniza tu cuenta de Surface entre dispositivos.",
        version: "1.0.1-beta",
        icon_url: "img/wavernote-icon.png",
        accent: "#2dd4bf",
        release_url: "https://github.com/OceanandWild/owsdatabase/releases/tag/wavernote-v1.0.1-beta",
        features: [
          "Biblioteca propia sin catálogos de ejemplo",
          "Tendencias y recomendaciones personales",
          "Cola, favoritos, playlists y reproducción persistente",
          "Subida manual o escaneo automático de tu carpeta Música"
        ],
        platforms: {
          windows: {
            label: "Windows 10 / 11",
            detail: "Instalador NSIS · x64",
            version: "1.0.0",
            file: "WaverNote_1.0.0_x64-setup.exe",
            url: "https://github.com/OceanandWild/owsdatabase/releases/download/wavernote-v1.0.0/WaverNote_1.0.0_x64-setup.exe",
            size: "2,14 MB",
            size_bytes: 2244861
          },
          android: {
            label: "Android 7.0+",
            detail: "APK universal firmado",
            version: "1.0.1-beta",
            file: "WaverNote_1.0.1-beta_universal.apk",
            url: "https://github.com/OceanandWild/owsdatabase/releases/download/wavernote-v1.0.1-beta/WaverNote_1.0.1-beta_universal.apk",
            size: "35,38 MB",
            size_bytes: 37102579
          }
        }
      }
    ]
  };

  let appsCache = FALLBACK.apps.slice();
  let loaded = false;

  function safeText(value) {
    return typeof escapeHtml === "function" ? escapeHtml(String(value == null ? "" : value)) : String(value == null ? "" : value);
  }

  function isAndroidNative() {
    try {
      return typeof isAndroidApp === "function" && isAndroidApp();
    } catch (_) {
      return false;
    }
  }

  function tauriCore() {
    try {
      const t = window.__TAURI__;
      if (t && t.core && typeof t.core.invoke === "function") return t.core;
    } catch (_) {}
    return null;
  }

  // En Android el Hub corre sobre Capacitor (no Tauri): ahí no hay comandos
  // nativos y la instalación sigue siendo el APK.
  function isDesktopApp() {
    return !!tauriCore() && !isAndroidNative();
  }

  // Descarga y abre el instalador desde la propia app. Así el archivo no
  // queda con Mark-of-the-Web y Windows no lo bloquea con "La configuración
  // de seguridad de Internet impidió la apertura de uno o varios archivos".
  async function installWindowsNatively(btn, app, p) {
    const core = tauriCore();
    if (!core) throw new Error("Tauri no disponible");
    const cta = btn ? btn.querySelector(".hub-app-dl-cta") : null;
    let unlisten = null;
    try {
      const ev = window.__TAURI__ && window.__TAURI__.event;
      if (ev && typeof ev.listen === "function") {
        unlisten = await ev.listen("ows-hub-app-progress", (e) => {
          const d = e && e.payload;
          if (!cta || !d || String(d.slug) !== String(app.slug)) return;
          cta.textContent = d.total
            ? Math.min(100, Math.round((d.downloaded / d.total) * 100)) + "%"
            : "Descargando…";
        });
      }
      const path = await core.invoke("download_hub_app", { slug: app.slug, url: p.url });
      await core.invoke("run_hub_app_installer", { path });
      if (typeof showToast === "function") {
        showToast("Abrimos el instalador de " + app.name + ". Seguí los pasos en pantalla.");
      }
    } finally {
      if (unlisten) {
        try {
          unlisten();
        } catch (_) {}
      }
    }
  }

  function platformOrder() {
    return isAndroidNative() ? ["android", "windows"] : ["windows", "android"];
  }

  function platformIcon(platform) {
    return platform === "android" ? "🤖" : "🪟";
  }

  function platformCta(platform) {
    return isAndroidNative() && platform === "android" ? "Instalar" : "Descargar";
  }

  function readInstalled(slug) {
    try {
      if (typeof getAndroidInstalledMap !== "function") return "";
      const map = getAndroidInstalledMap();
      return String((map && map[slug]) || "").trim();
    } catch (_) {
      return "";
    }
  }

  function appCard(app) {
    const slug = String(app.slug || "").trim();
    const accent = /^#[0-9a-f]{3,8}$/i.test(String(app.accent || "")) ? app.accent : "#2dd4bf";
    const platforms = app.platforms && typeof app.platforms === "object" ? app.platforms : {};
    const order = platformOrder().filter((p) => platforms[p]);
    const installed = isAndroidNative() ? readInstalled(slug) : "";

    const actions = order.map((platform) => {
      const p = platforms[platform] || {};
      const isPrimary = platform === (isAndroidNative() ? "android" : "windows");
      // Cada plataforma puede ir en una versión distinta (p. ej. beta solo en
      // Android): se muestra la versión real de esa descarga.
      const pVersion = String(p.version || "").trim();
      const meta = [p.detail, pVersion ? "v" + pVersion : "", p.size].filter(Boolean).map(safeText).join(" · ");
      const size = `<span class="hub-app-dl-sub">${meta}</span>`;
      return `
        <button class="hub-app-dl${isPrimary ? " is-primary" : ""}" type="button"
                data-hub-app-platform="${safeText(platform)}" data-hub-app-slug="${safeText(slug)}">
          <span class="hub-app-dl-ico" aria-hidden="true">${platformIcon(platform)}</span>
          <span class="hub-app-dl-copy">
            <span class="hub-app-dl-title">${isPrimary ? "Para tu dispositivo · " : ""}${safeText(p.label || platform)}</span>
            ${size}
          </span>
          <span class="hub-app-dl-cta">${platformCta(platform)} ↓</span>
        </button>`;
    }).join("");

    const features = Array.isArray(app.features)
      ? `<ul class="hub-app-features">${app.features.map((f) => `<li>${safeText(f)}</li>`).join("")}</ul>`
      : "";

    const badge = installed
      ? `<span class="hub-app-badge">Instalado${installed ? " · v" + safeText(installed) : ""}</span>`
      : `<span class="hub-app-badge">Nuevo</span>`;

    return `
      <article class="hub-app-card" style="--app-accent:${safeText(accent)}" data-app-slug="${safeText(slug)}">
        ${badge}
        <div class="hub-app-top">
          <div class="hub-app-icon-wrap">
            ${app.icon_url
              ? `<img class="hub-app-icon" src="${safeText(app.icon_url)}" alt="${safeText(app.name)}" loading="lazy" />`
              : `<span class="hub-app-icon" aria-hidden="true">🎵</span>`}
          </div>
          <div class="hub-app-heading">
            <span class="hub-app-kicker">${safeText(app.category || "App")}</span>
            <h4 class="hub-app-name">${safeText(app.name || "App")}</h4>
            <p class="hub-app-tagline">${safeText(app.tagline || "")}</p>
          </div>
          <span class="hub-app-version">v${safeText(app.version || "1.0.0")}</span>
        </div>
        <p class="hub-app-desc">${safeText(app.description || "")}</p>
        ${features}
        <div class="hub-app-platforms">${actions || '<p class="hub-app-desc">Todavía no hay descargas publicadas.</p>'}</div>
        <div class="hub-app-foot">
          <span>${safeText(app.category || "OWS")} · ${safeText(app.version ? "v" + app.version : "")}</span>
          ${app.release_url ? `<a href="${safeText(app.release_url)}" target="_blank" rel="noopener">Notas de la versión ↗</a>` : "<span></span>"}
        </div>
      </article>`;
  }

  function renderApps(apps) {
    const grid = document.getElementById("hub-apps-grid");
    const empty = document.getElementById("hub-apps-empty");
    if (!grid) return;
    const list = Array.isArray(apps) ? apps.filter((a) => a && a.slug) : [];
    if (!list.length) {
      grid.innerHTML = "";
      if (empty) empty.classList.remove("hidden");
      return;
    }
    if (empty) empty.classList.add("hidden");
    grid.innerHTML = list.map(appCard).join("");
  }

  function openExternal(url) {
    const href = String(url || "").trim();
    if (!href) return;
    // Desktop (Tauri): el WebView no maneja target=_blank de forma confiable.
    // Se abre en el navegador del sistema con el plugin opener (ows-hub lo trae).
    try {
      const core = window.__TAURI__ && window.__TAURI__.core;
      if (core && typeof core.invoke === "function") {
        core.invoke("plugin:opener|open_url", { url: href }).catch(() => {});
        return;
      }
    } catch (_) {}
    try {
      const a = document.createElement("a");
      a.href = href;
      a.target = "_blank";
      a.rel = "noopener";
      document.body.appendChild(a);
      a.click();
      setTimeout(() => { try { a.remove(); } catch (_) {} }, 1200);
    } catch (_) {
      try { window.open(href, "_blank", "noopener"); } catch (_) {}
    }
  }

  function findApp(slug) {
    const s = String(slug || "").trim();
    return appsCache.find((a) => String(a.slug || "").trim() === s) || null;
  }

  function setBusy(btn, busy) {
    if (!btn) return;
    btn.classList.toggle("is-busy", !!busy);
    btn.disabled = !!busy;
    const cta = btn.querySelector(".hub-app-dl-cta");
    if (cta) {
      if (busy) {
        if (!cta.dataset.idle) cta.dataset.idle = cta.textContent;
        cta.textContent = "Preparando…";
      } else if (cta.dataset.idle) {
        cta.textContent = cta.dataset.idle;
        delete cta.dataset.idle;
      }
    }
  }

  async function startDownload(btn, slug, platform) {
    const app = findApp(slug);
    if (!app) return;
    const p = (app.platforms && app.platforms[platform]) || null;
    if (!p || !p.url) {
      if (typeof showToast === "function") showToast("Esta app todavía no tiene descarga para esa plataforma");
      return;
    }

    if (platform === "android" && isAndroidNative()) {
      setBusy(btn, true);
      try {
        const rel = {
          project_slug: slug,
          package_id: "",
          version_name: String(p.version || app.version || ""),
          version_code: 0,
          apk_url: String(p.url || ""),
          sha256: "",
          size_bytes: Number(p.size_bytes || 0),
          release_notes: "",
          published_at: "",
          source: "hub-apps"
        };
        if (typeof startAndroidApkInstall === "function") {
          await startAndroidApkInstall(slug, app.name, rel);
        } else {
          openExternal(p.url);
        }
      } catch (err) {
        if (typeof showToast === "function") showToast("No se pudo iniciar la instalación del APK");
      } finally {
        setBusy(btn, false);
      }
      return;
    }

    if (platform === "windows" && isAndroidNative()) {
      if (typeof showToast === "function") {
        showToast("El instalador de Windows se abre desde tu PC. En este teléfono usá la versión Android.");
      }
      return;
    }

    // Escritorio: descarga nativa (sin aviso de zona ni SmartScreen).
    if (platform === "windows" && isDesktopApp()) {
      setBusy(btn, true);
      try {
        await installWindowsNatively(btn, app, p);
        return;
      } catch (err) {
        if (typeof showToast === "function") {
          showToast("No se pudo descargar desde el Hub; abrimos el navegador.");
        }
      } finally {
        setBusy(btn, false);
      }
    }

    openExternal(p.url);
    if (typeof showToast === "function") {
      showToast(platform === "android" ? "Descargando el APK de " + app.name + "…" : "Descargando el instalador de " + app.name + "…");
    }
  }

  function bindEvents() {
    const grid = document.getElementById("hub-apps-grid");
    if (!grid || grid.dataset.bound === "1") return;
    grid.dataset.bound = "1";
    grid.addEventListener("click", (ev) => {
      const btn = ev.target.closest("[data-hub-app-platform]");
      if (!btn) return;
      ev.preventDefault();
      startDownload(btn, btn.getAttribute("data-hub-app-slug"), btn.getAttribute("data-hub-app-platform"));
    });
  }

  async function loadHubApps() {
    bindEvents();
    if (loaded) {
      renderApps(appsCache);
      return appsCache;
    }
    try {
      const res = await fetch("hub-apps.json?v=1", { cache: "no-store" });
      if (!res.ok) throw new Error("HTTP " + res.status);
      const data = await res.json();
      if (data && Array.isArray(data.apps) && data.apps.length) {
        appsCache = data.apps;
      }
    } catch (_) {
      appsCache = FALLBACK.apps.slice();
    }
    loaded = true;
    renderApps(appsCache);
    return appsCache;
  }

  window.loadHubApps = loadHubApps;
  window.OWS_HUB_APPS = {
    load: loadHubApps,
    list: () => appsCache.slice(),
    version: "1.1.0"
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => { loadHubApps().catch(() => {}); });
  } else {
    loadHubApps().catch(() => {});
  }
})();
