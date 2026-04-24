(() => {
  const GLOBAL_KEY = "OWSProjectRestrictionGuard";
  if (typeof window === "undefined" || window[GLOBAL_KEY]) return;

  const STYLE_ID = "ows-project-guard-style";
  const ROOT_ID = "ows-project-guard-root";
  const ACK_PREFIX = "ows-project-guard-ack:";
  const DEFAULT_API_BASE = "https://owsdatabase.onrender.com";

  const normalizeText = (value) => String(value || "").trim();
  const normalizeRef = (value) => normalizeText(value).toLowerCase();

  function ensureStyle() {
    if (document.getElementById(STYLE_ID)) return;
    const style = document.createElement("style");
    style.id = STYLE_ID;
    style.textContent = `
#${ROOT_ID}{
  position:fixed; inset:0; z-index:2147483000; display:none; align-items:center; justify-content:center;
  padding:20px; background:linear-gradient(145deg, rgba(2,9,22,0.86), rgba(2,18,34,0.9));
  backdrop-filter:blur(6px);
}
#${ROOT_ID}.show{ display:flex; }
#${ROOT_ID} .ows-guard-modal{
  width:min(960px, 96vw); border-radius:18px; overflow:hidden;
  border:1px solid rgba(90,160,210,0.42);
  background:linear-gradient(170deg, #03132a 0%, #071d38 100%);
  box-shadow:0 28px 56px rgba(0,0,0,0.52);
  color:#e4f4ff; font-family:"Segoe UI", Tahoma, sans-serif;
}
#${ROOT_ID} .ows-guard-head{
  display:flex; align-items:center; justify-content:space-between;
  padding:14px 18px; border-bottom:1px solid rgba(86,169,222,0.25);
  background:linear-gradient(90deg, rgba(4,29,60,0.94), rgba(5,26,52,0.68));
}
#${ROOT_ID} .ows-guard-head-left{ display:flex; align-items:center; gap:10px; font-weight:900; letter-spacing:.04em; font-size:12px; text-transform:uppercase; color:#7fdcff; }
#${ROOT_ID} .ows-guard-close{
  width:34px; height:34px; border-radius:10px; border:1px solid rgba(116,177,220,0.35);
  background:rgba(12,28,52,0.75); color:#b9def7; cursor:pointer; font-size:20px; line-height:1;
}
#${ROOT_ID} .ows-guard-close:hover{ border-color:rgba(167,225,255,0.55); color:#ffffff; }
#${ROOT_ID} .ows-guard-body{ padding:18px; }
#${ROOT_ID} .ows-guard-flow{
  display:grid; grid-template-columns:1fr auto 1fr auto 1fr; gap:12px; align-items:center; margin-bottom:16px;
}
#${ROOT_ID} .ows-guard-card{
  min-height:120px; border-radius:14px; border:1px solid rgba(95,165,215,0.36);
  background:linear-gradient(160deg, rgba(8,31,61,0.92), rgba(5,21,42,0.86));
  padding:14px;
}
#${ROOT_ID} .ows-guard-card--blocked{
  border-color:rgba(255,95,115,0.45);
  background:linear-gradient(160deg, rgba(64,15,28,0.45), rgba(42,10,20,0.33));
}
#${ROOT_ID} .ows-guard-icon-wrap{ display:flex; align-items:center; gap:10px; margin-bottom:10px; }
#${ROOT_ID} .ows-guard-app-icon{
  width:52px; height:52px; border-radius:12px; object-fit:cover; background:#0d2037;
  border:1px solid rgba(131,194,255,0.45); box-shadow:0 8px 20px rgba(0,0,0,0.35);
}
#${ROOT_ID} .ows-guard-mini-title{ margin:0; font-size:28px; font-weight:900; color:#7fdcff; line-height:1; }
#${ROOT_ID} .ows-guard-title{ margin:0; font-size:28px; font-weight:900; line-height:1.12; color:#f3f9ff; }
#${ROOT_ID} .ows-guard-subtitle{ margin:6px 0 0; font-size:14px; color:#abc8de; line-height:1.45; }
#${ROOT_ID} .ows-guard-arrow{ font-size:28px; color:rgba(83,182,236,0.8); font-weight:900; user-select:none; }
#${ROOT_ID} .ows-guard-main{ margin-top:8px; }
#${ROOT_ID} .ows-guard-main h2{
  margin:0 0 8px; font-size:40px; line-height:1.08; color:#ecf8ff;
}
#${ROOT_ID} .ows-guard-main p{ margin:0; font-size:22px; line-height:1.45; color:#c3def1; }
#${ROOT_ID} .ows-guard-reason{
  margin-top:16px; border-radius:12px; border:1px solid rgba(255,125,145,0.45);
  background:linear-gradient(160deg, rgba(64,14,28,0.58), rgba(36,8,18,0.48));
  padding:12px 14px; color:#ffc9d2; font-weight:700; font-size:18px;
}
#${ROOT_ID} .ows-guard-actions{ display:flex; justify-content:flex-end; gap:10px; margin-top:16px; }
#${ROOT_ID} .ows-guard-btn{
  border:1px solid rgba(105,177,226,0.38); background:rgba(20,45,79,0.88); color:#def2ff;
  border-radius:12px; padding:10px 18px; font-size:18px; font-weight:900; cursor:pointer;
}
#${ROOT_ID} .ows-guard-btn:hover{ filter:brightness(1.08); }
#${ROOT_ID} .ows-guard-btn--primary{
  border-color:rgba(65,240,255,0.5); background:linear-gradient(135deg, #37d7ff, #53f5d6);
  color:#04324a;
}
@media (max-width:900px){
  #${ROOT_ID} .ows-guard-flow{ grid-template-columns:1fr; gap:10px; }
  #${ROOT_ID} .ows-guard-arrow{ display:none; }
  #${ROOT_ID} .ows-guard-main h2{ font-size:32px; }
  #${ROOT_ID} .ows-guard-main p{ font-size:18px; }
}
`;
    document.head.appendChild(style);
  }

  function createRoot() {
    let root = document.getElementById(ROOT_ID);
    if (root) return root;
    root = document.createElement("div");
    root.id = ROOT_ID;
    root.innerHTML = `
      <div class="ows-guard-modal" role="dialog" aria-modal="true" aria-label="OWS Project Restriction">
        <div class="ows-guard-head">
          <div class="ows-guard-head-left">
            <span>◈</span>
            <span>Restriccion de OWS Store</span>
          </div>
          <button type="button" class="ows-guard-close" aria-label="Cerrar">×</button>
        </div>
        <div class="ows-guard-body">
          <div class="ows-guard-flow">
            <div class="ows-guard-card">
              <div class="ows-guard-icon-wrap">
                <div class="ows-guard-app-icon" style="display:grid;place-items:center;font-weight:900;color:#7be4ff;">OWS</div>
                <div>
                  <h3 class="ows-guard-mini-title">OWS Store</h3>
                  <p class="ows-guard-subtitle">Estado de seguridad y distribucion.</p>
                </div>
              </div>
            </div>
            <div class="ows-guard-arrow">→</div>
            <div class="ows-guard-card ows-guard-card--blocked">
              <div class="ows-guard-icon-wrap">
                <div class="ows-guard-app-icon" style="display:grid;place-items:center;font-size:20px;">🔒</div>
                <div>
                  <h3 class="ows-guard-mini-title" data-role="blocked-title">Bloqueado por OWS Store</h3>
                  <p class="ows-guard-subtitle" data-role="blocked-subtitle">Acciones de instalacion, actualizacion y apertura quedan desactivadas.</p>
                </div>
              </div>
            </div>
            <div class="ows-guard-arrow">⦸</div>
            <div class="ows-guard-card">
              <div class="ows-guard-icon-wrap">
                <img class="ows-guard-app-icon" data-role="project-icon" alt="Project icon" />
                <div>
                  <h3 class="ows-guard-mini-title" data-role="project-name">Proyecto</h3>
                  <p class="ows-guard-subtitle" data-role="project-meta">OWS Store bloqueo este proyecto temporalmente.</p>
                </div>
              </div>
            </div>
          </div>

          <div class="ows-guard-main">
            <h2 data-role="title">Este proyecto esta temporalmente restringido</h2>
            <p data-role="message">La distribucion permanecera bloqueada hasta que OWS Store complete las validaciones.</p>
          </div>

          <div class="ows-guard-reason" data-role="reason">Motivo detectado: validacion de estado en OWS Store.</div>

          <div class="ows-guard-actions">
            <button type="button" class="ows-guard-btn" data-role="understood-btn">Entendido</button>
            <button type="button" class="ows-guard-btn ows-guard-btn--primary" data-role="updates-btn">Ver estado de actualizaciones</button>
          </div>
        </div>
      </div>
    `;
    document.body.appendChild(root);
    return root;
  }

  function safeUrl(url) {
    const text = normalizeText(url);
    if (!text) return "";
    if (/^https?:\/\//i.test(text)) return text;
    return "";
  }

  function buildAckKey(project, restriction) {
    const slug = normalizeRef(project?.slug || project?.name || "project");
    const type = normalizeRef(restriction?.type || "unknown");
    const stamp = normalizeText(restriction?.reason || restriction?.message || "");
    return `${ACK_PREFIX}${slug}:${type}:${stamp}`;
  }

  function buildMessageModel(payload) {
    const project = payload?.project || {};
    const restriction = payload?.restriction || {};
    const type = normalizeRef(restriction.type);
    const projectName = normalizeText(project.name) || "Proyecto";
    const isRework = type === "rework";
    const title = isRework
      ? `${projectName} esta en pleno rework`
      : `${projectName} esta temporalmente indisponible`;
    const defaultMsg = isRework
      ? `${projectName} esta en rework avanzado. OWS Store volvera a habilitarlo cuando cierre este proceso.`
      : `${projectName} fue marcado como indisponible temporalmente hasta completar validaciones de seguridad y distribucion.`;
    const reason = normalizeText(restriction.reason) || normalizeText(restriction.message) || defaultMsg;
    return {
      isRework,
      projectName,
      projectIcon: safeUrl(project.icon_url),
      title,
      message: normalizeText(restriction.message) || defaultMsg,
      reason
    };
  }

  function renderModal(root, payload, options) {
    const model = buildMessageModel(payload);
    const project = payload?.project || {};
    const restriction = payload?.restriction || {};

    const closeBtn = root.querySelector(".ows-guard-close");
    const understoodBtn = root.querySelector('[data-role="understood-btn"]');
    const updatesBtn = root.querySelector('[data-role="updates-btn"]');
    const blockedTitle = root.querySelector('[data-role="blocked-title"]');
    const blockedSubtitle = root.querySelector('[data-role="blocked-subtitle"]');
    const projectIcon = root.querySelector('[data-role="project-icon"]');
    const projectName = root.querySelector('[data-role="project-name"]');
    const projectMeta = root.querySelector('[data-role="project-meta"]');
    const title = root.querySelector('[data-role="title"]');
    const message = root.querySelector('[data-role="message"]');
    const reason = root.querySelector('[data-role="reason"]');

    if (blockedTitle) {
      blockedTitle.textContent = model.isRework ? "Bloqueado por rework" : "Bloqueado por indisponibilidad";
    }
    if (blockedSubtitle) {
      blockedSubtitle.textContent = model.isRework
        ? "Instalar, actualizar y abrir quedan desactivados durante este rework."
        : "OWS Store desactivo temporalmente la distribucion de este proyecto.";
    }
    if (projectName) {
      projectName.textContent = model.projectName;
    }
    if (projectMeta) {
      const slug = normalizeText(project.slug);
      projectMeta.textContent = slug
        ? `${model.projectName} - OWS (${slug})`
        : `${model.projectName} - OWS`;
    }
    if (projectIcon) {
      if (model.projectIcon) {
        projectIcon.src = model.projectIcon;
        projectIcon.style.display = "block";
      } else {
        projectIcon.removeAttribute("src");
        projectIcon.style.display = "none";
      }
    }
    if (title) title.textContent = model.title;
    if (message) message.textContent = model.message;
    if (reason) reason.textContent = `Motivo detectado: ${model.reason}`;

    const ackKey = buildAckKey(project, restriction);
    const acknowledge = () => {
      try { sessionStorage.setItem(ackKey, "1"); } catch (_) {}
      root.classList.remove("show");
    };
    if (closeBtn) closeBtn.onclick = acknowledge;
    if (understoodBtn) understoodBtn.onclick = acknowledge;
    if (updatesBtn) {
      updatesBtn.onclick = () => {
        const base = normalizeText(options.apiBaseUrl || DEFAULT_API_BASE).replace(/\/+$/, "");
        window.open(`${base}/ows-store`, "_blank", "noopener,noreferrer");
      };
    }

    let acknowledged = false;
    try { acknowledged = sessionStorage.getItem(ackKey) === "1"; } catch (_) {}
    if (!acknowledged) root.classList.add("show");
  }

  function clearModal(root) {
    root.classList.remove("show");
  }

  function resolveProjectRef(options = {}) {
    const slug = normalizeText(options.projectSlug || options.projectRef);
    const name = normalizeText(options.projectName);
    return slug || name;
  }

  async function requestRestriction(options = {}) {
    const apiBaseUrl = normalizeText(options.apiBaseUrl || DEFAULT_API_BASE).replace(/\/+$/, "");
    const projectRef = resolveProjectRef(options);
    if (!projectRef) return null;
    const url = `${apiBaseUrl}/ows-store/project-restrictions/${encodeURIComponent(projectRef)}`;
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) return null;
    const payload = await res.json();
    if (!payload || !payload.success) return null;
    return payload;
  }

  function mount(options = {}) {
    ensureStyle();
    const root = createRoot();
    const intervalMs = Math.max(10000, Math.floor(Number(options.checkIntervalMs || 30000)));

    let destroyed = false;
    let timer = null;
    const onRestrictionChange = typeof options.onRestrictionChange === "function"
      ? options.onRestrictionChange
      : null;

    const runCheck = async () => {
      if (destroyed) return;
      try {
        const payload = await requestRestriction(options);
        const active = !!payload?.restriction?.active;
        if (active) renderModal(root, payload, options);
        else clearModal(root);
        if (onRestrictionChange) onRestrictionChange(payload || { restriction: { active: false } });
      } catch (_) {
        if (onRestrictionChange) onRestrictionChange({ restriction: { active: false } });
      }
    };

    runCheck();
    timer = window.setInterval(runCheck, intervalMs);

    return {
      refresh: runCheck,
      destroy: () => {
        destroyed = true;
        if (timer) window.clearInterval(timer);
        clearModal(root);
      }
    };
  }

  window[GLOBAL_KEY] = { mount };
})();
