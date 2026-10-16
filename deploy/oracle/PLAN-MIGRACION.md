# Plan de migración — Backend OWS: Render → Oracle Cloud Always Free

- **Estado:** ⚠️ **BLOQUEADO por tarjeta** (actualizado 2026-10-15): no hay tarjeta ni para la verificación de identidad de Oracle. **Plan activo: §10 — "Render optimizado" (sin tarjeta, sin PC, $0).** Este documento queda como referencia para cuando exista una tarjeta.
- **Fecha:** 2026-10-15
- **Base:** commit `9049544` de `owsdatabase`
- **Costo objetivo:** US$ 0/mes
- **Leyenda:** 👤 = lo hace el usuario · 🤖 = lo hace el agente (con guía) 

---

## 1. Por qué y para qué

Render Free suspendió el servicio `owsdatabase` al superar el límite de **5 GB/mes** de
bandwidth (causa raíz ya confirmada). Este plan mueve el backend al free tier de Oracle
Cloud, que es el único gratuito sin límites "pesados" para proyectos grandes:

| | Render Free (hoy) | Oracle Always Free (destino) |
|---|---|---|
| Tráfico/mes | **5 GB** | **10 TB** (≈ 2.000×) |
| CPU / RAM | 0.1 CPU / 512 MB | 2 OCPU ARM / 12 GB |
| Disco | efímero | **200 GB persistentes** |
| Base de datos | externa o limitada | propia en la VM (sin límite de proveedor) |
| Hibernación / suspensión | sí (cold starts + cortes por bandwidth) | no |
| HTTPS | incluido | incluido (Caddy + Let's Encrypt) |
| Costo | $0 con límites | $0 para siempre, uso comercial permitido |

**Objetivos:**
1. Que el ecosistema (Hub, Ocean Pay, OWS Store, web) funcione 24/7 sin cortes por bandwidth.
2. Que aguante el crecimiento de los proyectos (12 GB RAM, 200 GB disco, 10 TB/mes).
3. Todo reproducible: cualquier reinstalación se reconstruye en ~30 min con los scripts del repo.
4. Render queda **vivo como fallback legacy** — ningún cliente queda sin servicio durante la transición.

---

## 2. Arquitectura destino

```
  Clientes (web netlify · Hub desktop · Hub Android · Ocean Pay · OWS Store)
        │  HTTPS
        ▼
  https://owsdatabase.<IP-PUBLICA>.nip.io      ← Caddy (TLS Let's Encrypt, renovación automática)
        │  HTTP local (127.0.0.1:3000)
        ▼
  systemd: ows-server  →  node server.js       ← Node 24 LTS, compresión ya integrada
        │
        ├── PostgreSQL 16 (localhost, SSL snakeoil, shared_buffers 2 GB)
        ├── /opt/owsdatabase  (repo git, uploads/ persistentes ← WildTransfer ya no se pierde)
        └── backups diarios pg_dump (retención 14 días)

  Deploy continuo:  git push main →  GitHub Actions  →  SSH  →  git reset + npm ci + restart
```

**Nota sobre la URL:** `<IP-PUBLICA>` es la IP reservada de la VM (fija de por vida). El dominio
`owsdatabase.<IP>.nip.io` no requiere comprar nada: el servicio nip.io/sslip.io (verificado
operativo, online desde 2012, usado por GCP/AWS/Azure) resuelve cualquier IP embebida en el
hostname y Caddy obtiene el certificado por HTTP-01. Si algún día nip.io falla se usa el formato
idéntico `sslip.io`. Si algún día compran dominio propio, la URL se cambia con los mismos pasos
que la Fase 5 (una sola vez).

---

## 3. Inventario técnico verificado (2026-10-15)

### 3.1 Backend (`server.js`, ~42.400 líneas)
- Node ESM, `dotenv`, `httpServer.listen(PORT, '0.0.0.0')` (línea 42399), `PORT` fallback 3000.
- `socket.io` montado sobre el mismo httpServer (líneas 247-248) → Caddy debe proxear WebSocket (lo hace por defecto).
- CORS ya abierto (`origin: true`) → no requiere cambios al cambiar de host.
- Compresión + cache de estáticos ya integrados (commit `9049544`) → se mantienen.
- Pool PG (líneas 212-226): si existe `DATABASE_URL` → `ssl: { rejectUnauthorized: false }`.
  Ubuntu trae PostgreSQL con `ssl=on` + certificado snakeoil → **funciona sin tocar código**.
- Uploads locales (WildTransfer) en `uploads/` relativo al cwd → en la VM quedan **persistentes**
  (en Render Free son efímeros: se perdían en cada deploy — esto es una mejora real).
- `puppeteer`, `ffmpeg` y `node-cron` están en `package.json` pero **no se usan en `server.js`**
  (verificado; probable legado). En la instalación de la VM se usa `PUPPETEER_SKIP_DOWNLOAD=1`
  para no descargar Chromium (~170 MB) al pedo.
- `bcrypt` es nativo → la VM necesita `build-essential python3` (compila en ~1-2 min durante `npm ci`).
- No hay `render.yaml`/`Procfile`/`Dockerfile`: Render autodetecta `npm start` → en la VM se replica con systemd.

### 3.2 Variables de entorno usadas por `server.js` (34 — checklist completa en Anexo B)
⚠️ **Crítico:** `JWT_SECRET`, `OWS_ADMIN_SECRET`, `STUDIO_SECRET`, `WNS_*` se copian **idénticas**.
Si cambian, se invalidan los tokens de usuarios logueados y firmas existentes.

### 3.3 URL del backend hardcodeada (clientes a migrar — detalle en Fase 5)
| Archivo | Lugar |
|---|---|
| `web/OWS/app.js` | `OWS_DEFAULT_API` (líneas 5-8) — **el más importante** (lo heredan Hub desktop y Android) |
| `web/OWS/library.js` | línea 125 |
| `web/OWS/admin/admin-app.js` | líneas 3, 12 (panel local) |
| `web/OWS/Ocean Pay/app.js` | líneas 2, 3 |
| `OWS-Desktop/src-tauri/tauri.conf.json` | línea 28 (CSP `connect-src`) |
| `OWS-Desktop/.github/workflows/android.yml` | línea 280 |
| `OWS Store/scripts/fetch-projects.js` | líneas 4, 7 (build-time) |
| `scripts/ows-session.ps1` · `scripts/release.ps1` · `scripts/release-ows-store.ps1` | líneas 35 · 47 · 159 |

### 3.4 Ubicación de la base de datos actual
**A confirmar en Fase 0** (host de `DATABASE_URL` en el dashboard de Render):
- **Caso A — externa** (Neon, Supabase, etc.): el dump puede hacerse **ya mismo** (la suspensión de Render no la afecta).
- **Caso B — Postgres de Render**: el dump recién es posible tras el reset del ciclo de facturación.

---

## 4. Decisiones de arquitectura

| Decisión | Elección | Motivo |
|---|---|---|
| Instancia | `VM.Standard.A1.Flex` — 2 OCPU / 12 GB ARM, Ubuntu 24.04 aarch64 | Es el Always Free vigente (verificado 2026); sobra para este stack |
| Disco | Un solo boot volume de 200 GB | Usa toda la cuota Always Free, sin particiones adicionales |
| IP | Reserved Public IP | La URL nip.io queda **fija de por vida** |
| Node | 24 LTS (NodeSource) | LTS soportado hasta 2028; compatible con todo el stack |
| Base de datos | PostgreSQL 16 en la VM (`DATABASE_URL` local) | 200 GB de espacio, sin límites de proveedor, latencia cero |
| HTTPS | Caddy + Let's Encrypt sobre `<IP>.nip.io` | Gratis, sin dominio, renovación automática |
| Deploy | GitHub Actions → SSH → `git reset` + `npm ci` + restart | Mismo flujo push-to-deploy que Render |
| Corte | Doble etapa (primero la VM usa la DB actual; después se migra la DB) | Cero riesgo de perder datos durante la verificación |
| Render | Se deja intacto como fallback legacy | Los clientes viejos siguen funcionando hasta que actualicen |

---

## 5. Fases de ejecución

### 👤 Fase 0 — Preparación (30-45 min, solo la puede hacer el usuario)

1. **Crear cuenta en Oracle Cloud** (https://signup.cloud.oracle.com):
   - Requiere tarjeta de crédito/débito **solo para verificar identidad** (hacen un cargo de ~US$ 1 y lo reversan; nunca cobran el free tier).
   - **Región home: elegir São Paulo (GRU)** — mejor latencia para Uruguay. ⚠️ La región home no se cambia fácil: elegir bien.
   - Si la región elegida rechaza "Add instance" por falta de capacidad ARM (pasa seguido), no es bloqueante: se reintenta en horas/días o se prueba otro Availability Domain.
2. **Copiar las variables de entorno de Render** → Render Dashboard → servicio `owsdatabase` → *Environment* → copiar cada valor al archivo local `deploy/oracle/.env.render` (usar Anexo B como checklist; ese archivo queda gitignored, jamás se sube).
3. **Confirmar dónde vive la DB**: mirar el host de `DATABASE_URL` (¿es un host propio de Render `dpg-...` o externo?) y avisar cuál de los dos casos es.
4. Avisar al agente: "cuenta lista" → arrancan las fases 1-3.

### 🤖 Fase 1 — Crear la VM + hardening (~45 min)

1. Consola OCI → **Create instance**:
   - Nombre: `ows-server` · Image: *Canonical Ubuntu 24.04* (aarch64) · Shape: `VM.Standard.A1.Flex` (2 OCPU / 12 GB) · Boot volume: **200 GB**.
   - VCN: *Create VCN with Internet Connectivity* (wizard) · SSH key: pegar la clave pública generada localmente.
2. **Reserved Public IP**: `Networking → IP management → Reserved public IPs` → crear → asignar a la instancia. Anotar la IP (será `<IP-PUBLICA>` en todo el plan).
3. **Security List (ingress)**: permitir `22` (con fail2ban), `80` y `443` desde `0.0.0.0/0`.
4. Conectar por SSH y hacer hardening + firewall del OS (las imágenes Ubuntu de OCI traen iptables restrictivo — hay que abrir 80/443 también adentro):
   ```bash
   sudo apt update && sudo apt -y upgrade
   sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80 -j ACCEPT
   sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 443 -j ACCEPT
   sudo netfilter-persistent save
   sudo apt -y install fail2ban unattended-upgrades
   sudo systemctl enable --now fail2ban unattended-upgrades
   ```
5. Verificación: `ssh` solo con llave (sin password), `fail2ban-client status sshd` activo.

**Claves SSH (se generan en la PC una sola vez):**
```powershell
ssh-keygen -t ed25519 -f $env:USERPROFILE\.ssh\ows_oracle -C "ows-oracle"
# Pública  → se pega en el wizard de OCI y se agrega a la VM
# Privada  → se guarda como secret ORACLE_SSH_KEY en GitHub (Fase 4)
```

### 🤖 Fase 2 — PostgreSQL + datos (~45 min)

```bash
sudo apt -y install postgresql   # v16 en Ubuntu 24.04 (SSL snakeoil ya viene activo)
sudo -u postgres psql -c "CREATE USER ows WITH PASSWORD '<GENERAR-CLAVE-FUERTE>';"
sudo -u postgres psql -c "CREATE DATABASE owsdatabase OWNER ows;"
# Tune básico para 12 GB de RAM (además mantiene el uso de memoria "vivo", ver riesgos):
# shared_buffers = 2GB, effective_cache_size = 6GB, work_mem = 16MB
```

**Migración en doble etapa (la recomendada):**
1. **Etapa 1 (sin migrar nada):** la app de la VM arranca apuntando `DATABASE_URL` a la **DB actual**.
   Todo se verifica en vivo con datos reales y la DB de origen intacta (rollback = apagar la VM).
2. **Etapa 2 (un rato después):** ventana de mantenimiento corta:
   ```bash
   # En origen (Caso A: ya mismo · Caso B: tras el reset de Render)
   pg_dump "$DATABASE_URL_ORIGEN" --no-owner --no-privileges -Fc -f ows.dump
   # En la VM
   pg_restore -d "postgres://ows:<CLAVE>@127.0.0.1:5432/owsdatabase" --no-owner --no-privileges ows.dump
   # Verificación: mismos count(*) en tablas clave de ambos lados
   ```
   Luego se cambia `DATABASE_URL` en `/etc/ows-server.env` → restart → verificación.
   **La DB de origen NO se borra**: queda como rollback por 2 semanas mínimo.

**Backups automáticos:** script `deploy/oracle/backup-db.sh` + cron diario 04:00 (hora Uruguay):
`pg_dump -Fc` → `/var/backups/ows/` con retención 14 días.
(Futuro opcional: replicar a OCI Object Storage — incluye 20 GB gratis.)

### 🤖 Fase 3 — App + Caddy + HTTPS (~60 min)

```bash
# 1) Node 24 + herramientas
curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash -
sudo apt -y install nodejs build-essential python3 ffmpeg

# 2) Repo
sudo mkdir -p /opt/owsdatabase && sudo chown ubuntu: /opt/owsdatabase
git clone https://github.com/OceanandWild/owsdatabase.git /opt/owsdatabase
cd /opt/owsdatabase && PUPPETEER_SKIP_DOWNLOAD=1 npm ci --omit=dev

# 3) Variables de entorno (root:ubuntu 640 — nunca versionadas)
sudo install -m 640 -o root -g ubuntu deploy/oracle/.env.render /etc/ows-server.env
# Editar: PORT=3000 · NODE_ENV=production · DATABASE_URL=postgres://ows:<CLAVE>@127.0.0.1:5432/owsdatabase
```

`/etc/systemd/system/ows-server.service`:
```ini
[Unit]
Description=OWS Server (owsdatabase)
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/opt/owsdatabase
EnvironmentFile=/etc/ows-server.env
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now ows-server
curl -fsS http://127.0.0.1:3000/api/health   # (se agrega este endpoint en esta fase)
```

**Caddy** (TLS automático):
```bash
sudo apt -y install debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt -y install caddy
```
`/etc/caddy/Caddyfile`:
```
owsdatabase.<IP-PUBLICA>.nip.io {
    encode zstd gzip
    reverse_proxy 127.0.0.1:3000
}
```
```bash
sudo systemctl reload caddy
curl -fsS https://owsdatabase.<IP-PUBLICA>.nip.io/api/health
```

**Pruebas en vivo SIN tocar ningún cliente** (el frontend ya soporta override):
`https://owshub.netlify.app/?api=https://owsdatabase.<IP-PUBLICA>.nip.io` → probar login, noticias,
lanzamientos, descargas, WildTransfer. *(Si Render sigue suspendido: este override funciona igual
porque apunta directo a Oracle.)*

**Cambio de código mínimo (único del servidor):** agregar `GET /api/health` (~3 líneas, junto a los
demás endpoints `/…/health` del archivo). Se commitea con pathspec, se pushea, y el workflow de Fase 4 lo despliega.

### 🤖 Fase 4 — Deploy continuo (~30 min)

1. Secrets del repo en GitHub (`Settings → Secrets and variables → Actions`):
   `ORACLE_HOST` = IP · `ORACLE_USER` = `ubuntu` · `ORACLE_SSH_KEY` = clave privada.
2. Workflow `.github/workflows/deploy-oracle.yml`:
```yaml
name: Deploy a Oracle (producción)
on:
  push:
    branches: [main]
    paths-ignore: ['deploy/**', 'changelog-drafts/**', '*.md']
  workflow_dispatch:

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy por SSH
        uses: appleboy/ssh-action@v1
        with:
          host: ${{ secrets.ORACLE_HOST }}
          username: ${{ secrets.ORACLE_USER }}
          key: ${{ secrets.ORACLE_SSH_KEY }}
          script: |
            set -e
            cd /opt/owsdatabase
            git fetch origin main && git reset --hard origin/main
            PUPPETEER_SKIP_DOWNLOAD=1 npm ci --omit=dev
            sudo systemctl restart ows-server
            sleep 3 && curl -fsS http://127.0.0.1:3000/api/health
```
3. Probar con un cambio trivial → verificar deploy verde + `/api/health` OK.
4. Nota: Render también sigue auto-deployando desde `main` (cuando vuelva) — eso es **deseado**:
   mantiene el fallback actualizado gratis. No se toca nada en Render.

### 🤖 Fase 5 — Migración de clientes (por releases, según prioridad)

| # | Cliente | Archivos | Cómo llega el cambio |
|---|---|---|---|
| 1 | **Web OWS** (owshub.netlify.app) | `web/OWS/app.js`, `library.js` | push a `main` → Netlify auto-deploy |
| 1 | **Ocean Pay web** | `web/OWS/Ocean Pay/app.js` | push a `main` |
| 1 | **Panel admin** (local) | `admin-app.js` | directo al abrir |
| 1 | **Scripts internos** | `ows-session.ps1`, `release.ps1`, `release-ows-store.ps1` | commit |
| 2 | **Hub Desktop** | frontend sincronizado + CSP en `tauri.conf.json` (agregar el host nuevo y **conservar** el viejo) | release **3.4.17** (updater) |
| 3 | **Hub Android** | `android.yml` (línea 280) + frontend | APK nuevo |
| 4 | **Ocean Pay desktop** | su flujo de release | próxima release |
| 4 | **OWS Store** | `fetch-projects.js` (build-time) + auditar uso runtime de la API | próxima release |

Reglas de convivencia (importantes):
- La URL vieja (`owsdatabase.onrender.com`) se **elimina gradualmente**, no de golpe: primero se agrega
  la nueva como principal, y Render queda como fallback para clientes viejos.
- Cambio de URL de emergencia: el frontend ya soporta `?api=` y `localStorage.ows_api_base` — sirve de
  palanca si hubiera que revertir sin release.
- Los releases de Hub/Android **solo se ejecutan cuando el usuario lo pida** (regla del workspace).

### 🤖 Fase 6 — Verificación final + monitoreo (~30 min)

Checklist de humo (contra `https://owsdatabase.<IP>.nip.io`):
- [ ] Login / SSO compartido (mismo `JWT_SECRET`) desde netlify.
- [ ] Noticias y Lanzamientos (datos vivos).
- [ ] Changelog del Hub + updater (`releases/latest/download/latest.json`).
- [ ] Descargas de proyectos (redirect 302 a GitHub/Cloudinary).
- [ ] WildTransfer: subir y bajar un archivo → **persistente** (sobrevive restart).
- [ ] socket.io (canales en vivo) a través de Caddy.
- [ ] Panel admin local contra la API nueva.
- [ ] Backups: correr script manual una vez + verificar el cron.
- [ ] Monitoreo externo: **UptimeRobot free** (5 min) a `/api/health` → alertas por email.
- [ ] `journalctl -u ows-server -f` sin errores recurrentes a los días de uso.

Decisión post-migración: Render se deja como fallback **2-4 semanas**; después (si todo está estable y
los clientes actualizaron) se decide si apagarlo. No hay apuro: cuesta $0.

---

## 6. Riesgos y mitigaciones

| Riesgo | Probabilidad | Mitigación |
|---|---|---|
| Falta de capacidad ARM en la región | Media | Reintentar en otro Availability Domain/horario; contingencia: 2 micro AMD (1 GB c/u, app+DB) o quedarse en Render |
| Sin tarjeta para verificar en Oracle | Baja | Anexo A (plan B sin tarjeta: PC + túnel) |
| Reclamo de instancia "ociosa" (>7 días con CPU/red/memoria bajas) | Baja-media | Tráfico real + monitor cada 5 min + `shared_buffers=2 GB`; Oracle avisa por email antes; **todo es reproducible: reinstalar = ~30 min** con este plan |
| nip.io caído | Muy baja | Formato idéntico `sslip.io` (mismo cambio de 1 línea) |
| Certificado Let's Encrypt rate-limited | Muy baja | Usar la variante sslip.io del mismo IP (documentado por el propio servicio) |
| Pérdida de datos en la migración | Baja | Doble etapa: la VM verifica contra la DB actual; recién después dump/restore con verificación de conteos; origen intacto 2 semanas |
| Cambio de `JWT_SECRET`/secrets | Media si se copia mal | Checklist Anexo B con énfasis en secretos idénticos |
| `bcrypt` no compila en ARM | Baja | `build-essential python3` instalados; compila en ~1-2 min |
| Puppeteer en ARM (no se usa) | — | `PUPPETEER_SKIP_DOWNLOAD=1` en cada `npm ci` |

## 7. Rollback

- **Antes de migrar los clientes:** abandonar/apagar la VM = impacto cero (Render intacto).
- **Después:** re-apuntar `DATABASE_URL` (2 min) y/o revertir la URL en clientes (push de 1 línea
  para web; los clientes desktop/Android viejos siguen en Render de todos modos).
- **Datos:** la DB de origen no se borra hasta 2 semanas después de la estabilización.

## 8. Cronograma estimado

| Fase | Quién | Tiempo |
|---|---|---|
| 0 — Preparación (cuenta + envs) | 👤 | 30-45 min |
| 1-3 — VM + DB + app + HTTPS | 🤖 | 2-3 h (una sesión) |
| 4 — Deploy continuo | 🤖 | 30 min |
| 5-6 — Clientes + verificación | 🤖👤 | 1 sesión + releases |
| **Total** | | **~1-2 días calendario** |

## 9. Lo que esto habilita (después de migrar)

- **WildTransfer persistente** (en Render Free los archivos volátiles se perdían en cada deploy).
- **Installers sin límites prácticos**: la VM puede servir descargas de >2 GB (que no entran en
  GitHub Releases) usando los 10 TB/mes — o seguir usando GitHub Releases/Cloudinary, como prefieras.
- **Base de datos sin techo de proveedor** (Neon free = 0.5 GB; la VM tiene 200 GB).
- **Cero cortes por bandwidth** para el resto del año, incluso con juegos grandes.
- Base lista para el día que quieran **dominio propio** (cambio único de URL).

---

## 10. Plan activo (2026-10-15): "Render optimizado" — sin tarjeta, $0

**Motivo:** no hay tarjeta disponible ni para la verificación de identidad de Oracle → migración
bloqueada. No hace falta igual: el camino sin tarjeta ya estaba encaminado y es este.

### 10.1 Por qué Render Free alcanza (incluso para proyectos grandes)
- El límite de 5 GB/mes se lo comían las **descargas de juegos que pasaban por el backend**
  (installers/APKs sin URL directa, vía API de itch) — principal sospechoso ya identificado.
- Esas descargas van **directo desde GitHub Releases / Cloudinary**: gratis y sin tope práctico.
  El handler de descargas ya soporta redirigir (302 ≈ 0 bytes de bandwidth); Hub y APKs ya lo usan.
  Falta la auditoría de los proyectos que todavía no tienen URL directa.
- La API es liviana y ya está comprimida (`9049544`: −73% medido). Con las descargas afuera, el
  consumo esperado es una fracción del 5 GB mensual.
- Crecimiento: archivos mayores a 2 GB (tope por archivo de GitHub Releases) → dividir en partes
  o usar Cloudinary / Hugging Face (hosting grande gratuito).

### 10.2 Tareas pendientes (cuando Render vuelva del reset de ciclo)
1. [ ] Verificar que deployaron `9049544` y `031bcb9` (si no: Manual Deploy → Deploy latest commit).
2. [ ] Auditoría de descargas: proyectos sin `installer_url` directa → asignar GitHub Releases o
   Cloudinary. Ídem `apk-download`. (Clave: sin esto, el 5 GB vuelve a consumirse.)
3. [ ] Configurar pinger externo gratis (UptimeRobot cada 5 min → `/ecoconsole/health`) para que el
   servicio **nunca duerma**: las 750 h/mes alcanzan para 24/7 (730 h) → 24/7 real, sin PC.
4. [ ] Medir consumo real: Render Dashboard → Bandwidth (primer mes con descargas afuera de Render).
5. [ ] Nota: NO se puede levantar el servicio antes del reset sin PC encendida (descartada por el
   usuario) ni tarjeta (descartada) → solo esperar el reinicio de ciclo (fecha en Render → Billing).

### 10.3 Barrido completo de alternativas (verificado 2026-10-15) — conclusión
No existe plataforma que sea a la vez: gratis + sin tarjeta + 24/7 sin PC + sin límites + capaz de
correr este backend. Las candidatas fallan en algo:

| Plataforma | Por qué queda descartada |
|---|---|
| Oracle · Google · AWS · Azure | piden tarjeta solo para verificar identidad (filtro anti-abuso) |
| Northflank (2 servicios always-on) | pide tarjeta al registrarse |
| Koyeb | desde feb-2026 pide tarjeta + retención US$29 |
| Fly.io | eliminó el free tier (2024) |
| Railway | free = US$1/mes de crédito (no alcanza para 24/7) |
| Hugging Face Spaces | Docker ahora requiere plan PRO (cambio 2026) |
| Back4App Containers | free = ~1 hora de vida por deploy (para pruebas) |
| SnapDeploy | 100 h/mes y solo despierta con visita humana |
| ngrok | 1 GB/mes, 20k requests/mes y página intersticial |
| Qoddi · Sevalla | el free solo permite sitios estáticos |
| Serv00 | ToS prohíbe usos fuera de "website hosting" y archivos de juegos |
| Cloudflare Workers · Deno · Leapcell · Vercel · Netlify | no corren este stack (sin fs, sin socket.io real, serverless) |
| PC + túnel (Tailscale) | el usuario no puede mantener la PC encendida 24/7 |

**Conclusión:** Render Free ES la solución práctica — con el pinger (§10.2.3) queda 24/7 sin PC, y
con las descargas afuera (§10.2.2) el límite de 5 GB deja de importar aunque los proyectos crezcan
enormemente. $0, sin tarjeta, sin PC. Si algún día aparece una tarjeta, Oracle (secciones 1-9) sigue
siendo el upgrade natural (10 TB/mes).

### 10.4 Failover anti-suspensión → espejo `owsdatabase2` (implementado 2026-10-15)
Los clientes web del ecosistema ahora caen solos al espejo `https://owsdatabase2.onrender.com`
cuando la principal no responde, y vuelven solos cuando se recupera. No hay que tocar cada
endpoint: `web/OWS/ows-api-failover.js` envuelve `window.fetch` una sola vez.
- **Cubre:** Hub web (owshub.netlify.app), OWS Hub desktop y Android (llegan vía `sync:app`),
  Ocean Pay web y el panel admin local (se puede publicar noticias aunque la principal esté
  caída). Los links de descarga también apuntan a la base sana (`preferredUrl`).
- **Mecánica:** error de red/CORS o HTTP 502/503/504 → se reintenta contra la otra base; sonda a
  `/ecoconsole/health` cada 45 s para volver a la principal; la pestaña recuerda la última base
  sana (sessionStorage). `?api=` / `localStorage.ows_api_base` siguen mandando (override = pruebas,
  no se toca). Verificado con tests en sandbox (7/7).
- **Requisitos del espejo:** mismo código (`main`), mismas envs (Anexo B — sin reemplazar secretos;
  p. ej. `JWT_SECRET` idéntico para que los tokens sirvan en ambos) y **la MISMA base de datos**.
  Idealmente el espejo vive en OTRA cuenta/workspace de Render (una suspensión de bandwidth no
  voltea los dos).
- **OWS Store:** mismo failover inline en su `index.html` (toma efecto en su próximo build).
  Otras apps propias (OWS News, WildTransfer, Ocean Pay desktop): pueden incluir el mismo módulo
  antes de su primer fetch.

---

## Anexo A — (DESCARTADO 2026-10-15) PC del estudio + Tailscale Funnel

> ❌ Descartado: el usuario no puede mantener la PC encendida 24/7. Queda documentado por si en
> el futuro existe una PC (o Raspberry Pi) que pueda quedar siempre encendida.

**Cómo funcionaría:** `server.js` corre en la PC del estudio (Node local) y se publica a internet
con **Tailscale Funnel**: URL fija `https://<pc>.<tailnet>.ts.net` con HTTPS válido — sin abrir
puertos del router (anda incluso detrás de NAT/CGNAT).

- **Pros:** $0, sin tarjeta, sin dominio, sin límite de bandwidth publicado (uso razonable);
  URL estable; los clientes se migran igual que en la Fase 5 (y se puede probar antes con el
  override `?api=` sin tocar nada).
- **Contras:** la PC debe quedar encendida 24/7 para el servicio; el plan free de Tailscale está
  pensado para **uso personal (no comercial)** — usarlo para la producción del estudio es zona
  gris de sus términos; no sirve para servir descargas pesadas (eso sigue en GitHub/Cloudinary).
- **Pasos:** cuenta Tailscale (login con Google/GitHub, sin tarjeta) → instalar la app en la PC →
  `tailscale funnel 3000` (mapea HTTPS 443 → puerto local 3000) → probar
  `https://<pc>.<tailnet>.ts.net/api/health` + override en la web → migrar clientes (Fase 5).
- En Windows: dejar Node + Funnel como servicio (NSSM o tarea de inicio) para arranque automático.

⚠️ **Descartados:** ver la tabla completa del barrido en §10.3 (ngrok, SnapDeploy, Back4App,
Railway, HF Spaces, Serv00, Northflank, etc.).

**Créditos de estudiante (no aplica):** nadie del estudio tiene email de estudiante (consultado
2026-10-15). Si eso cambia, el **GitHub Student Developer Pack** incluye créditos cloud sin tarjeta
(p. ej. Azure for Students US$100/año) y dominio gratis ~1 año.

## Anexo B — Checklist de variables de entorno (34)

| Grupo | Variables |
|---|---|
| DB | `DATABASE_URL` (nueva, local) · `PGHOST/PGPORT/PGUSER/PGPASSWORD/PGDATABASE` (fallback, no se usan si hay DATABASE_URL) |
| Core / secretos ⚠️ (copiar idénticos) | `JWT_SECRET` · `OWS_ADMIN_SECRET` · `STUDIO_SECRET` · `WNS_CLIENT_SECRET` · `WNS_PACKAGE_SID` |
| Ops | `NODE_ENV=production` · `PORT=3000` · `OWS_SHUTDOWN_RETURN_DATE` · `WILDER_GAMBIT_INSTALLER_URL` |
| Flags | `DISABLE_OWS_REWORK_RESTRICTION` · `OP_LEGACY_BALANCE_RESCUE` · `ENABLE_OWS_STORE_PROJECTS_SEED` |
| Terceros | `BREVO_API_KEY` · `ITCH_API_KEY` · `ITCHIO_API_KEY` · `GEMINI_API_KEY` · `MP_ACCESS_TOKEN` · `GH_TOKEN` · `GITHUB_TOKEN` |
| Firebase / FCM | `FCM_PROJECT_ID` · `FCM_CLIENT_EMAIL` · `FCM_PRIVATE_KEY` · `FCM_SERVER_KEY` · `FIREBASE_PROJECT_ID` · `FIREBASE_CLIENT_EMAIL` · `FIREBASE_PRIVATE_KEY` · `FIREBASE_SERVER_KEY` · `FIREBASE_SERVICE_ACCOUNT_JSON` |

## Anexo C — Comandos de mantenimiento (día a día)

```bash
sudo systemctl restart ows-server     # reiniciar
sudo systemctl status ows-server      # estado
journalctl -u ows-server -f           # logs en vivo
journalctl -u caddy -f                # logs del proxy
sudo -u postgres psql owsdatabase     # consola SQL
/opt/ows/backup-db.sh                 # backup manual de la DB
ls -lh /var/backups/ows/              # ver backups existentes

# Deploy manual (si GitHub Actions no corre):
cd /opt/owsdatabase && git fetch origin main && git reset --hard origin/main && \
  PUPPETEER_SKIP_DOWNLOAD=1 npm ci --omit=dev && sudo systemctl restart ows-server
```

---
*Documento vivo: al terminar cada fase se marcará el progreso acá mismo.*
