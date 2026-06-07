# Reglas Críticas del Workspace (Ocean and Wild Studios)

Estas reglas tienen prioridad operativa cuando se trabaje en este workspace, especialmente en `OWS Store/`.

1. OWS Store: cierre bloqueante
- No cerrar tareas sin trazabilidad de version y cambios.
- Changelog/evento/noticia deben quedar reflejados en la timeline central de OWS Store.

2. Flujo de release
- Ejecutar build/release solo cuando el usuario lo pida explicitamente.
- Seguir `workspace-instructions.txt` y `scripts/release.ps1`.

3. Higiene de cambios
- No incluir archivos o proyectos ajenos a la tarea en commit/push.
- Si se toca backend compartido, incluir `server.js`.

4. Regla de borradores y redaccion
- En `changelog-drafts/`, no incluir contenido intermedio o en desarrollo (WIP).
- No documentar en borradores operaciones internas de gestion (por ejemplo, creacion de evento por API) salvo pedido explicito del usuario.
- Evitar texto literal calcado del pedido; redactar de forma natural y contextual.

5. Estandar para spritesheets malformados (obligatorio)
- Si un spritesheet no divide exacto por su grilla objetivo, primero normalizar canvas y luego recortar.
- Evitar recorte manual frame por frame cuando se pueda resolver con pipeline automatizado.
- Pipeline recomendado (ImageMagick):
  1) ajustar canvas para que sea divisible por la grilla (`-extent`),
  2) recortar por grilla (`-crop CxR@ +repage +adjoin`),
  3) normalizar cada frame a tamano fijo centrado (`-trim +repage -gravity center -extent`).
- Si hay overflow visual entre celdas, priorizar secuencias de frames estables en codigo hasta regenerar assets.

6. Regla de Integridad de Keystore Android (OBLIGATORIO)
- ESTRICTAMENTE PROHIBIDO: Ningún agente debe sugerir, generar o reemplazar el keystore de Android (`ANDROID_SIGNING_KEY_BASE64`) en GitHub Secrets.
- Todo el ecosistema de OWS usa un único certificado universal. Reemplazarlo corrompe la ruta de actualización para todos los usuarios (error "Paquete no válido").
- Si hay problemas de firma, revisar `build.gradle` y el workflow de GitHub, pero NUNCA rotar la llave criptográfica.

7. Backup a owsrecover (OBLIGATORIO)
- SIEMPRE usar `scripts/backup-to-github.ps1` (o el lanzador `OWS Store/scripts/ejecutar-backup.bat`) para sincronizar a owsrecover.
- NUNCA usar `git add/commit/push` directo desde la carpeta owsrecover: eso no actualiza `BACKUP_STATUS.json` y rompe el Centro de Control OWS.
- Cada vez que se hagan cambios de código (WIP) o se publique una release, se DEBE correr el script para registrar la versión con timestamp Uruguay.
- Si el usuario NO pidió release/publicación → correr `ejecutar-backup.bat` sin parámetros (queda como `WIP-YYYY.M.D-tHHMM`).
- Si el usuario SÍ pidió release → correr `ejecutar-backup.bat -version <version-real>` (la misma que se bumpea en OWS Store).
- WIP ≠ Release. WIP = cambios de preparación, no publicados. Release = cambio publicado con versión fija.

8. OWS Admin Panel = SOLO LOCAL (OBLIGATORIO)
- La carpeta `OWS Admin Panel/` contiene secretos, rutas internas y lógica de autenticación. NUNCA debe estar en owsdatabase ni en owsrecover como archivo trackeado.
- Está en `.gitignore` (carpeta entera). Si se trackeó por error, usar `git rm --cached` para sacarlo.
- El servidor de producción (Render) NUNCA debe servir el panel: la línea `app.use('/ows-admin-panel', express.static(...))` está PROHIBIDA.
- Para usar el panel: abrir localmente vía Live Server (VSCode, puerto 5501) o `npx http-server`. La API_BASE se autodetecta y apunta a `https://owsdatabase.onrender.com` en cualquier caso local.
- CORS ya está abierto (`origin: true, credentials: true`) para permitir llamadas desde localhost/file:// al Render.
