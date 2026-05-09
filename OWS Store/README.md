# OWS Nexus Store - Electron Desktop

App de escritorio para **OWS Nexus Store** (Central Studio Hub). Conecta a `https://owsdatabase.onrender.com` para cargar proyectos desde `ows_projects`.

## Requisitos

- Node.js 18+
- npm

## Instalación

```bash
cd "OWS Store Electron"
npm install
```

## Desarrollo

```bash
npm start
```

## Generar instalador Windows

1. **Añade el icono** en `build/icon.ico` (usa el prompt de `ICON_PROMPT.md`).
2. Ejecuta:

```bash
npm run dist
```

Los instaladores se generan en `dist/`:
- `OWS Nexus Store Setup 1.0.0.exe` (NSIS)
- `OWS Nexus Store 1.0.0.exe` (portable)

## Auto-actualización

La app busca actualizaciones al iniciar. Para que funcione:

1. Tras `npm run dist`, sube a un servidor web la carpeta de salida o estos archivos:
   - `OWS Nexus Store Setup X.X.X.exe`
   - `latest.yml`
   - `OWS Nexus Store Setup X.X.X.exe.blockmap`
2. En `package.json` → `build.publish.url` pon la URL base (ej: `https://tudominio.com/ows-store/`).
3. El `latest.yml` indica la versión actual; al publicar uno nuevo, la app descargará e instalará.

## Prompts para iconos

- **OWS Nexus Store**: ver `ICON_PROMPT.md`
- **Otros proyectos** (datos de `ows_projects`): ejecuta `node scripts/fetch-projects.js`
