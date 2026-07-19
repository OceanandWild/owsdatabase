# OWS Store - Tauri Release Helper
# Usage:
#   powershell.exe -ExecutionPolicy Bypass -File "scripts\release-ows-store.ps1" -owsVersion 2026.7.19-t1400 [-cargoVersion 0.1.0]
#
# Parameters:
#   owsVersion:  OWS date version for GitHub release tag and APP_VERSION (required)
#   cargoVersion: Cargo.toml semver version (optional, defaults to 0.1.0)

param(
    [string]$owsVersion,
    [string]$cargoVersion = "0.1.0"
)

$ROOT = $PSScriptRoot | Split-Path -Parent
$OWS_STORE_DIR = Join-Path $ROOT "OWS Store"
$CARGO_TOML = Join-Path $OWS_STORE_DIR "src-tauri\Cargo.toml"
$INDEX_HTML = Join-Path $OWS_STORE_DIR "index.html"
$DIST_INDEX = Join-Path $OWS_STORE_DIR "dist\index.html"
$UPDATER_KEY = Join-Path $OWS_STORE_DIR "src-tauri\updater-keys.json"
$MANIFEST_JSON = Join-Path $ROOT "ows-store-tauri-update.json"

$GH = "C:\Program Files\GitHub CLI\gh.exe"

function Write-Step($msg) { Write-Host "`n>>> $msg" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "    OK: $msg" -ForegroundColor Green }
function Write-Err($msg)  { Write-Host "    ERROR: $msg" -ForegroundColor Red }

# ── Validate inputs ────────────────────────────────────────────────────────────
if (-not $owsVersion) {
    Write-Err "Debes especificar -owsVersion (ej: 2026.7.19-t1400)"
    exit 1
}
if ($owsVersion -notmatch '^\d{4}\.\d{1,2}\.\d{1,2}-t\d{4}$') {
    Write-Err "owsVersion debe tener formato YYYY.M.D-tHHMM (ej: 2026.7.19-t1400)"
    exit 1
}

$TAG = "v$owsVersion"
$INSTALLER_NAME = "OWS Store_${cargoVersion}_x64-setup.exe"
$INSTALLER_PATH = Join-Path $OWS_STORE_DIR "src-tauri\target\release\bundle\nsis\$INSTALLER_NAME"

# ── 1. Update versions ─────────────────────────────────────────────────────────
Write-Step "1. Actualizando APP_VERSION en index.html"
$rawIndex = Get-Content -Raw $INDEX_HTML
if ($rawIndex -match "(window\.APP_VERSION\s*=\s*)'[^']+'") {
    $newIndex = $rawIndex -replace [regex]::Escape($matches[0]), "`$1'$owsVersion'"
    [System.IO.File]::WriteAllText($INDEX_HTML, $newIndex, (New-Object System.Text.UTF8Encoding($false)))
    Write-OK "APP_VERSION actualizado a $owsVersion en index.html"
}
if (Test-Path $DIST_INDEX) {
    $rawDist = Get-Content -Raw $DIST_INDEX
    if ($rawDist -match "(window\.APP_VERSION\s*=\s*)'[^']+'") {
        $newDist = $rawDist -replace [regex]::Escape($matches[0]), "`$1'$owsVersion'"
        [System.IO.File]::WriteAllText($DIST_INDEX, $newDist, (New-Object System.Text.UTF8Encoding($false)))
        Write-OK "APP_VERSION actualizado a $owsVersion en dist/index.html"
    }
}

Write-Step "2. Actualizando version en Cargo.toml"
$cargoRaw = Get-Content -Raw $CARGO_TOML
if ($cargoRaw -match '^version\s*=\s*"[^"]+"') {
    $newCargo = $cargoRaw -replace [regex]::Escape($matches[0]), "version = `"$cargoVersion`""
    [System.IO.File]::WriteAllText($CARGO_TOML, $newCargo, (New-Object System.Text.UTF8Encoding($false)))
    Write-OK "Cargo.toml version actualizado a $cargoVersion"
}

# ── 2. Build ───────────────────────────────────────────────────────────────────
Write-Step "3. Ejecutando cargo tauri build..."
Push-Location $OWS_STORE_DIR
try {
    & "cargo" tauri build 2>&1
    if ($LASTEXITCODE -ne 0) { throw "cargo tauri build falló" }
    Write-OK "Build completado"
} catch {
    Write-Err "Error: $_"
    Pop-Location
    exit 1
}
Pop-Location

if (-not (Test-Path $INSTALLER_PATH)) {
    Write-Err "No se encontró el installer en: $INSTALLER_PATH"
    exit 1
}
Write-OK "Installer: $INSTALLER_PATH"

# ── 3. Sign installer ──────────────────────────────────────────────────────────
Write-Step "4. Firmando installer con Tauri private key..."
$signOutput = & "cargo" tauri sign --private-key $UPDATER_KEY -f $INSTALLER_PATH 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Err "Firma falló. Se omite (puedes firmar manualmente luego)."
    $SIGNATURE = ""
} else {
    # Extraer signature del output (tauri sign imprime la firma en base64)
    $SIGNATURE = ($signOutput | Select-String -Pattern "^dW50cnVzdGVk" | Select-Object -First 1).Line.Trim()
    if (-not $SIGNATURE) { $SIGNATURE = $signOutput[-1].Trim() }
    Write-OK "Firma generada: ${SIGNATURE.Substring(0, 32)}..."
}

# ── 4. Generate update manifest ────────────────────────────────────────────────
Write-Step "5. Generando ows-store-tauri-update.json"
$pubDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$manifest = @{
    version = $cargoVersion
    notes  = "OWS Store $owsVersion"
    pub_date = $pubDate
    platforms = @{
        "windows-x86_64" = @{
            signature = $SIGNATURE
            url = "https://github.com/OceanandWild/owsdatabase/releases/download/$TAG/$INSTALLER_NAME"
        }
    }
} | ConvertTo-Json -Depth 10
$manifest | Set-Content -Path $MANIFEST_JSON -Encoding UTF8
Write-OK "Manifest generado en $MANIFEST_JSON"

# ── 5. Create GitHub release ───────────────────────────────────────────────────
Write-Step "6. Creando GitHub Release en OceanandWild/owsdatabase..."
$releaseNotesInput = Read-Host "Release notes (texto libre, Enter para omitir)"
if (-not $releaseNotesInput) { $releaseNotesInput = "OWS Store $owsVersion" }

$releaseArgs = @(
    "release", "create", $TAG,
    "--repo", "OceanandWild/owsdatabase",
    "--title", "OWS Store $owsVersion",
    "--notes", $releaseNotesInput,
    $INSTALLER_PATH
)
if ($MANIFEST_JSON -and (Test-Path $MANIFEST_JSON)) {
    $releaseArgs += $MANIFEST_JSON
}
$releaseOutput = & $GH @releaseArgs 2>&1
if ($LASTEXITCODE -ne 0) {
    # Maybe release already exists — try uploading assets
    Write-Err "Creación de release falló. Intentando subir assets a release existente..."
    & $GH release upload $TAG --repo OceanandWild/owsdatabase --clobber $INSTALLER_PATH 2>&1
    if ($MANIFEST_JSON -and (Test-Path $MANIFEST_JSON)) {
        & $GH release upload $TAG --repo OceanandWild/owsdatabase --clobber $MANIFEST_JSON 2>&1
    }
} else {
    Write-OK "GitHub Release creado: $TAG"
    Write-OK "$releaseOutput"
}

# ── 6. Register version in DB ──────────────────────────────────────────────────
Write-Step "7. Registrando versión en OWS Database..."
$API = "https://owsdatabase.onrender.com"
$TOKEN = $env:OWS_ADMIN_SECRET
if ($TOKEN) {
    $body = @{ version = $owsVersion; platform = "windows" } | ConvertTo-Json
    try {
        $r = Invoke-RestMethod -Uri "$API/ows-store/projects/ows-store/version" `
            -Method PATCH `
            -Headers @{ "Content-Type"="application/json"; "x-ows-admin-token"=$TOKEN } `
            -Body $body `
            -ErrorAction Stop
        Write-OK "Versión $owsVersion registrada en DB"
    } catch {
        Write-Err "No se pudo registrar versión en DB: $_"
    }
} else {
    Write-Info "OWS_ADMIN_SECRET no definido — salteando registro en DB"
}

# ── 7. Summary ─────────────────────────────────────────────────────────────────
Write-Step "8. Resumen"
Write-Host "  OWS Version : $owsVersion" -ForegroundColor Green
Write-Host "  Cargo Version: $cargoVersion" -ForegroundColor Green
Write-Host "  Tag         : $TAG" -ForegroundColor Green
Write-Host "  Installer   : $INSTALLER_NAME" -ForegroundColor Green
Write-Host "  Release     : https://github.com/OceanandWild/owsdatabase/releases/tag/$TAG" -ForegroundColor Green
Write-Host ""
Write-Host "IMPORTANTE:" -ForegroundColor Yellow
Write-Host "  1. El ows-store-tauri-update.json debe estar en la raíz del repo owsdatabase." -ForegroundColor Yellow
Write-Host "  2. La próxima vez que el OWS Store actual ejecute checkOwsStoreSelfUpdate()," -ForegroundColor Yellow
Write-Host "     detectará la nueva versión ($owsVersion > APP_VERSION actual)." -ForegroundColor Yellow
Write-Host "  3. Para mantener el CI, actualiza release-windows-universal.yml en owsdatabase." -ForegroundColor Yellow
