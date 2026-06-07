# Script de Respaldo Automatizado OWS
# Ubicación: $BACKUP_WEB\..\Ocean and Wild Studios\scripts\backup-to-github.ps1
# Lanzador: $BACKUP_WEB\..\Ocean and Wild Studios\OWS Store\scripts\ejecutar-backup.bat

[CmdletBinding()]
param(
    [string]$version = ""
)

$ErrorActionPreference = "Stop"

$DEV_WEB = "C:\Users\hachi\OneDrive\Escritorio\Ocean and Wild Studios"
$DEV_UNITY = "C:\Users\hachi\OneDrive\Escritorio\OWS Unity"
$BACKUP_WEB = "C:\Users\hachi\OneDrive\Escritorio\owsrecover"
$BACKUP_UNITY = "C:\Users\hachi\OneDrive\Escritorio\owsrecover-unity"

# ─────────────────────────────────────────────────────────────────────────────
# 0. RESOLVER VERSION + TIMESTAMP URUGUAY
# ─────────────────────────────────────────────────────────────────────────────
# Uruguay = America/Montevideo. .NET expone zonas via TimeZoneInfo.
try {
    $uryTz = [System.TimeZoneInfo]::FindSystemTimeZoneById('America/Montevideo')
} catch {
    $uryTz = $null
}
$uryNow = if ($uryTz) { [System.TimeZoneInfo]::ConvertTime([System.DateTime]::Now, $uryTz) } else { Get-Date }
$uryTimestamp = $uryNow.ToString('o')
$uryCompact = $uryNow.ToString('yyyy.M.d-tHHmm')

# Si el usuario paso -version, ese valor va literal (es la version real del
# release/publicacion). Si no, registramos un marcador "WIP" con la fecha
# y hora Uruguay para que el Centro de Control OWS pueda ver cuando se
# hicieron cambios de preparacion, separados de releases reales.
$isWip = $false
if ([string]::IsNullOrWhiteSpace($version)) {
    $version = "WIP-$uryCompact"
    $isWip = $true
}
Write-Host "=== INICIANDO RESPALDO AUTOMATICO OWS ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Version registrada: $version" -ForegroundColor $(if ($isWip) { 'Yellow' } else { 'Green' })
Write-Host "Timestamp Uruguay : $uryTimestamp" -ForegroundColor DarkGray
Write-Host ""

# ─────────────────────────────────────────────────────────────────────────────
# 1. ACTUALIZAR PROYECTOS WEB
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ">> Sincronizando proyectos Web..." -ForegroundColor Yellow

$webProjects = Get-ChildItem -Path $DEV_WEB -Directory | Where-Object { 
    $_.Name -notmatch "Discontinued Projects" -and 
    (Test-Path (Join-Path $_.FullName "index.html"))
}

foreach ($proj in $webProjects) {
    $src = $proj.FullName
    $dest = Join-Path $BACKUP_WEB $proj.Name
    
    Write-Host "   Sincronizando: $($proj.Name)" -ForegroundColor DarkGray
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    
    # Robocopy para copiar de forma inteligente
    $robocopyArgs = @(
        "`"$src`"", "`"$dest`"", "/E", "/NFL", "/NDL", "/NP", "/R:1", "/W:1",
        "/XD", "node_modules", "android\build", "android\.gradle", "android\app\build", "android\capacitor-cordova-android-plugins", ".git", "build", "dist", "out", "www", ".cache",
        "/XF", "*.apk", "*.aab", "*.keystore", "*.jks", "*.log", "shadow_pulse_astats.txt", "temp_eclipse_astats.txt"
    )
    & robocopy $robocopyArgs | Out-Null
}

# Sincronizar scripts y secrets específicamente
Write-Host "   Sincronizando scripts y secrets..." -ForegroundColor DarkGray
New-Item -ItemType Directory -Path (Join-Path $BACKUP_WEB "OWS Store\scripts") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $BACKUP_WEB "secrets") -Force | Out-Null
& robocopy "`"$DEV_WEB\OWS Store\scripts`"" "`"$BACKUP_WEB\OWS Store\scripts`"" /E /NFL /NDL /NP /R:1 /W:1 | Out-Null
& robocopy "`"$DEV_WEB\secrets`"" "`"$BACKUP_WEB\secrets`"" /E /NFL /NDL /NP /R:1 /W:1 | Out-Null

# ─────────────────────────────────────────────────────────────────────────────
# 1.5. GENERAR BACKUP_STATUS.json (fuente autoritativa para el Admin Panel)
# ─────────────────────────────────────────────────────────────────────────────
# El server de OWS Store lee este archivo desde owsrecover para mostrar el
# estado real de los respaldos en el Centro de Control OWS. NO hardcodeamos
# la lista de proyectos: iteramos sobre los mismos $webProjects que se
# sincronizaron arriba, asi cualquier proyecto nuevo (que tenga index.html
# en $DEV_WEB) queda automaticamente registrado.
Write-Host "   Generando BACKUP_STATUS.json..." -ForegroundColor DarkGray
$backupTimestamp = $uryTimestamp
$statusProjects = [ordered]@{}
foreach ($proj in $webProjects) {
    # La clave es el nombre exacto del folder en owsrecover (case-sensitive,
    # con espacios). Debe matchear el campo github_folder del DB. Usamos
    # el nombre del proyecto tal como quedo en disco, sin normalizar.
    $statusProjects[$proj.Name] = $backupTimestamp
}
# Metadata global del script
# - current_version: la version pasada por parametro (o WIP-YYYY.M.D-tHHMM si no)
# - is_wip: true cuando es un respaldo de cambios sin release publicado
# - last_full_backup: timestamp ISO Uruguay
# - schema_version: 1 (estable)
$statusObject = [ordered]@{
    schema_version   = 1
    last_full_backup = $backupTimestamp
    script_version   = "1.1"
    source           = "scripts/backup-to-github.ps1"
    current_version  = $version
    is_wip           = $isWip
    timezone         = "America/Montevideo"
    web_projects     = $statusProjects
}
$statusJson = $statusObject | ConvertTo-Json -Depth 5
$statusPath = Join-Path $BACKUP_WEB "BACKUP_STATUS.json"
Set-Content -LiteralPath $statusPath -Value $statusJson -Encoding UTF8 -Force
# NOTA: PowerShell 5.1 Set-Content -Encoding UTF8 escribe BOM (EF BB BF) que rompe JSON.parse en Node.
# Lo removemos explicitamente para mantener el archivo compatible con clientes estrictos.
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($statusPath, $statusJson, $utf8NoBom)
Write-Host "   BACKUP_STATUS.json escrito con $($statusProjects.Count) proyectos (version: $version, wip: $isWip)" -ForegroundColor DarkGray

# ─────────────────────────────────────────────────────────────────────────────
# 2. ACTUALIZAR PROYECTOS UNITY
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ">> Sincronizando proyectos Unity..." -ForegroundColor Yellow

$unityProjects = @("Animaciones", "Bomberman", "Stupid Zombies", "Tower Defense")
$includeUnityDirs = @("Assets", "ProjectSettings", "UserSettings")

foreach ($proj in $unityProjects) {
    $srcProj = Join-Path $DEV_UNITY $proj
    $destProj = Join-Path (Join-Path $BACKUP_UNITY "Unity") $proj
    
    if (Test-Path $srcProj) {
        Write-Host "   Sincronizando: $proj" -ForegroundColor DarkGray
        New-Item -ItemType Directory -Path $destProj -Force | Out-Null
        
        foreach ($folder in $includeUnityDirs) {
            $srcFolder = Join-Path $srcProj $folder
            $destFolder = Join-Path $destProj $folder
            if (Test-Path $srcFolder) {
                & robocopy "`"$srcFolder`"" "`"$destFolder`"" /E /NFL /NDL /NP /R:1 /W:1 | Out-Null
            }
        }
        # Copiar archivos de configuración sueltos
        Get-ChildItem -Path $srcProj -File | ForEach-Object {
            if ($_.Extension -in @(".csproj", ".sln", ".json", ".txt")) {
                Copy-Item -Path $_.FullName -Destination $destProj -Force
            }
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 3. ELIMINAR BASURA RESIDUAL (Dists, Videos pesados, temporales)
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ">> Ejecutando limpieza residual..." -ForegroundColor Yellow
$cleanupScript = Join-Path $BACKUP_WEB "_cleanup_heavy.ps1"
if (Test-Path $cleanupScript) {
    & powershell -ExecutionPolicy Bypass -File $cleanupScript | Out-Null
}

# ─────────────────────────────────────────────────────────────────────────────
# 4. SUBIR CAMBIOS DE WEB A GITHUB
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ">> Subiendo actualizaciones Web & Secrets a GitHub..." -ForegroundColor Green
Set-Location $BACKUP_WEB
git add .
$status = git status --porcelain
if ($status) {
    $commitType = if ($isWip) { "WIP" } else { "Release" }
    $commitMsg = "$commitType automatico - Web & Secrets [$version | $uryCompact UY]"
    git commit -m $commitMsg
    git pull origin main --no-rebase -s recursive -X ours --quiet
    git push origin main
    Write-Host "   ¡Web & Secrets subidos con éxito!" -ForegroundColor Green
} else {
    Write-Host "   Sin cambios en proyectos Web." -ForegroundColor DarkGray
}

# ─────────────────────────────────────────────────────────────────────────────
# 5. SUBIR CAMBIOS DE UNITY A GITHUB
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ">> Subiendo actualizaciones Unity a GitHub..." -ForegroundColor Green
Set-Location $BACKUP_UNITY
git add .
$statusUnity = git status --porcelain
if ($statusUnity) {
    git commit -m "Backup automatico - Unity [$(Get-Date -Format 'yyyy-MM-dd HH:mm')]"
    git pull origin main --no-rebase -s recursive -X ours --quiet
    git push origin main
    Write-Host "   ¡Unity subido con éxito!" -ForegroundColor Green
} else {
    Write-Host "   Sin cambios en proyectos Unity." -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "=== RESPALDO COMPLETADO CORRECTAMENTE ===" -ForegroundColor Cyan
Write-Host "Presione cualquier tecla para cerrar..."
Read-Host
