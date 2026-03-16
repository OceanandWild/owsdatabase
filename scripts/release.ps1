# OWS Store - Universal Release Script
# Usage: .\scripts\release.ps1 -project <slug> -version 2026.X.X-tHHMM
# New project: .\scripts\release.ps1 -newProject -project <slug> -version ... -projectName "Name" -projectDir "Dir" -projectRepo "repo"
#
# IMPORTANTE: Ejecutar con:
#   powershell.exe -ExecutionPolicy Bypass -File ".\scripts\release.ps1" -project ows-store -version 2026.X.X-tHHMM

param(
    [string]$project,
    [string]$version,
    [string]$platform = "windows",
    [switch]$newProject,
    [string]$projectName,
    [string]$projectDir,
    [string]$projectRepo,
    [string]$packageId
)

# ── Config ────────────────────────────────────────────────────────────────────
$GH       = "C:\Program Files\GitHub CLI\gh.exe"
$API      = "https://owsdatabase.onrender.com"
$TOKEN    = $env:OWS_ADMIN_SECRET
$ORG      = "OceanandWild"
$ROOT     = $PSScriptRoot | Split-Path -Parent

# ── Project map ──────────────────────────────────────────────────────────────
$PROJECTS = @{
    "ows-store"            = @{ repo = "owsdatabase";            dir = "OWS Store";              platforms = @("windows") }
    "wildweapon-mayhem"    = @{ repo = "wildweapon-mayhem";      dir = "WildWeapon Mayhem";       platforms = @("windows") }
    "savagespaceanimals"   = @{ repo = "savagespaceanimals";     dir = "Savage Space Animals";    platforms = @("windows") }
    "oceanpay"             = @{ repo = "oceanpay";               dir = "Ocean Pay Electron";      platforms = @("windows") }
    "floretshop"           = @{ repo = "floretshop";             dir = "Floret Shop";             platforms = @("windows","android") }
    "wildtransfer"         = @{ repo = "wildtransfer";           dir = "WildTransfer";            platforms = @("windows","android") }
    "a-wild-question-game" = @{ repo = "a-wild-question-game";   dir = "A Wild Question Game";    platforms = @("windows","android") }
    "velocity-surge"       = @{ repo = "velocity-surge";         dir = "Velocity Surge";          platforms = @("windows") }
    "wildwave"             = @{ repo = "wildwave";               dir = "WildWave";                platforms = @("windows") }
    "ecoxion"              = @{ repo = "ecoxion";                dir = "Ecoxion";                 platforms = @("windows") }
    "dinobox"              = @{ repo = "owsdatabase";            dir = "DinoBox";                 platforms = @("windows") }
    "wilddestiny"          = @{ repo = "wilddestiny";            dir = "Wild Destiny";            platforms = @("windows") }
}

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Step($msg) { Write-Host "`n>>> $msg" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "    OK: $msg" -ForegroundColor Green }
function Write-Err($msg)  { Write-Host "    ERROR: $msg" -ForegroundColor Red }
function Write-Info($msg) { Write-Host "    $msg" -ForegroundColor Gray }

function Require-Token {
    if (-not $TOKEN) {
        Write-Err "OWS_ADMIN_SECRET no definido. Ejecuta: `$env:OWS_ADMIN_SECRET = 'MUFASA1939'"
        exit 1
    }
}

# ── Wait for GitHub asset to exist (prevents 404 on updater) ─────────────────
function Wait-GithubAsset {
    param([string]$Repo, [string]$Tag, [string]$AssetPattern, [int]$MaxMinutes = 15)

    $url      = "https://api.github.com/repos/$ORG/$Repo/releases/tags/$Tag"
    $deadline = (Get-Date).AddMinutes($MaxMinutes)
    $attempt  = 0

    Write-Step "Esperando asset en GitHub ($Repo @ $Tag)..."
    Write-Info  "Patron buscado: $AssetPattern"
    Write-Info  "Timeout: $MaxMinutes minutos"

    while ((Get-Date) -lt $deadline) {
        $attempt++
        try {
            $headers  = @{ "Accept" = "application/vnd.github+json"; "User-Agent" = "OWSReleaseScript/1.0" }
            $response = Invoke-RestMethod -Uri $url -Headers $headers -ErrorAction Stop
            $assets   = $response.assets | Where-Object { $_.name -like $AssetPattern }

            if ($assets -and $assets.Count -gt 0) {
                $asset = $assets[0]
                # Esperar a que el upload este completo (state = uploaded)
                if ($asset.state -eq "uploaded") {
                    Write-OK "Asset listo: $($asset.name) ($([math]::Round($asset.size/1MB, 1)) MB)"
                    return $true
                } else {
                    Write-Info "[$attempt] Asset encontrado pero aun subiendo (state: $($asset.state))..."
                }
            } else {
                Write-Info "[$attempt] Asset no disponible aun (release existe: $($response.id -ne $null))..."
            }
        } catch {
            Write-Info "[$attempt] Release no existe aun en GitHub..."
        }

        Start-Sleep -Seconds 20
    }

    Write-Err "Timeout esperando asset ($MaxMinutes min). El workflow puede aun estar corriendo."
    Write-Info "Revisa: https://github.com/$ORG/$Repo/actions"
    return $false
}

# ── Register version in DB ────────────────────────────────────────────────────
function Register-Version {
    param([string]$Slug, [string]$Ver, [string]$Plat = "windows")
    Require-Token

    $body = @{ version = $Ver; platform = $Plat } | ConvertTo-Json
    try {
        $r = Invoke-RestMethod -Uri "$API/ows-store/projects/$Slug/release" `
            -Method POST `
            -Headers @{ "Content-Type"="application/json"; "x-ows-admin-token"=$TOKEN } `
            -Body $body `
            -ErrorAction Stop
        Write-OK "Version $Ver ($Plat) registrada en DB para $Slug"
        return $true
    } catch {
        Write-Err "No se pudo registrar version en DB: $_"
        return $false
    }
}

# ── Register new project in DB ────────────────────────────────────────────────
function Register-NewProject {
    param([string]$Slug, [string]$Name, [string]$Repo, [string]$Plat, [string]$PkgId)
    Require-Token

    $meta = @{ repo = "$ORG/$Repo" }
    if ($PkgId) { $meta.packageId = $PkgId }

    $body = @{
        slug     = $Slug
        name     = $Name
        platform = $Plat
        metadata = $meta
    } | ConvertTo-Json

    try {
        $r = Invoke-RestMethod -Uri "$API/ows-store/projects" `
            -Method POST `
            -Headers @{ "Content-Type"="application/json"; "x-ows-admin-token"=$TOKEN } `
            -Body $body `
            -ErrorAction Stop
        Write-OK "Proyecto $Name ($Slug) registrado en DB"
        return $true
    } catch {
        Write-Err "No se pudo registrar proyecto en DB: $_"
        return $false
    }
}

# ── Trigger GitHub Actions workflow ──────────────────────────────────────────
function Trigger-Workflow {
    param([string]$Repo, [string]$Workflow, [string]$Ver, [string]$TargetRepo)

    $fields = @("version=$Ver")
    if ($TargetRepo) { $fields += "target_repo=$TargetRepo" }

    $fieldArgs = $fields | ForEach-Object { "-f", $_ }

    try {
        & $GH workflow run $Workflow `
            --repo "$ORG/owsdatabase" `
            @fieldArgs 2>&1
        Write-OK "Workflow $Workflow disparado (version: $Ver)"
        Start-Sleep -Seconds 5
        return $true
    } catch {
        Write-Err "No se pudo disparar workflow: $_"
        return $false
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# MODO: Nuevo proyecto
# ─────────────────────────────────────────────────────────────────────────────
if ($newProject) {
    if (-not $project -or -not $version -or -not $projectName -or -not $projectRepo) {
        Write-Err "Uso: .\scripts\release.ps1 -newProject -project <slug> -version <ver> -projectName <name> -projectDir <dir> -projectRepo <repo> [-platform both] [-packageId <id>]"
        exit 1
    }

    Write-Step "Registrando nuevo proyecto: $projectName ($project)"
    $platStr = if ($platform -eq "both") { "windows,android" } else { $platform }
    Register-NewProject -Slug $project -Name $projectName -Repo $projectRepo -Plat $platStr -PkgId $packageId

    Write-Info "Proyecto registrado. Ahora agrega '$project' al mapa PROJECTS en este script y corre el release normal."
    exit 0
}

# ─────────────────────────────────────────────────────────────────────────────
# MODO: Release normal
# ─────────────────────────────────────────────────────────────────────────────
if (-not $project -or -not $version) {
    Write-Err "Uso: powershell.exe -ExecutionPolicy Bypass -File '.\scripts\release.ps1' -project <slug> -version 2026.X.X-tHHMM"
    exit 1
}

if (-not $PROJECTS.ContainsKey($project)) {
    Write-Err "Proyecto '$project' no encontrado en el mapa. Proyectos disponibles: $($PROJECTS.Keys -join ', ')"
    exit 1
}

$cfg        = $PROJECTS[$project]
$repo       = $cfg.repo
$platforms  = $cfg.platforms
$tag        = "v$version"

Write-Host "`n========================================" -ForegroundColor Magenta
Write-Host "  OWS RELEASE - $project @ $version" -ForegroundColor Magenta
Write-Host "  Repo: $ORG/$repo  |  Tag: $tag" -ForegroundColor Magenta
Write-Host "========================================`n" -ForegroundColor Magenta

# ── Git: commit + push ────────────────────────────────────────────────────────
Write-Step "Git: commit y push"
Push-Location $ROOT
try {
    if ($project -eq "ows-store") {
        git add "OWS Store/index.html" 2>&1
    } elseif ($project -eq "dinobox") {
        git add "DinoBox/" 2>&1
    } else {
        $dirPath = $cfg.dir
        if (Test-Path $dirPath) { git add "$dirPath/" 2>&1 }
    }

    git add "scripts/release.ps1" 2>&1
    $status = git status --porcelain 2>&1
    if ($status) {
        git commit -m "release: $project $version" 2>&1
        git push origin main 2>&1
        Write-OK "Push completado"
    } else {
        Write-Info "Sin cambios que commitear"
    }
} catch {
    Write-Err "Error en git: $_"
}
Pop-Location

# ── Trigger Windows build ─────────────────────────────────────────────────────
if ($platforms -contains "windows" -and ($platform -eq "windows" -or $platform -eq "both")) {
    Write-Step "Disparando build Windows..."

    $targetRepo = if ($repo -ne "owsdatabase") { $repo } else { $null }
    $triggered  = Trigger-Workflow -Repo $repo -Workflow "release-windows-universal.yml" -Ver $version -TargetRepo $targetRepo

    if ($triggered) {
        # Determinar nombre del asset esperado
        $assetSlug    = $project.Replace("-", ".")
        $assetPattern = "*$version*.exe"

        # Esperar a que el asset exista ANTES de registrar en DB
        $assetReady = Wait-GithubAsset -Repo $repo -Tag $tag -AssetPattern $assetPattern -MaxMinutes 15

        if ($assetReady) {
            Register-Version -Slug $project -Ver $version -Plat "windows"
        } else {
            Write-Err "Asset no encontrado a tiempo. Registra manualmente cuando el build termine:"
            Write-Info "Invoke-RestMethod -Uri `"$API/ows-store/projects/$project/release`" -Method POST -Headers @{`"x-ows-admin-token`"=`"$TOKEN`"} -Body '{`"version`":`"$version`",`"platform`":`"windows`"}' -ContentType `"application/json`""
        }
    }
}

# ── Trigger Android build ──────────────────────────────────────────────────────
if ($platforms -contains "android" -and ($platform -eq "android" -or $platform -eq "both")) {
    Write-Step "Disparando build Android..."
    Trigger-Workflow -Repo $repo -Workflow "release-android-universal.yml" -Ver $version -TargetRepo $repo
    # Android no necesita wait de asset (APK se sube separado)
    Register-Version -Slug $project -Ver $version -Plat "android"
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "  RELEASE COMPLETADO: $project $version" -ForegroundColor Green
Write-Host "  https://github.com/$ORG/$repo/releases/tag/$tag" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green
