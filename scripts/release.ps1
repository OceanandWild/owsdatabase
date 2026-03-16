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

# ── Register version in DB ────────────────────────────────────────────────────
function Register-Version {
    param([string]$Slug, [string]$Ver, [string]$Plat = "windows")
    Require-Token

    $body = @{ version = $Ver } | ConvertTo-Json
    try {
        $r = Invoke-RestMethod -Uri "$API/ows-store/projects/$Slug/version" `
            -Method PATCH `
            -Headers @{ "Content-Type"="application/json"; "x-ows-admin-token"=$TOKEN } `
            -Body $body `
            -ErrorAction Stop
        Write-OK "Version $Ver registrada en DB para $Slug"
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
    param([string]$Slug, [string]$Workflow, [string]$Ver)

    try {
        # Inputs correctos segun release-windows-universal.yml: project (choice) + version
        $output = & $GH workflow run $Workflow `
            --repo "$ORG/owsdatabase" `
            -f "project=$Slug" `
            -f "version=$Ver" 2>&1

        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0) {
            Write-Err "gh workflow run fallo (exit $exitCode): $output"
            return $false
        }
        Write-OK "Workflow $Workflow disparado  project=$Slug  version=$Ver"

        # Confirmar que el run aparecio en GitHub
        Start-Sleep -Seconds 8
        $check = & $GH run list --repo "$ORG/owsdatabase" --workflow $Workflow --limit 1 2>&1
        if ($check -match $Ver) {
            Write-OK "Run confirmado en GitHub Actions"
        } else {
            Write-Info "Run iniciado (no se pudo confirmar por nombre). Revisa: https://github.com/$ORG/owsdatabase/actions"
        }
        return $true
    } catch {
        Write-Err "Error disparando workflow: $_"
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

# ── Trigger Windows build ───────────────────────────────────────
if ($platforms -contains "windows" -and ($platform -eq "windows" -or $platform -eq "both")) {
    Write-Step "Disparando build Windows..."
    $triggered = Trigger-Workflow -Slug $project -Workflow "release-windows-universal.yml" -Ver $version

    if ($triggered) {
        Write-Host ""

        # Esperar a que el run aparezca y obtener su ID
        Start-Sleep -Seconds 10
        $runId = $null
        for ($i = 0; $i -lt 5; $i++) {
            $runJson = & $GH run list --repo "$ORG/owsdatabase" --workflow "release-windows-universal.yml" --limit 1 --json databaseId,status,createdAt 2>&1
            if ($runJson -match '"databaseId"') {
                try {
                    $run = $runJson | ConvertFrom-Json
                    $runId = $run[0].databaseId
                    break
                } catch {}
            }
            Start-Sleep -Seconds 5
        }

        if (-not $runId) {
            Write-Err "No se pudo obtener el ID del run. Revisa manualmente:"
            Write-Host "  https://github.com/$ORG/owsdatabase/actions" -ForegroundColor Cyan
        } else {
            Write-Info "Run ID: $runId — monitoreando progreso..."
            Write-Host ""

            $maxWait = 25  # maximo 25 intentos x 20s = ~8 min
            $attempt = 0
            $done = $false

            while (-not $done -and $attempt -lt $maxWait) {
                $attempt++
                Start-Sleep -Seconds 20

                $statusJson = & $GH run view $runId --repo "$ORG/owsdatabase" --json status,conclusion,jobs 2>&1
                if ($statusJson -notmatch '"status"') {
                    Write-Info "[$attempt] Esperando datos del run..."
                    continue
                }

                try {
                    $runData   = $statusJson | ConvertFrom-Json
                    $status    = $runData.status
                    $conclusion = $runData.conclusion

                    # Mostrar jobs individuales
                    $jobLine = ""
                    if ($runData.jobs -and $runData.jobs.Count -gt 0) {
                        $job = $runData.jobs[0]
                        $jobLine = " | $($job.name): $($job.status)"
                        if ($job.steps -and $job.steps.Count -gt 0) {
                            $activeStep = $job.steps | Where-Object { $_.status -eq "in_progress" } | Select-Object -Last 1
                            if ($activeStep) { $jobLine += " > $($activeStep.name)" }
                        }
                    }

                    if ($status -eq "completed") {
                        $done = $true
                        if ($conclusion -eq "success") {
                            Write-Host ""
                            Write-Host "  ============================================" -ForegroundColor Green
                            Write-Host "  BUILD COMPLETADO EXITOSAMENTE" -ForegroundColor Green
                            Write-Host "  Release: https://github.com/$ORG/$repo/releases/tag/$tag" -ForegroundColor Green
                            Write-Host "  Ya podes instalar y probar la nueva version." -ForegroundColor Green
                            Write-Host "  ============================================" -ForegroundColor Green
                            Write-Host ""
                        } else {
                            Write-Host ""
                            Write-Err "Build terminado con fallo (conclusion: $conclusion)"
                            Write-Host "  Detalles: https://github.com/$ORG/owsdatabase/actions/runs/$runId" -ForegroundColor Yellow
                            Write-Host ""
                        }
                    } else {
                        $elapsed = $attempt * 20
                        Write-Host "  [$($elapsed)s] Status: $status$jobLine" -ForegroundColor Yellow
                    }
                } catch {
                    Write-Info "[$attempt] Procesando respuesta..."
                }
            }

            if (-not $done) {
                Write-Host ""
                Write-Info "Timeout de monitoreo. El build puede seguir corriendo."
                Write-Host "  Seguimiento: https://github.com/$ORG/owsdatabase/actions/runs/$runId" -ForegroundColor Cyan
                Write-Host ""
            }
        }
    }
}


# ── Trigger Android build ──────────────────────────────────────────────────────
if ($platforms -contains "android" -and ($platform -eq "android" -or $platform -eq "both")) {
    Write-Step "Disparando build Android..."
    Trigger-Workflow -Slug $project -Workflow "release-android-universal.yml" -Ver $version
    # Android no necesita wait de asset (APK se sube separado)
    Register-Version -Slug $project -Ver $version -Plat "android"
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "  RELEASE COMPLETADO: $project $version" -ForegroundColor Green
Write-Host "  https://github.com/$ORG/$repo/releases/tag/$tag" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green
