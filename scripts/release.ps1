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
    [switch]$createRepo,
    [switch]$wireWindowsWorkflow,
    [switch]$releaseAfterSetup,
    [string]$storeVersion,
    [string]$releaseDate,
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
    "ows-store"            = @{ repo = "owsdatabase";            dir = "OWS Store";              platforms = @("windows","android") }
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
    "ocean-ai"             = @{ repo = "ocean-ai";               dir = "Ocean AI";                platforms = @("windows") }
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

function Ensure-GhAuth {
    try {
        & $GH auth status 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-OK "GitHub CLI autenticado"
            return $true
        }
    } catch {}
    Write-Err "GitHub CLI sin auth. Ejecuta: & `"$GH`" auth login"
    return $false
}

function Ensure-GhRepo {
    param([string]$RepoName)
    $full = "$ORG/$RepoName"
    try {
        & $GH repo view $full 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-OK "Repo ya existe: $full"
            return $true
        }
    } catch {}
    try {
        & $GH repo create $full --public --confirm 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-OK "Repo creado: $full"
            return $true
        }
    } catch {}
    Write-Err "No se pudo crear/verificar repo $full con gh."
    return $false
}

function Update-WindowsWorkflowMapAndOptions {
    param([string]$Slug, [string]$Repo, [string]$Dir)

    $wfPath = Join-Path $ROOT ".github\workflows\release-windows-universal.yml"
    if (-not (Test-Path $wfPath)) {
        Write-Err "No se encontro workflow Windows universal: $wfPath"
        return $false
    }

    $raw = Get-Content -Raw $wfPath
    $changed = $false

    # options list (workflow_dispatch.inputs.project.options)
    if ($raw -notmatch "(?m)^\s*-\s*$([regex]::Escape($Slug))\s*$") {
        if ($raw -match "(?m)^(\s*-\s*dinobox\s*)$") {
            $raw = $raw -replace "(?m)^(\s*-\s*dinobox\s*)$", "`$1`r`n          - $Slug"
            $changed = $true
        } else {
            Write-Err "No se pudo inyectar option en workflow (no se encontro ancla dinobox)."
            return $false
        }
    }

    # project config map
    if ($raw -notmatch [regex]::Escape("`"$Slug`"")) {
        $entry = "            `"$Slug`"             = @{ repo = `"$Repo`";            dir = `"$Dir`";             buildOut = `"C:\builds\$Slug`" }"
        if ($raw -match "(?m)^(\s*`"dinobox`".*)$") {
            $raw = $raw -replace "(?m)^(\s*`"dinobox`".*)$", "`$1`r`n$entry"
            $changed = $true
        } else {
            Write-Err "No se pudo inyectar config del proyecto en workflow."
            return $false
        }
    }

    if ($changed) {
        [System.IO.File]::WriteAllText($wfPath, $raw, (New-Object System.Text.UTF8Encoding($false)))
        Write-OK "Workflow Windows universal actualizado para $Slug"
    } else {
        Write-Info "Workflow Windows universal ya estaba listo para $Slug"
    }
    return $true
}

function Publish-ProjectToExternalRepo {
    param([string]$RepoName, [string]$LocalProjectDir)
    if (-not (Test-Path $LocalProjectDir)) {
        Write-Err "No existe carpeta local del proyecto: $LocalProjectDir"
        return $false
    }
    if (-not (Ensure-GhAuth)) { return $false }

    $tempClone = Join-Path $env:TEMP ("ows_release_" + $RepoName + "_" + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
    try {
        & $GH repo clone "$ORG/$RepoName" $tempClone 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "gh repo clone fallo para $RepoName" }

        # Mirror local project -> external repo root (excluding heavy/generated dirs)
        robocopy $LocalProjectDir $tempClone /E /XD "node_modules" "dist" "release" ".git" /NFL /NDL /NJH /NJS /NC /NS | Out-Null

        $gitignorePath = Join-Path $tempClone ".gitignore"
        if (-not (Test-Path $gitignorePath)) {
            @("node_modules/","dist/","release/","*.log") | Set-Content -Path $gitignorePath -Encoding UTF8
        }

        Push-Location $tempClone
        git add . 2>&1 | Out-Null
        $st = git status --porcelain 2>&1
        if ($st) {
            git commit -m "release: sync project files from owsdatabase workspace" 2>&1 | Out-Null
            git push origin main 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "git push fallo en repo externo $RepoName" }
            Write-OK "Repo externo actualizado: $ORG/$RepoName"
        } else {
            Write-Info "Repo externo sin cambios: $ORG/$RepoName"
        }
        Pop-Location
        return $true
    } catch {
        try { Pop-Location } catch {}
        Write-Err "No se pudo publicar en repo externo $ORG/$RepoName : $_"
        return $false
    }
}

function Resolve-IconUrl {
    param([string]$Repo, [string]$Slug)
    $path = ("build/{0}.png" -f $Slug) -replace " ", "%20"
    return "https://raw.githubusercontent.com/$ORG/$Repo/main/$path"
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
    param([string]$Slug, [string]$Name, [string]$Repo, [string]$Plat, [string]$PkgId, [string]$ReleaseDate)
    Require-Token

    $meta = @{ repo = "$ORG/$Repo" }
    if ($PkgId) { $meta.packageId = $PkgId }
    $iconUrl = Resolve-IconUrl -Repo $Repo -Slug $Slug

    $body = @{
        slug     = $Slug
        name     = $Name
        description = "$Name en OWS Store"
        url = "https://github.com/$ORG/$Repo/releases/latest"
        icon_url = $iconUrl
        banner_url = ""
        version = "1.0.0"
        platform = $Plat
        metadata = $meta
        status   = "coming_soon"
        release_date = $ReleaseDate
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
    param(
        [string]$Slug,
        [string]$Workflow,
        [string]$Ver,
        [hashtable]$Inputs = $null
    )

    try {
        $args = @("workflow", "run", $Workflow, "--repo", "$ORG/owsdatabase")
        if ($Inputs -and $Inputs.Count -gt 0) {
            foreach ($key in $Inputs.Keys) {
                $args += "-f"
                $args += ("{0}={1}" -f $key, [string]$Inputs[$key])
            }
        } else {
            # Inputs por defecto (release-windows-universal.yml / release-android-universal.yml)
            $args += "-f"
            $args += "project=$Slug"
            $args += "-f"
            $args += "version=$Ver"
        }

        $output = & $GH @args 2>&1

        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0) {
            Write-Err "gh workflow run fallo (exit $exitCode): $output"
            return $false
        }
        if ($Inputs -and $Inputs.Count -gt 0) {
            Write-OK "Workflow $Workflow disparado (inputs custom)"
        } else {
            Write-OK "Workflow $Workflow disparado  project=$Slug  version=$Ver"
        }

        # Confirmar que el run aparecio en GitHub
        Start-Sleep -Seconds 8
        $check = & $GH run list --repo "$ORG/owsdatabase" --workflow $Workflow --limit 1 2>&1
        if ($Ver -and ($check -match $Ver)) {
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

    if (-not $projectDir) { $projectDir = $projectName }
    if (-not $storeVersion) { $storeVersion = $version }
    if (-not $releaseDate) {
        $releaseDate = (Get-Date).AddDays(28).ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
    if (-not $PSBoundParameters.ContainsKey('createRepo')) { $createRepo = $true }
    if (-not $PSBoundParameters.ContainsKey('wireWindowsWorkflow')) { $wireWindowsWorkflow = $true }

    Write-Step "Registrando nuevo proyecto: $projectName ($project)"
    $platStr = if ($platform -eq "both") { "windows,android" } else { $platform }
    Register-NewProject -Slug $project -Name $projectName -Repo $projectRepo -Plat $platStr -PkgId $packageId -ReleaseDate $releaseDate | Out-Null

    # Repo bootstrap (gh)
    if ($createRepo) {
        Write-Step "Verificando/creando repo remoto"
        if (Ensure-GhAuth) {
            Ensure-GhRepo -RepoName $projectRepo | Out-Null
        }
    }

    # Sync local project files to external repo if applicable.
    if ($projectRepo -ne "owsdatabase") {
        $localProjectPath = Join-Path $ROOT $projectDir
        if (Test-Path $localProjectPath) {
            Write-Step "Sincronizando archivos locales de $projectDir hacia $projectRepo"
            Publish-ProjectToExternalRepo -RepoName $projectRepo -LocalProjectDir $localProjectPath | Out-Null
        } else {
            Write-Info "No se encontro carpeta local '$projectDir'. Se omite sync inicial al repo externo."
        }
    }

    # Wire workflow so the universal Windows pipeline can build the new slug
    if ($wireWindowsWorkflow) {
        Write-Step "Actualizando workflow universal de Windows para $project"
        Update-WindowsWorkflowMapAndOptions -Slug $project -Repo $projectRepo -Dir $projectDir | Out-Null
    }

    # Persist in release map for future normal releases
    if (-not $PROJECTS.ContainsKey($project)) {
        $PROJECTS[$project] = @{
            repo = $projectRepo
            dir = $projectDir
            platforms = @("windows")
        }
        Write-OK "Mapa de release actualizado en runtime para $project"
    }

    # Commit/push infrastructure changes
    Write-Step "Guardando cambios de infraestructura (script/workflow)"
    Push-Location $ROOT
    try {
        git add "scripts/release.ps1" ".github/workflows/release-windows-universal.yml" 2>&1
        $statusInfra = git status --porcelain 2>&1
        if ($statusInfra) {
            git commit -m "chore(release): bootstrap universal para $project" 2>&1
            git push origin main *> $null
            if ($LASTEXITCODE -ne 0) { throw "git push fallo al subir cambios de infraestructura" }
            Write-OK "Cambios de infraestructura subidos"
        } else {
            Write-Info "Sin cambios de infraestructura para commitear"
        }
    } catch {
        Write-Err "No se pudieron subir cambios de infraestructura: $_"
    }
    Pop-Location

    if ($releaseAfterSetup) {
        Write-Step "Secuencia release encadenada (OWS Store -> $project)"
        $storeOk = Trigger-Workflow -Slug "ows-store" -Workflow "release-windows-universal.yml" -Ver $storeVersion
        if ($storeOk) {
            Register-Version -Slug "ows-store" -Ver $storeVersion -Plat "windows" | Out-Null
        } else {
            Write-Err "No se pudo disparar build de OWS Store."
        }

        $projectOk = Trigger-Workflow -Slug $project -Workflow "release-windows-universal.yml" -Ver $version
        if ($projectOk) {
            Register-Version -Slug $project -Ver $version -Plat "windows" | Out-Null
        } else {
            Write-Err "No se pudo disparar build de $project."
        }
    } else {
        Write-Info "Proyecto bootstrap listo. Puedes correr release normal con el mismo script."
    }

    exit 0
}

function Get-LatestWorkflowRunId {
    param([string]$Workflow)
    try {
        $json = & $GH run list --repo "$ORG/owsdatabase" --workflow $Workflow --limit 1 --json databaseId,status,conclusion,createdAt 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $json) { return $null }
        $arr = $json | ConvertFrom-Json
        if (-not $arr -or $arr.Count -eq 0) { return $null }
        return [string]$arr[0].databaseId
    } catch {
        return $null
    }
}

function Wait-WorkflowRunCompletion {
    param(
        [string]$RunId,
        [int]$MaxAttempts = 90,
        [int]$SleepSeconds = 10
    )
    if (-not $RunId) { return @{ ok = $false; status = "unknown"; conclusion = "" } }
    for ($i=1; $i -le $MaxAttempts; $i++) {
        try {
            $json = & $GH run view $RunId --repo "$ORG/owsdatabase" --json status,conclusion 2>$null
            if ($LASTEXITCODE -ne 0 -or -not $json) {
                Start-Sleep -Seconds $SleepSeconds
                continue
            }
            $obj = $json | ConvertFrom-Json
            $status = [string]$obj.status
            $conclusion = [string]$obj.conclusion
            if ($status -eq "completed") {
                return @{ ok = ($conclusion -eq "success"); status = $status; conclusion = $conclusion }
            }
        } catch {}
        Start-Sleep -Seconds $SleepSeconds
    }
    return @{ ok = $false; status = "timeout"; conclusion = "" }
}

function Get-AndroidArtifactNameForProject {
    param([string]$Slug)
    switch ($Slug) {
        "ows-store" { return "ows-store-apk-release-signed" }
        "floretshop" { return "floretshop-apk-release-signed" }
        "wildtransfer" { return "wildtransfer-apk-release-signed" }
        "a-wild-question-game" { return "a-wild-question-game-apk-release-signed" }
        default { return "$Slug-apk-release-signed" }
    }
}

function Promote-AndroidArtifactToRelease {
    param(
        [string]$Slug,
        [string]$RepoName,
        [string]$Ver,
        [string]$SourceRunId
    )
    if (-not $SourceRunId) {
        Write-Err "No hay run id de origen para promote Android."
        return $false
    }

    $artifactName = Get-AndroidArtifactNameForProject -Slug $Slug
    $releaseTag = "v$Ver"
    $releaseName = "$Slug $Ver (Android)"
    $releaseNotes = "Android build for $Slug $Ver"
    $targetRepo = "$ORG/$RepoName"

    Write-Step "Promoviendo artifact Android a release (sin latest)..."
    $ok = Trigger-Workflow -Slug $Slug -Workflow "promote-artifact-to-release.yml" -Ver "" -Inputs @{
        source_run_id = $SourceRunId
        artifact_name = $artifactName
        release_tag = $releaseTag
        release_name = $releaseName
        release_notes = $releaseNotes
        mark_latest = "false"
        prerelease = "false"
        target_repository = $targetRepo
    }
    if (-not $ok) { return $false }

    $promoteRunId = Get-LatestWorkflowRunId -Workflow "promote-artifact-to-release.yml"
    if (-not $promoteRunId) {
        Write-Info "Promote disparado. No se pudo resolver run id para monitoreo."
        return $true
    }
    Write-Info "Promote run id: $promoteRunId - monitoreando..."
    $wait = Wait-WorkflowRunCompletion -RunId $promoteRunId -MaxAttempts 90 -SleepSeconds 10
    if (-not $wait.ok) {
        Write-Err "Promote Android no finalizo OK (status=$($wait.status), conclusion=$($wait.conclusion))."
        return $false
    }
    Write-OK "Promote Android completado."
    return $true
}

function Register-AndroidReleaseFromGitHub {
    param(
        [string]$Slug,
        [string]$RepoName,
        [string]$Ver
    )
    Require-Token
    $tag = "v$Ver"
    $releaseApiPath = "repos/$ORG/$RepoName/releases/tags/$tag"
    try {
        $releaseJson = & $GH api $releaseApiPath 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $releaseJson) {
            Write-Err "No se pudo leer release $tag para registrar Android."
            return $false
        }
        $release = $releaseJson | ConvertFrom-Json
        $assets = @($release.assets)
        $apkAsset = $assets | Where-Object { $_.name -match '\.apk$' } | Select-Object -First 1
        if (-not $apkAsset) {
            Write-Err "No se encontro asset APK en release $tag."
            return $false
        }

        $metaAsset = $assets | Where-Object { $_.name -eq 'android-release-metadata.json' } | Select-Object -First 1
        if (-not $metaAsset) {
            Write-Err "No se encontro android-release-metadata.json en release $tag."
            return $false
        }

        $tmpMeta = Join-Path $env:TEMP ("android-release-metadata-{0}-{1}.json" -f $Slug, ([Guid]::NewGuid().ToString("N")))
        & $GH api ("repos/$ORG/$RepoName/releases/assets/" + $metaAsset.id) -H "Accept: application/octet-stream" --output $tmpMeta 2>$null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $tmpMeta)) {
            Write-Err "No se pudo descargar android-release-metadata.json para registro."
            return $false
        }
        $meta = Get-Content -Raw $tmpMeta | ConvertFrom-Json
        Remove-Item $tmpMeta -Force -ErrorAction SilentlyContinue

        $packageId = [string]$meta.package_id
        $versionName = [string]$meta.version_name
        $versionCode = [int]$meta.version_code
        if (-not $packageId -or -not $versionName -or $versionCode -le 0) {
            Write-Err "Metadata Android invalida para registro."
            return $false
        }

        $apkUrl = [string]$apkAsset.browser_download_url
        $sizeBytes = [int64]$apkAsset.size

        $bodyObj = @{
            project_slug = $Slug
            package_id = $packageId
            version_name = $versionName
            version_code = $versionCode
            apk_url = $apkUrl
            size_bytes = $sizeBytes
            release_notes = "Android build for $Slug $Ver"
            status = "published"
            is_mandatory = $false
            published_at = [string]$release.published_at
        }
        $body = $bodyObj | ConvertTo-Json
        $r = Invoke-RestMethod -Uri "$API/ows-store/android/releases" `
            -Method POST `
            -Headers @{ "Content-Type"="application/json"; "x-ows-admin-token"=$TOKEN } `
            -Body $body `
            -ErrorAction Stop
        Write-OK "Registro Android en API completado para $Slug ($versionName / $versionCode)."
        return $true
    } catch {
        Write-Err "No se pudo registrar release Android en API: $_"
        return $false
    }
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
    if ($repo -ne "owsdatabase") {
        # For external repos, sync/push project files to the target repo first.
        $dirPath = $cfg.dir
        $published = Publish-ProjectToExternalRepo -RepoName $repo -LocalProjectDir $dirPath
        if (-not $published) { Write-Err "Continuando sin sincronizar repo externo (puede fallar release)." }
    } else {
        if ($project -eq "ows-store") {
            git add "OWS Store/index.html" 2>&1
        } elseif ($project -eq "dinobox") {
            git add "DinoBox/" 2>&1
        } else {
            $dirPath = $cfg.dir
            if (Test-Path $dirPath) { git add "$dirPath/" 2>&1 }
        }
    }

    git add "scripts/release.ps1" 2>&1
    $status = git status --porcelain 2>&1
    if ($status) {
        git commit -m "release: $project $version" 2>&1
        git push origin main *> $null
        if ($LASTEXITCODE -ne 0) { throw "git push fallo para release $project $version" }
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

        # Obtener el run ID
        Start-Sleep -Seconds 10
        $runId = $null
        for ($i = 0; $i -lt 5; $i++) {
            $runJson = & $GH run list --repo "$ORG/owsdatabase" --workflow "release-windows-universal.yml" --limit 1 --json databaseId,status 2>&1
            if ($runJson -match "databaseId") {
                try {
                    $runId = ($runJson | ConvertFrom-Json)[0].databaseId
                    break
                } catch {}
            }
            Start-Sleep -Seconds 5
        }

        if (-not $runId) {
            Write-Err "No se pudo obtener el run ID."
            Write-Host "  Revisa: https://github.com/$ORG/owsdatabase/actions" -ForegroundColor Cyan
        } else {
            Write-Info ("Run ID: " + $runId + " - monitoreando...")
            Write-Host ""

            $maxWait = 25
            $attempt = 0
            $done    = $false

            while (-not $done -and $attempt -lt $maxWait) {
                $attempt++
                Start-Sleep -Seconds 20

                $sv = & $GH run view $runId --repo "$ORG/owsdatabase" --json status,conclusion,jobs 2>&1
                if ($sv -notmatch '"status"') { Write-Info ("  [" + ($attempt * 20) + "s] Esperando..."); continue }

                try {
                    $rd         = $sv | ConvertFrom-Json
                    $status     = $rd.status
                    $conclusion = $rd.conclusion
                    $extra      = ""

                    if ($rd.jobs -and $rd.jobs.Count -gt 0) {
                        $job   = $rd.jobs[0]
                        $extra = " | " + $job.name + " (" + $job.status + ")"
                        $step  = $job.steps | Where-Object { $_.status -eq "in_progress" } | Select-Object -Last 1
                        if ($step) { $extra += " > " + $step.name }
                    }

                    if ($status -eq "completed") {
                        $done = $true
                        Write-Host ""
                        if ($conclusion -eq "success") {
                            Write-Host "  ==========================================" -ForegroundColor Green
                            Write-Host "  BUILD COMPLETADO - LISTO PARA PROBAR" -ForegroundColor Green
                            Write-Host ("  Release: https://github.com/$ORG/" + $repo + "/releases/tag/" + $tag) -ForegroundColor Green
                            Write-Host "  ==========================================" -ForegroundColor Green
                        } else {
                            Write-Err ("Build fallo (conclusion: " + $conclusion + ")")
                            Write-Host ("  Detalles: https://github.com/$ORG/owsdatabase/actions/runs/" + $runId) -ForegroundColor Yellow
                        }
                        Write-Host ""
                    } else {
                        Write-Host ("  [" + ($attempt * 20) + "s] " + $status + $extra) -ForegroundColor Yellow
                    }
                } catch {
                    Write-Info ("  [" + ($attempt * 20) + "s] Procesando...")
                }
            }

            if (-not $done) {
                Write-Info "Timeout. El build puede seguir corriendo."
                Write-Host ("  Seguimiento: https://github.com/$ORG/owsdatabase/actions/runs/" + $runId) -ForegroundColor Cyan
            }
        }
    }
}


# ── Trigger Android build ──────────────────────────────────────────────────────
if ($platforms -contains "android" -and ($platform -eq "android" -or $platform -eq "both")) {
    Write-Step "Disparando build Android..."
    $androidWorkflow = "release-android-universal.yml"
    if ($project -eq "ows-store") {
        $androidWorkflow = "ows-store-android.yml"
        Trigger-Workflow -Slug $project -Workflow $androidWorkflow -Ver $version -Inputs @{ build_profile = "full" } | Out-Null
    } else {
        Trigger-Workflow -Slug $project -Workflow $androidWorkflow -Ver $version | Out-Null
    }
    $androidRunId = Get-LatestWorkflowRunId -Workflow $androidWorkflow
    if ($androidRunId) {
        Write-Info "Android run id: $androidRunId - monitoreando..."
        $androidWait = Wait-WorkflowRunCompletion -RunId $androidRunId -MaxAttempts 120 -SleepSeconds 10
        if (-not $androidWait.ok) {
            Write-Err "Build Android no finalizo OK (status=$($androidWait.status), conclusion=$($androidWait.conclusion))."
        } else {
            Write-OK "Build Android completado."
            $promoted = Promote-AndroidArtifactToRelease -Slug $project -RepoName $repo -Ver $version -SourceRunId $androidRunId
            if ($promoted) {
                Register-AndroidReleaseFromGitHub -Slug $project -RepoName $repo -Ver $version | Out-Null
            }
        }
    } else {
        Write-Info "No se pudo resolver run id Android para monitoreo/promote automatico."
    }
    Register-Version -Slug $project -Ver $version -Plat "android"
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "  RELEASE COMPLETADO: $project $version" -ForegroundColor Green
Write-Host "  https://github.com/$ORG/$repo/releases/tag/$tag" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green
