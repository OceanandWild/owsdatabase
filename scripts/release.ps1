# ============================================================
# OWS Release Script - Script universal de release
# Uso: .\release.ps1 -project <slug> -version <version> [-platform windows|android|both]
# Ejemplos:
#   .\release.ps1 -project dinobox -version 2026.3.20-t1400
#   .\release.ps1 -project floretshop -version 2026.3.20-t1400 -platform both
#   .\release.ps1 -project ows-store -version 2026.3.20-t1400
# ============================================================

param(
    [Parameter(Mandatory=$true)]
    [string]$project,

    [Parameter(Mandatory=$true)]
    [string]$version,

    [string]$platform = "windows",

    [string]$notes = "",

    [switch]$skipBuild,
    [switch]$skipRelease,
    [switch]$skipApi
)

# ─── CONFIGURACION ────────────────────────────────────────────────────────────
$GH           = "C:\Program Files\GitHub CLI\gh.exe"
$WORKSPACE    = "C:\Users\hachi\OneDrive\Escritorio\Ocean and Wild Studios"
$API          = "https://owsdatabase.onrender.com"
$ADMIN_TOKEN  = $env:OWS_ADMIN_SECRET
$GH_ORG       = "OceanandWild"

# Mapa de proyectos: slug -> configuracion
$PROJECTS = @{
    "ows-store"          = @{ repo = "owsdatabase";          electronDir = "OWS Store Electron"; buildOut = "C:\builds\ows-store";          exePattern = "OWS.Store.Setup.*.exe";              platforms = @("windows");          androidWorkflow = "";                          packageId = "" }
    "wildweapon-mayhem"  = @{ repo = "wildweapon-mayhem";    electronDir = "WildWeapon Mayhem";  buildOut = "C:\builds\wildweapon-mayhem";  exePattern = "WildWeapon*.exe";                    platforms = @("windows");          androidWorkflow = "";                          packageId = "" }
    "savagespaceanimals" = @{ repo = "savagespaceanimals";   electronDir = "Savage Space Animals";buildOut = "C:\builds\ssa";               exePattern = "*.exe";                              platforms = @("windows");          androidWorkflow = "";                          packageId = "" }
    "oceanpay"           = @{ repo = "oceanpay";             electronDir = "Ocean Pay Electron"; buildOut = "C:\builds\oceanpay";           exePattern = "*.exe";                              platforms = @("windows");          androidWorkflow = "";                          packageId = "" }
    "floretshop"         = @{ repo = "floretshop";           electronDir = "Floret Shop";        buildOut = "C:\builds\floretshop";         exePattern = "*.exe";                              platforms = @("windows","android"); androidWorkflow = "build-external-android.yml"; packageId = "com.oceanandwild.floretshop" }
    "wildtransfer"       = @{ repo = "wildtransfer";         electronDir = "WildTransfer";       buildOut = "C:\builds\wildtransfer";       exePattern = "*.exe";                              platforms = @("windows","android"); androidWorkflow = "build-external-android.yml"; packageId = "com.oceanandwild.wildtransfer" }
    "a-wild-question-game" = @{ repo = "a-wild-question-game"; electronDir = "A Wild Question Game"; buildOut = "C:\builds\awqg";          exePattern = "*.exe";                              platforms = @("windows","android"); androidWorkflow = "build-external-android.yml"; packageId = "com.oceanandwild.awqg" }
    "velocity-surge"     = @{ repo = "velocity-surge";       electronDir = "Velocity Surge";     buildOut = "C:\builds\velocity-surge";     exePattern = "*.exe";                              platforms = @("windows");          androidWorkflow = "";                          packageId = "" }
    "wildwave"           = @{ repo = "wildwave";             electronDir = "WildWave";           buildOut = "C:\builds\wildwave";           exePattern = "*.exe";                              platforms = @("windows");          androidWorkflow = "";                          packageId = "" }
    "ecoxion"            = @{ repo = "ecoxion";              electronDir = "Ecoxion";            buildOut = "C:\builds\ecoxion";            exePattern = "Ecoxion.Setup.*.exe";                platforms = @("windows");          androidWorkflow = "";                          packageId = "" }
    "dinobox"            = @{ repo = "owsdatabase";          electronDir = "DinoBox";            buildOut = "C:\builds\dinobox";            exePattern = "*.exe";                              platforms = @("windows");          androidWorkflow = "";                          packageId = "" }
}
# ─────────────────────────────────────────────────────────────────────────────

function Write-Step($msg) { Write-Host "`n► $msg" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "  ✓ $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "  ⚠ $msg" -ForegroundColor Yellow }
function Write-Fail($msg) { Write-Host "  ✗ $msg" -ForegroundColor Red }

function Invoke-API($method, $endpoint, $body) {
    try {
        $params = @{
            Uri     = "$API$endpoint"
            Method  = $method
            Headers = @{ "Content-Type" = "application/json"; "x-ows-admin-token" = $ADMIN_TOKEN }
        }
        if ($body) { $params.Body = ($body | ConvertTo-Json -Depth 5) }
        $r = Invoke-RestMethod @params
        return $r
    } catch {
        Write-Warn "API call fallida ($method $endpoint): $_"
        return $null
    }
}

# ─── VALIDACIONES ─────────────────────────────────────────────────────────────
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  OWS Release — $project v$version [$platform]" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

if (-not $PROJECTS.ContainsKey($project)) {
    Write-Fail "Proyecto '$project' no encontrado. Proyectos disponibles:"
    $PROJECTS.Keys | ForEach-Object { Write-Host "  - $_" }
    exit 1
}

$cfg = $PROJECTS[$project]
$TAG = "v$version"
$releaseNotes = if ($notes) { $notes } else { "- Release $version de $project" }

if (-not $ADMIN_TOKEN) {
    Write-Warn "OWS_ADMIN_SECRET no configurado. Las llamadas a la API van a fallar."
    Write-Warn "Ejecuta: `$env:OWS_ADMIN_SECRET = 'tu-secret'"
}

# Determinar plataformas a buildear
$doBuildWindows = ($platform -eq "windows" -or $platform -eq "both") -and ($cfg.platforms -contains "windows")
$doBuildAndroid = ($platform -eq "android" -or $platform -eq "both") -and ($cfg.platforms -contains "android")

if (-not $doBuildWindows -and -not $doBuildAndroid) {
    Write-Fail "Plataforma '$platform' no soportada para '$project'. Plataformas disponibles: $($cfg.platforms -join ', ')"
    exit 1
}

# ─── BUILD WINDOWS ────────────────────────────────────────────────────────────
$exePath = $null
$ymlPath = $null

if ($doBuildWindows -and -not $skipBuild) {
    Write-Step "Build Windows — $project"

    $electronDir = Join-Path $WORKSPACE $cfg.electronDir
    if (-not (Test-Path $electronDir)) {
        Write-Fail "No se encontro la carpeta Electron: $electronDir"
        exit 1
    }

    # Bump version en package.json
    $pkgPath = Join-Path $electronDir "package.json"
    if (Test-Path $pkgPath) {
        $pkg = Get-Content $pkgPath -Raw | ConvertFrom-Json
        $pkg.version = $version
        $pkg | ConvertTo-Json -Depth 10 | Set-Content $pkgPath -Encoding UTF8
        Write-OK "Version bumpeada a $version en package.json"
    }

    # npm install + build
    Push-Location $electronDir
    npm install --silent
    if ($LASTEXITCODE -ne 0) { Write-Fail "npm install fallo"; Pop-Location; exit 1 }

    npm run dist
    if ($LASTEXITCODE -ne 0) { Write-Fail "npm run dist fallo"; Pop-Location; exit 1 }
    Pop-Location

    Write-OK "Build completado"
}

# Buscar artefactos generados
if ($doBuildWindows) {
    $buildOut = $cfg.buildOut
    $possibleDirs = @($buildOut, (Join-Path $WORKSPACE "$($cfg.electronDir)\dist"), (Join-Path $WORKSPACE "$($cfg.electronDir)\release"))

    foreach ($dir in $possibleDirs) {
        if (Test-Path $dir) {
            $exe = Get-ChildItem $dir -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue |
                   Where-Object { $_.Name -notlike "*unpacked*" -and $_.Name -notlike "*Helper*" } |
                   Select-Object -First 1
            $yml = Get-ChildItem $dir -Filter "latest.yml" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($exe) { $exePath = $exe.FullName }
            if ($yml) { $ymlPath = $yml.FullName }
        }
    }

    if (-not $exePath) {
        Write-Fail "No se encontro el .exe en $buildOut"
        exit 1
    }
    Write-OK "EXE: $exePath"
    if ($ymlPath) { Write-OK "YML: $ymlPath" }
    else { Write-Warn "latest.yml no encontrado — el auto-updater no funcionara" }
}

# ─── RELEASE WINDOWS EN GITHUB ────────────────────────────────────────────────
if ($doBuildWindows -and -not $skipRelease) {
    Write-Step "Publicando release Windows en GitHub — $($GH_ORG)/$($cfg.repo)"

    $releaseArgs = @("release", "create", $TAG, "--repo", "$GH_ORG/$($cfg.repo)", "--title", "$project $version", "--notes", $releaseNotes, "--latest")

    if ($exePath) { $releaseArgs += $exePath }
    if ($ymlPath) { $releaseArgs += $ymlPath }

    & $GH @releaseArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Error publicando release Windows"
        exit 1
    }
    Write-OK "Release Windows publicada: https://github.com/$GH_ORG/$($cfg.repo)/releases/tag/$TAG"
}

# ─── BUILD + RELEASE ANDROID ──────────────────────────────────────────────────
if ($doBuildAndroid -and -not $skipBuild) {
    Write-Step "Disparando build Android via GitHub Actions — $project"

    $workflowInputs = "-f project=$project -f source_ref=main -f version_name=$version"

    & $GH workflow run $cfg.androidWorkflow --repo OceanandWild/owsdatabase --ref main `
        -f project=$project `
        -f source_ref=main

    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Error disparando workflow Android"
    } else {
        Write-OK "Workflow Android disparado. Verificar en: https://github.com/OceanandWild/owsdatabase/actions"
        Write-Warn "Recorda hacer Promote a Release cuando el workflow termine."
    }
}

# ─── ACTUALIZAR DB VIA API ────────────────────────────────────────────────────
if (-not $skipApi) {
    Write-Step "Actualizando OWS Store DB"

    # Bump version del proyecto
    $r = Invoke-API "PATCH" "/ows-store/projects/$project/version" @{ version = $version }
    if ($r) { Write-OK "Version actualizada en DB: $version" }

    # Registrar release Android en DB si aplica
    if ($doBuildAndroid -and $cfg.packageId) {
        Write-Warn "Recorda registrar la release Android en DB cuando el workflow termine:"
        Write-Host "  POST /ows-store/android/releases" -ForegroundColor Gray
        Write-Host "  { project_slug: '$project', package_id: '$($cfg.packageId)', version_name: '$version', apk_url: '<URL>' }" -ForegroundColor Gray
    }

    # OWS News
    $newsBody = @{
        title         = "$project $version disponible"
        description   = "Nueva version de $project publicada."
        project_names = @($project)
        changes       = $releaseNotes
        update_date   = (Get-Date -Format "yyyy-MM-dd")
    }
    $r2 = Invoke-API "POST" "/ows-news/updates" $newsBody
    if ($r2) { Write-OK "OWS News publicado" }
}

# ─── GIT PUSH (si es ows-store o proyecto en owsdatabase) ────────────────────
if ($cfg.repo -eq "owsdatabase") {
    Write-Step "Git push a owsdatabase"
    Push-Location $WORKSPACE

    $electronDir = $cfg.electronDir
    git add "$electronDir/package.json" "server.js" "package.json" 2>$null
    $status = git status --porcelain
    if ($status) {
        git commit -m "chore: bump $project to $version"
        git push origin main
        if ($LASTEXITCODE -eq 0) { Write-OK "Push exitoso" }
        else { Write-Warn "Push fallo — hacelo manualmente" }
    } else {
        Write-OK "Nada que commitear"
    }
    Pop-Location
}

# ─── RESUMEN ──────────────────────────────────────────────────────────────────
Write-Host "`n============================================================" -ForegroundColor Green
Write-Host "  RELEASE COMPLETADO" -ForegroundColor Green
Write-Host "  Proyecto:  $project" -ForegroundColor White
Write-Host "  Version:   $version" -ForegroundColor White
Write-Host "  Fecha:     $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor White
Write-Host "  Plataforma: $platform" -ForegroundColor White
if ($doBuildWindows) {
    Write-Host "  Release:   https://github.com/$GH_ORG/$($cfg.repo)/releases/tag/$TAG" -ForegroundColor White
}
Write-Host "============================================================" -ForegroundColor Green
