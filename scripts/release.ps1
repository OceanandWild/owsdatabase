# OWS Release Script - Script universal de release
# Uso normal:
#   .\scripts\release.ps1 -project <slug> -version 2026.X.X-tHHMM
#   .\scripts\release.ps1 -project <slug> -version 2026.X.X-tHHMM -platform both
#
# Modo nuevo proyecto (registra en DB + script, no hace build):
#   .\scripts\release.ps1 -newProject -project <slug> -version 2026.X.X-tHHMM
#     -projectName "Nombre Visible" -projectDir "Nombre Carpeta Local"
#     -projectRepo "nombre-repo-github" [-platform both] [-packageId "com.x.y"]
#
# NOTA: Ejecutar solo cuando el usuario pida explicitamente hacer build/release.

param(
    [Parameter(Mandatory=$true)]  [string]$project,
    [Parameter(Mandatory=$true)]  [string]$version,
    [string]$platform       = "windows",
    [string]$notes          = "",
    [switch]$skipBuild,
    [switch]$skipRelease,
    [switch]$skipApi,

    # Modo nuevo proyecto
    [switch]$newProject,
    [string]$projectName    = "",
    [string]$projectDir     = "",
    [string]$projectRepo    = "",
    [string]$packageId      = ""
)

$GH          = "C:\Program Files\GitHub CLI\gh.exe"
$WORKSPACE   = "C:\Users\hachi\OneDrive\Escritorio\Ocean and Wild Studios"
$API         = "https://owsdatabase.onrender.com"
$ADMIN_TOKEN = $env:OWS_ADMIN_SECRET
$GH_ORG      = "OceanandWild"
$SCRIPT_PATH = $PSCommandPath

$PROJECTS = @{
    "ows-store"            = @{ repo="owsdatabase";          dir="OWS Store";            buildOut="C:\builds\ows-store";       platforms=@("windows");           androidWorkflow=""; packageId="" }
    "wildweapon-mayhem"    = @{ repo="wildweapon-mayhem";    dir="WildWeapon Mayhem";    buildOut="C:\builds\wildweapon";      platforms=@("windows");           androidWorkflow=""; packageId="" }
    "savagespaceanimals"   = @{ repo="savagespaceanimals";   dir="Savage Space Animals"; buildOut="C:\builds\ssa";             platforms=@("windows");           androidWorkflow=""; packageId="" }
    "oceanpay"             = @{ repo="oceanpay";             dir="Ocean Pay Electron";   buildOut="C:\builds\oceanpay";        platforms=@("windows");           androidWorkflow=""; packageId="" }
    "floretshop"           = @{ repo="floretshop";           dir="Floret Shop";          buildOut="C:\builds\floretshop";      platforms=@("windows","android"); androidWorkflow="release-android-universal.yml"; packageId="com.oceanandwild.floretshop" }
    "wildtransfer"         = @{ repo="wildtransfer";         dir="WildTransfer";         buildOut="C:\builds\wildtransfer";    platforms=@("windows","android"); androidWorkflow="release-android-universal.yml"; packageId="com.oceanandwild.wildtransfer" }
    "a-wild-question-game" = @{ repo="a-wild-question-game"; dir="A Wild Question Game"; buildOut="C:\builds\awqg";            platforms=@("windows","android"); androidWorkflow="release-android-universal.yml"; packageId="com.oceanandwild.awqg" }
    "velocity-surge"       = @{ repo="velocity-surge";       dir="Velocity Surge";       buildOut="C:\builds\velocity-surge";  platforms=@("windows");           androidWorkflow=""; packageId="" }
    "wildwave"             = @{ repo="wildwave";             dir="WildWave";             buildOut="C:\builds\wildwave";        platforms=@("windows");           androidWorkflow=""; packageId="" }
    "ecoxion"              = @{ repo="ecoxion";              dir="Ecoxion";              buildOut="C:\builds\ecoxion";         platforms=@("windows");           androidWorkflow=""; packageId="" }
    "dinobox"              = @{ repo="owsdatabase";          dir="DinoBox";              buildOut="C:\builds\dinobox";         platforms=@("windows");           androidWorkflow=""; packageId="" }
}

function Log-Step { param($msg) Write-Host "`n>> $msg" -ForegroundColor Cyan }
function Log-OK   { param($msg) Write-Host "   OK: $msg" -ForegroundColor Green }
function Log-Warn { param($msg) Write-Host "   WARN: $msg" -ForegroundColor Yellow }
function Log-Fail { param($msg) Write-Host "   FAIL: $msg" -ForegroundColor Red }

function Invoke-API {
    param($method, $endpoint, $body)
    try {
        $params = @{
            Uri     = "$API$endpoint"
            Method  = $method
            Headers = @{ "Content-Type" = "application/json"; "x-ows-admin-token" = $ADMIN_TOKEN }
        }
        if ($body) { $params.Body = ($body | ConvertTo-Json -Depth 5) }
        return Invoke-RestMethod @params
    } catch {
        Log-Warn "API call fallida $method ${endpoint}: $_"
        return $null
    }
}

# ============================================================
# MODO NUEVO PROYECTO
# ============================================================
if ($newProject) {
    Write-Host "`n============================================================" -ForegroundColor Magenta
    Write-Host "  OWS Nuevo Proyecto -- $project" -ForegroundColor Magenta
    Write-Host "============================================================" -ForegroundColor Magenta

    if (-not $projectName -or -not $projectDir -or -not $projectRepo) {
        Log-Fail "Para -newProject se requiere: -projectName, -projectDir, -projectRepo"
        Write-Host "  Ejemplo:" -ForegroundColor Gray
        Write-Host "  .\scripts\release.ps1 -newProject -project mi-juego -version 2026.3.20-t1400 -projectName 'Mi Juego' -projectDir 'Mi Juego' -projectRepo 'mi-juego'" -ForegroundColor Gray
        exit 1
    }

    $isAndroid  = ($platform -eq "android" -or $platform -eq "both")
    $platforms  = if ($isAndroid) { "@(`"windows`",`"android`")" } else { "@(`"windows`")" }
    $pkgIdLine  = if ($isAndroid -and $packageId) { $packageId } else { "" }
    $workflow   = if ($isAndroid) { "release-android-universal.yml" } else { "" }
    $buildOutPath = "C:\builds\$project"

    # 1. Registrar en OWS Store DB
    Log-Step "Registrando proyecto en OWS Store DB"
    $dbPlatforms = if ($isAndroid) { @("windows","android") } else { @("windows") }
    $newProjectBody = @{
        slug        = $project
        name        = $projectName
        description = "$projectName disponible en OWS Store."
        url         = "https://github.com/$GH_ORG/$projectRepo/releases/latest"
        version     = $version
        status      = "launched"
        metadata    = @{ platforms = $dbPlatforms; repo = "$GH_ORG/$projectRepo" }
    }
    $r = Invoke-API "POST" "/ows-store/projects" $newProjectBody
    if ($r) { Log-OK "Proyecto registrado en DB" }

    # 2. Agregar al script release.ps1
    Log-Step "Agregando proyecto al script release.ps1"
    $scriptContent = Get-Content $SCRIPT_PATH -Raw

    $newLine = "    `"$project`"$(' ' * [Math]::Max(1, 25 - $project.Length))= @{ repo=`"$projectRepo`"; dir=`"$projectDir`"; buildOut=`"$buildOutPath`"; platforms=$platforms; androidWorkflow=`"$workflow`"; packageId=`"$pkgIdLine`" }"
    $insertAfter = '"dinobox"'
    $scriptContent = $scriptContent -replace '("dinobox"[^\n]+\n)', "`$1    $newLine`n"
    Set-Content $SCRIPT_PATH $scriptContent -Encoding ASCII
    Log-OK "Proyecto agregado al script. Recorda hacer push de scripts/release.ps1"

    # 3. OWS News
    Log-Step "Publicando en OWS News"
    $newsBody = @{
        title         = "$projectName $version disponible"
        description   = "Nuevo proyecto $projectName agregado al ecosistema OWS."
        project_names = @($project)
        changes       = "- Primer release oficial de $projectName"
        update_date   = (Get-Date -Format "yyyy-MM-dd")
    }
    $r2 = Invoke-API "POST" "/ows-news/updates" $newsBody
    if ($r2) { Log-OK "OWS News publicado" }

    Write-Host "`n============================================================" -ForegroundColor Magenta
    Write-Host "  NUEVO PROYECTO REGISTRADO: $project" -ForegroundColor Magenta
    Write-Host "  Siguiente paso: hacer el release con:" -ForegroundColor White
    Write-Host "  .\scripts\release.ps1 -project $project -version $version$(if ($isAndroid) { ' -platform both' })" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Magenta
    exit 0
}

# ============================================================
# MODO RELEASE NORMAL
# ============================================================
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  OWS Release -- $project v$version [$platform]" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

if (-not $PROJECTS.ContainsKey($project)) {
    Log-Fail "Proyecto '$project' no encontrado. Disponibles:"
    $PROJECTS.Keys | ForEach-Object { Write-Host "  - $_" }
    exit 1
}

$cfg = $PROJECTS[$project]
$TAG = "v$version"
$releaseNotes = if ($notes) { $notes } else { "- Release $version de $project" }

if (-not $ADMIN_TOKEN) {
    Log-Warn "OWS_ADMIN_SECRET no configurado. Las llamadas a la API van a fallar."
}

$doBuildWindows = ($platform -eq "windows" -or $platform -eq "both") -and ($cfg.platforms -contains "windows")
$doBuildAndroid = ($platform -eq "android"  -or $platform -eq "both") -and ($cfg.platforms -contains "android")

if (-not $doBuildWindows -and -not $doBuildAndroid) {
    Log-Fail "Plataforma '$platform' no soportada para '$project'. Disponibles: $($cfg.platforms -join ', ')"
    exit 1
}

$exePath = $null
$ymlPath = $null

if ($doBuildWindows -and -not $skipBuild) {
    Log-Step "Build Windows -- $project"
    $electronDir = Join-Path $WORKSPACE $cfg.dir
    if (-not (Test-Path $electronDir)) {
        Log-Fail "No se encontro la carpeta: $electronDir"
        exit 1
    }
    $pkgPath = Join-Path $electronDir "package.json"
    if (Test-Path $pkgPath) {
        $pkg = Get-Content $pkgPath -Raw | ConvertFrom-Json
        $pkg.version = $version
        $pkg | ConvertTo-Json -Depth 10 | Set-Content $pkgPath -Encoding ASCII
        Log-OK "Version bumpeada a $version"
    }
    Push-Location $electronDir
    npm install --silent
    if ($LASTEXITCODE -ne 0) { Log-Fail "npm install fallo"; Pop-Location; exit 1 }
    npm run dist
    if ($LASTEXITCODE -ne 0) { Log-Fail "npm run dist fallo"; Pop-Location; exit 1 }
    Pop-Location
    Log-OK "Build completado"
}

if ($doBuildWindows) {
    $dirs = @($cfg.buildOut, (Join-Path $WORKSPACE "$($cfg.dir)\dist"), (Join-Path $WORKSPACE "$($cfg.dir)\release"))
    foreach ($dir in $dirs) {
        if (Test-Path $dir) {
            $exe = Get-ChildItem $dir -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue |
                   Where-Object { $_.Name -notlike "*unpacked*" -and $_.Name -notlike "*Helper*" } |
                   Select-Object -First 1
            $yml = Get-ChildItem $dir -Filter "latest.yml" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($exe -and -not $exePath) { $exePath = $exe.FullName }
            if ($yml -and -not $ymlPath) { $ymlPath = $yml.FullName }
        }
    }
    if (-not $exePath) { Log-Fail "No se encontro el .exe en $($cfg.buildOut)"; exit 1 }
    Log-OK "EXE: $exePath"
    if ($ymlPath) { Log-OK "YML: $ymlPath" } else { Log-Warn "latest.yml no encontrado" }
}

if ($doBuildWindows -and -not $skipRelease) {
    Log-Step "Publicando release Windows -- $GH_ORG/$($cfg.repo)"
    $releaseArgs = @("release","create",$TAG,"--repo","$GH_ORG/$($cfg.repo)","--title","$project $version","--notes",$releaseNotes,"--latest")
    if ($exePath) { $releaseArgs += $exePath }
    if ($ymlPath) { $releaseArgs += $ymlPath }
    & $GH @releaseArgs
    if ($LASTEXITCODE -ne 0) { Log-Fail "Error publicando release Windows"; exit 1 }
    Log-OK "Release publicada: https://github.com/$GH_ORG/$($cfg.repo)/releases/tag/$TAG"
}

if ($doBuildAndroid -and -not $skipBuild) {
    Log-Step "Disparando build Android -- $project"
    & $GH workflow run $cfg.androidWorkflow --repo OceanandWild/owsdatabase --ref main -f project=$project -f version_name=$version
    if ($LASTEXITCODE -ne 0) { Log-Fail "Error disparando workflow Android" }
    else { Log-OK "Workflow Android disparado. Ver: https://github.com/OceanandWild/owsdatabase/actions" }
}

if (-not $skipApi) {
    Log-Step "Actualizando OWS Store DB"
    $r = Invoke-API "PATCH" "/ows-store/projects/$project/version" @{ version = $version }
    if ($r) { Log-OK "Version actualizada en DB: $version" }
    $newsBody = @{
        title         = "$project $version disponible"
        description   = "Nueva version de $project publicada."
        project_names = @($project)
        changes       = $releaseNotes
        update_date   = (Get-Date -Format "yyyy-MM-dd")
    }
    $r2 = Invoke-API "POST" "/ows-news/updates" $newsBody
    if ($r2) { Log-OK "OWS News publicado" }
}

if ($cfg.repo -eq "owsdatabase") {
    Log-Step "Git push a owsdatabase"
    Push-Location $WORKSPACE
    git add "$($cfg.dir)/package.json" 2>$null
    $gitStatus = git status --porcelain
    if ($gitStatus) {
        git commit -m "chore: bump $project to $version"
        git push origin main
        if ($LASTEXITCODE -eq 0) { Log-OK "Push exitoso" }
        else { Log-Warn "Push fallo -- hacelo manualmente" }
    } else {
        Log-OK "Nada que commitear"
    }
    Pop-Location
}

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host "  RELEASE COMPLETADO" -ForegroundColor Green
Write-Host "  Proyecto:   $project" -ForegroundColor White
Write-Host "  Version:    $version" -ForegroundColor White
Write-Host "  Fecha:      $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor White
Write-Host "  Plataforma: $platform" -ForegroundColor White
if ($doBuildWindows) {
    Write-Host "  Release: https://github.com/$GH_ORG/$($cfg.repo)/releases/tag/$TAG" -ForegroundColor White
}
Write-Host "============================================================" -ForegroundColor Green
