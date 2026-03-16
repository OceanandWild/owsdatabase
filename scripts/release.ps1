# OWS Release Script - Script universal de release
# Uso: .\scripts\release.ps1 -project <slug> -version <version> [-platform windows|android|both]

param(
    [Parameter(Mandatory=$true)]  [string]$project,
    [Parameter(Mandatory=$true)]  [string]$version,
    [string]$platform = "windows",
    [string]$notes = "",
    [switch]$skipBuild,
    [switch]$skipRelease,
    [switch]$skipApi
)

$GH          = "C:\Program Files\GitHub CLI\gh.exe"
$WORKSPACE   = "C:\Users\hachi\OneDrive\Escritorio\Ocean and Wild Studios"
$API         = "https://owsdatabase.onrender.com"
$ADMIN_TOKEN = $env:OWS_ADMIN_SECRET
$GH_ORG      = "OceanandWild"

$PROJECTS = @{
    "ows-store"            = @{ repo="owsdatabase";          dir="OWS Store Electron";   buildOut="C:\builds\ows-store";       platforms=@("windows"); androidWorkflow=""; packageId="" }
    "wildweapon-mayhem"    = @{ repo="wildweapon-mayhem";    dir="WildWeapon Mayhem";    buildOut="C:\builds\wildweapon";      platforms=@("windows"); androidWorkflow=""; packageId="" }
    "savagespaceanimals"   = @{ repo="savagespaceanimals";   dir="Savage Space Animals"; buildOut="C:\builds\ssa";             platforms=@("windows"); androidWorkflow=""; packageId="" }
    "oceanpay"             = @{ repo="oceanpay";             dir="Ocean Pay Electron";   buildOut="C:\builds\oceanpay";        platforms=@("windows"); androidWorkflow=""; packageId="" }
    "floretshop"           = @{ repo="floretshop";           dir="Floret Shop";          buildOut="C:\builds\floretshop";      platforms=@("windows","android"); androidWorkflow="release-android-universal.yml"; packageId="com.oceanandwild.floretshop" }
    "wildtransfer"         = @{ repo="wildtransfer";         dir="WildTransfer";         buildOut="C:\builds\wildtransfer";    platforms=@("windows","android"); androidWorkflow="release-android-universal.yml"; packageId="com.oceanandwild.wildtransfer" }
    "a-wild-question-game" = @{ repo="a-wild-question-game"; dir="A Wild Question Game"; buildOut="C:\builds\awqg";            platforms=@("windows","android"); androidWorkflow="release-android-universal.yml"; packageId="com.oceanandwild.awqg" }
    "velocity-surge"       = @{ repo="velocity-surge";       dir="Velocity Surge";       buildOut="C:\builds\velocity-surge";  platforms=@("windows"); androidWorkflow=""; packageId="" }
    "wildwave"             = @{ repo="wildwave";             dir="WildWave";             buildOut="C:\builds\wildwave";        platforms=@("windows"); androidWorkflow=""; packageId="" }
    "ecoxion"              = @{ repo="ecoxion";              dir="Ecoxion";              buildOut="C:\builds\ecoxion";         platforms=@("windows"); androidWorkflow=""; packageId="" }
    "dinobox"              = @{ repo="owsdatabase";          dir="DinoBox";              buildOut="C:\builds\dinobox";         platforms=@("windows"); androidWorkflow=""; packageId="" }
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
        $pkg | ConvertTo-Json -Depth 10 | Set-Content $pkgPath -Encoding UTF8
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
