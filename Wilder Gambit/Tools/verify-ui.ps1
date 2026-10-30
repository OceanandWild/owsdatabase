# ---------------------------------------------------------------------------
# verify-ui.ps1 - Verificación headless del tema de UI de Wilder Gambit.
#
# Corre Unity en batchmode y ejecuta WilderGambit.Editor.WgUiCheck.Run, que
# valida: kit de sprites en Resources/UI/Wg, importación como Sprite con alpha,
# carga de WgTheme.uss, urls del tema, y que MainMenu.uxml / PauseMenu.uxml
# instancien y referencien el tema.
#
# Requiere el editor CERRADO (batchmode no puede compartir el proyecto).
#   powershell -ExecutionPolicy Bypass -File Tools/verify-ui.ps1
# ---------------------------------------------------------------------------
$ErrorActionPreference = "Stop"

$proj = Split-Path -Parent $PSScriptRoot
$unityExe = "C:\Program Files\Unity\Hub\Editor\6000.3.11f1\Editor\Unity.exe"
$log = Join-Path $env:TEMP "wg-ui-check.log"
$lock = Join-Path $proj "Temp\UnityLockfile"

if (-not (Test-Path $unityExe)) { throw "no está Unity 6000.3.11f1 en '$unityExe'" }

$open = Get-CimInstance Win32_Process -Filter "Name='Unity.exe'" |
    Where-Object { $_.CommandLine -like "*Wilder Gambit*" -and $_.CommandLine -notlike "*-batchmode*" }
if ($open -or (Test-Path $lock)) {
    Write-Host "BLOQUEADO: el editor tiene abierto Wilder Gambit. Cerrá el editor y volvé a correr." -ForegroundColor Red
    exit 2
}

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $unityExe
$psi.Arguments = '-batchmode -nographics -quit -projectPath "' + $proj + '" -executeMethod WilderGambit.Editor.WgUiCheck.Run -logFile "' + $log + '"'
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true

Write-Host ">> Unity batchmode: chequeo de tema de UI..." -ForegroundColor Cyan
$proc = [System.Diagnostics.Process]::Start($psi)
$proc.WaitForExit()

if (Test-Path $log) {
    $lines = Get-Content -LiteralPath $log
    $hits = $lines | Select-String -Pattern "WG-UI-CHECK|error CS|Shader error|USS|WgTheme|Asset import failed"
    if ($hits) { $hits | ForEach-Object { "   " + $_.Line } }
    $ok = $lines | Select-String -Pattern "\[WG-UI-CHECK\] OK"
    Write-Host ""
    if ($ok) { Write-Host "RESULTADO: OK" -ForegroundColor Green; exit 0 }
    Write-Host "RESULTADO: revisar el log: $log" -ForegroundColor Yellow
    exit 1
}

Write-Host "no se generó el log: $log" -ForegroundColor Red
exit 1
