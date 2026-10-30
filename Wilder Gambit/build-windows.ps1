# Build headless de Windows para Wilder Gambit (editor cerrado)
# Uso:  powershell -ExecutionPolicy Bypass -File build-windows.ps1
# Salida: Builds\Wilder Gambit.exe (listo para ejecutar)

$ErrorActionPreference = "Continue"

$ProjectDir = $PSScriptRoot
$UnityExe   = "C:\Program Files\Unity\Hub\Editor\6000.6.6f1\Editor\Unity.exe"
$LogFile    = Join-Path $env:TEMP "wg-build.log"
$LockFile   = Join-Path $ProjectDir "Temp\UnityLockfile"

if (-not (Test-Path $UnityExe)) {
    Write-Host "ERROR: no se encuentra Unity 6000.3.11f1 en '$UnityExe'" -ForegroundColor Red
    exit 1
}

# 1) Verificar que el proyecto NO este abierto en el editor (batchmode no puede compartir el proyecto)
if (Test-Path $LockFile) {
    $opened = Get-CimInstance Win32_Process -Filter "Name='Unity.exe'" |
        Where-Object { $_.CommandLine -like "*Wilder Gambit*" -and $_.CommandLine -notlike "*-batchmode*" }
    if ($opened) {
        Write-Host "BLOQUEADO: Unity Editor tiene 'Wilder Gambit' abierto. Cerra el editor y volve a ejecutar." -ForegroundColor Red
        exit 1
    }
    Remove-Item $LockFile -Force
    Write-Host "Lockfile huerfano liberado." -ForegroundColor DarkGray
}

if (Test-Path $LogFile) { Remove-Item $LogFile -Force }

# 2) Batchmode build
#    NOTA: -nographics es OBLIGATORIO en esta maquina. Sin el, GfxDeviceD3D11
#    crashea al crear texturas cuando otros proyectos Unity usan la GPU.
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName  = $UnityExe
$psi.Arguments = '-batchmode -nographics -quit -projectPath "' + $ProjectDir + '" -executeMethod WGBuildScript.BuildWindows -logFile "' + $LogFile + '"'
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError  = $true

Write-Host "Construyendo Windows build (editor cerrado)..." -ForegroundColor Cyan
$start = Get-Date
$proc = [System.Diagnostics.Process]::Start($psi)
[void]$proc.StandardOutput.ReadToEndAsync()
$stderr = $proc.StandardError.ReadToEndAsync()
$proc.WaitForExit()
$seconds = [int]((Get-Date) - $start).TotalSeconds

# 3) Resultado
$exe = Join-Path $ProjectDir "Builds\Wilder Gambit.exe"
if ($proc.ExitCode -eq 0 -and (Test-Path $exe)) {
    $exeInfo = Get-Item $exe
    Write-Host ""
    Write-Host "BUILD OK en $seconds s" -ForegroundColor Green
    Write-Host "  Ejecutable: $exe"
    Write-Host ("  Tamano Data: " + [int]((Get-ChildItem (Join-Path $ProjectDir "Builds\Wilder Gambit_Data") -Recurse -File -EA SilentlyContinue | Measure-Object Length -Sum).Sum / 1MB) + " MB")
    Write-Host "  Log: $LogFile"
    exit 0
} else {
    Write-Host ""
    Write-Host "BUILD FALLIDO (exit $($proc.ExitCode)) tras $seconds s" -ForegroundColor Red
    if ($stderr.Trim()) { Write-Host $stderr -ForegroundColor DarkYellow }
    Write-Host "Revisar log: $LogFile" -ForegroundColor DarkYellow
    if (Test-Path $LogFile) { Get-Content $LogFile -Tail 40 }
    exit $proc.ExitCode
}
