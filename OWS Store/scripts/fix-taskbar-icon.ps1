param(
  [switch]$SkipBuild,
  [switch]$SkipInstall,
  [switch]$SkipCacheReset,
  [string]$InstallerPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
  param([string]$Message)
  Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Is-Admin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Relaunch-Elevated {
  $argList = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", "`"$PSCommandPath`""
  )

  if ($SkipBuild) { $argList += "-SkipBuild" }
  if ($SkipInstall) { $argList += "-SkipInstall" }
  if ($SkipCacheReset) { $argList += "-SkipCacheReset" }
  if ($InstallerPath) {
    $argList += "-InstallerPath"
    $argList += "`"$InstallerPath`""
  }

  Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList ($argList -join " ")
  exit
}

function Remove-IconCaches {
  Write-Step "Limpiando cache de iconos de Windows"

  $explorerCaches = @(
    Join-Path $env:LOCALAPPDATA "IconCache.db"
    Join-Path $env:LOCALAPPDATA "Microsoft\Windows\Explorer\iconcache*"
    Join-Path $env:LOCALAPPDATA "Microsoft\Windows\Explorer\thumbcache*"
  )

  Get-Process explorer -ErrorAction SilentlyContinue | Stop-Process -Force
  Start-Sleep -Milliseconds 900

  foreach ($cache in $explorerCaches) {
    Remove-Item -Path $cache -Force -Recurse -ErrorAction SilentlyContinue
  }

  Start-Process explorer.exe
  Start-Sleep -Seconds 2
}

function Remove-OldPinnedLinks {
  Write-Step "Eliminando accesos directos anclados obsoletos"
  $taskbarPinned = Join-Path $env:APPDATA "Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
  if (-not (Test-Path $taskbarPinned)) { return }

  $targets = @(
    "OWS Store.lnk",
    "OWS Nexus Store.lnk",
    "Electron.lnk"
  )
  foreach ($name in $targets) {
    $linkPath = Join-Path $taskbarPinned $name
    if (Test-Path $linkPath) {
      Remove-Item $linkPath -Force -ErrorAction SilentlyContinue
    }
  }
}

function Ensure-Shortcuts {
  Write-Step "Recreando accesos directos con icono correcto"
  $candidates = @(
    @{ Dir = (Join-Path $env:LOCALAPPDATA "Programs\OWS Store"); Exe = "OWS Store.exe"; Name = "OWS Store" },
    @{ Dir = (Join-Path $env:LOCALAPPDATA "Programs\OWS Nexus Store"); Exe = "OWS Nexus Store.exe"; Name = "OWS Nexus Store" }
  )

  $selected = $null
  foreach ($candidate in $candidates) {
    $candidateExePath = Join-Path $candidate.Dir $candidate.Exe
    if (Test-Path $candidateExePath) {
      $selected = @{
        Dir = $candidate.Dir
        ExePath = $candidateExePath
        ShortcutName = $candidate.Name
      }
      break
    }
  }

  if ($null -eq $selected) {
    Write-Warning "No se encontro el ejecutable instalado para OWS Store."
    return
  }

  $desktopLnk = Join-Path ([Environment]::GetFolderPath("Desktop")) ($selected.ShortcutName + ".lnk")
  $programsLnk = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\$($selected.ShortcutName).lnk"

  $wsh = New-Object -ComObject WScript.Shell
  foreach ($lnk in @($desktopLnk, $programsLnk)) {
    $shortcut = $wsh.CreateShortcut($lnk)
    $shortcut.TargetPath = $selected.ExePath
    $shortcut.WorkingDirectory = $selected.Dir
    $shortcut.IconLocation = "$($selected.ExePath),0"
    $shortcut.Save()
  }
}

if (-not (Is-Admin)) {
  Write-Warning "Se requieren privilegios de administrador. Se relanzara con elevacion."
  Relaunch-Elevated
}

$projectRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location $projectRoot

Write-Step "Proyecto: $projectRoot"

if (-not $SkipBuild) {
  Write-Step "Compilando OWS Store con signAndEditExecutable=true"
  npm run dist
  if ($LASTEXITCODE -ne 0) {
    throw "Fallo la compilacion. Revisa la salida de npm run dist."
  }
}

$resolvedInstaller = $InstallerPath
if (-not $resolvedInstaller) {
  $outputDir = "C:\builds\ows-store"
  $latest = Get-ChildItem -Path $outputDir -Filter "OWS*.Setup.*.exe" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
  if ($null -eq $latest) {
    throw "No se encontro instalador en $outputDir"
  }
  $resolvedInstaller = $latest.FullName
}

if (-not (Test-Path $resolvedInstaller)) {
  throw "No existe el instalador: $resolvedInstaller"
}

if (-not $SkipInstall) {
  Write-Step "Cerrando instancias previas de OWS Store"
  Get-Process "OWS Store" -ErrorAction SilentlyContinue | Stop-Process -Force
  Get-Process "OWS Nexus Store" -ErrorAction SilentlyContinue | Stop-Process -Force

  Write-Step "Ejecutando instalador"
  Start-Process -FilePath $resolvedInstaller -Wait
}

Remove-OldPinnedLinks
if (-not $SkipCacheReset) {
  Remove-IconCaches
}
Ensure-Shortcuts

Write-Step "Completado"
Write-Host "Siguiente paso: abre OWS Store desde Inicio y anclalo de nuevo a la barra de tareas." -ForegroundColor Green
