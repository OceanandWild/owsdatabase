# Empaqueta el build de Windows de Wilder Gambit en un ZIP para itch.io.
# Uso:  powershell -ExecutionPolicy Bypass -File package-windows.ps1 [-Version 1.0.2]
# Entrada:  Builds\            (salida de build-windows.ps1)
# Salida:   Wilder-Gambit-v<Version>-Windows.zip

param(
  [string]$Version = "",
  [int]$CompressionLevel = 5   # 0 = sin comprimir (rapido), 9 = maximo
)

$ErrorActionPreference = "Stop"

$ProjectDir  = $PSScriptRoot
$BuildDir    = Join-Path $ProjectDir "Builds"
$ProjectSettings = Join-Path $ProjectDir "ProjectSettings\ProjectSettings.asset"

if (-not (Test-Path $BuildDir)) {
    Write-Host "ERROR: no existe '$BuildDir'. Corré build-windows.ps1 primero." -ForegroundColor Red
    exit 1
}
if (-not (Test-Path (Join-Path $BuildDir "Wilder Gambit.exe"))) {
    Write-Host "ERROR: no hay 'Wilder Gambit.exe' en el build. Corré build-windows.ps1 primero." -ForegroundColor Red
    exit 1
}

# La version sale de ProjectSettings (bundleVersion) si no se pasa -Version.
if (-not $Version) {
    $line = Select-String -Path $ProjectSettings -Pattern '^\s*bundleVersion:\s*(.+)$' | Select-Object -First 1
    if (-not $line) { Write-Host "ERROR: no se pudo leer bundleVersion de ProjectSettings.asset" -ForegroundColor Red; exit 1 }
    $Version = $line.Matches[0].Groups[1].Value.Trim()
}

$ZipPath = Join-Path $ProjectDir "Wilder-Gambit-v$Version-Windows.zip"

# Carpetas que Unity genera para depurar y que jamas van en un release.
$ExcludeDirs = @('*_BurstDebugInformation_DoNotShip', '*_BackUpThisFolder_ButDontShipItWithYourGame', '.utmp', 'Logs')

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$files = Get-ChildItem -LiteralPath $BuildDir -Recurse -File | Where-Object {
    $rel = $_.FullName.Substring($BuildDir.Length).TrimStart('\')
    $parts = $rel -split '\\'
    $excluded = $false
    foreach ($p in $parts[0..($parts.Length - 2)]) {
        # -like (no -contains): los patrones de $ExcludeDirs son wildcards.
        if ($ExcludeDirs | Where-Object { $p -like $_ }) { $excluded = $true; break }
    }
    -not $excluded
}

if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }

$rawBytes = ($files | Measure-Object Length -Sum).Sum
Write-Host "Empaquetando v$Version -> $(Split-Path $ZipPath -Leaf)"
Write-Host ("  {0} archivos · {1} MB sin comprimir" -f $files.Count, [int]($rawBytes / 1MB))

$fs  = [System.IO.File]::Open($ZipPath, [System.IO.FileMode]::CreateNew)
$zip = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)
try {
    $level = switch ($CompressionLevel) {
        0 { [System.IO.Compression.CompressionLevel]::NoCompression }
        1 { [System.IO.Compression.CompressionLevel]::Fastest }
        9 { [System.IO.Compression.CompressionLevel]::SmallestSize }
        default { [System.IO.Compression.CompressionLevel]::Optimal }
    }
    $n = 0
    foreach ($f in $files) {
        # Los nombres de entrada del ZIP usan "/" (v0.1.0 se publico con "\" y
        # algunos descompresores lo rompen: se normaliza siempre).
        $entryName = $f.FullName.Substring($BuildDir.Length).TrimStart('\') -replace '\\', '/'
        $entry = $zip.CreateEntry($entryName, $level)
        $entry.LastWriteTime = $f.LastWriteTime
        $es = $entry.Open()
        try {
            $src = [System.IO.File]::OpenRead($f.FullName)
            try { $src.CopyTo($es, 1048576) } finally { $src.Dispose() }
        } finally { $es.Dispose() }
        $n++
        if ($n % 50 -eq 0) { Write-Host ("  {0}/{1}..." -f $n, $files.Count) }
    }
} finally {
    $zip.Dispose()
    $fs.Dispose()
}

$final = Get-Item $ZipPath
Write-Host ""
Write-Host "ZIP OK: $($final.FullName)"
Write-Host ("  {0} MB · {1} archivos" -f [int]($final.Length / 1MB), $files.Count)
exit 0
