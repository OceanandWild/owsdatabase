# ---------------------------------------------------------------------------
# make-ui-plate.ps1 - Convierte una placa de UI generada (PNG con alpha) en una
# placa 9-slice limpia: esquinas sin deformar, bordes rectos y centro suave.
#
# Por qué: Flow entrega JPG 16:9 y la placa suele quedar más ancha que alta.
# Estirarla a un hueco con otra proporción deforma la filigrana de las esquinas.
# Acá se recortan las 4 esquinas reales, se estiran SOLO los tramos rectos y el
# centro, y se recompone a un tamaño canónico. En USS se usa con
# -unity-slice-left/right = CornerX y -unity-slice-top/bottom = CornerY.
#
# Uso:
#   powershell -ExecutionPolicy Bypass -File make-ui-plate.ps1 `
#     -In "wg_window_keyed.png" -Out "wg_window.png" -Width 1400 -Height 880 -Corner 150
#   powershell -ExecutionPolicy Bypass -File make-ui-plate.ps1 `
#     -In "wg_btn_keyed.png" -Out "wg_btn.png" -Width 620 -Height 180 -CornerX 110 -CornerY 40
# ---------------------------------------------------------------------------
param(
    [Parameter(Mandatory = $true)][string]$In,
    [Parameter(Mandatory = $true)][string]$Out,
    [Parameter(Mandatory = $true)][int]$Width,
    [Parameter(Mandatory = $true)][int]$Height,
    [int]$Corner = 0,
    [int]$CornerX = 0,
    [int]$CornerY = 0,
    [int]$TopShave = 0,
    [switch]$Glow
)

$ErrorActionPreference = "Stop"
$magick = "magick"

function Invoke-Magick {
    param([string[]]$MagickArgs, [string]$Label)
    & $magick @MagickArgs 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "magick falló en '$Label'" }
}

$src = (Resolve-Path -LiteralPath $In).Path
$outFull = [System.IO.Path]::GetFullPath($Out)
$outDir = Split-Path -Parent $outFull
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }

$cx = if ($CornerX -gt 0) { $CornerX } else { $Corner }
$cy = if ($CornerY -gt 0) { $CornerY } else { $Corner }
if ($cx -le 0 -or $cy -le 0) { throw "hace falta -Corner (o -CornerX/-CornerY) mayor que 0" }

$tw = $Width
$th = $Height
$ew = $tw - 2 * $cx
$eh = $th - 2 * $cy

$tmp = Join-Path $env:TEMP ("wg-plate-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

try {
    # 0) Preparación: recorte opcional del borde superior (restos de fondo)
    $work = Join-Path $tmp "src.png"
    if ($TopShave -gt 0) {
        Invoke-Magick @($src, "-shave", "0x$TopShave", "+repage", $work) "shave"
    }
    else {
        Copy-Item -LiteralPath $src -Destination $work -Force
    }

    $ident = & $magick identify -format "%w %h" $work
    $W = [int]($ident -split ' ')[0]
    $H = [int]($ident -split ' ')[1]
    Write-Host ("origen: {0}x{1}  ->  placa {2}x{3} (corner {4}x{5})" -f $W, $H, $tw, $th, $cx, $cy)

    if ($W -le (2 * $cx) -or $H -le (2 * $cy)) {
        throw "la placa es demasiado chica ($W x $H) para un corner de ${cx}x${cy}"
    }
    if ($ew -le 0 -or $eh -le 0) { throw "tamaño final inválido para ese corner" }

    # 1) Esquinas reales (sin deformar)
    Invoke-Magick @($work, "-crop", "${cx}x${cy}+0+0", "+repage", (Join-Path $tmp "tl.png")) "esquina TL"
    Invoke-Magick @($work, "-crop", "${cx}x${cy}+$($W - $cx)+0", "+repage", (Join-Path $tmp "tr.png")) "esquina TR"
    Invoke-Magick @($work, "-crop", "${cx}x${cy}+0+$($H - $cy)", "+repage", (Join-Path $tmp "bl.png")) "esquina BL"
    Invoke-Magick @($work, "-crop", "${cx}x${cy}+$($W - $cx)+$($H - $cy)", "+repage", (Join-Path $tmp "br.png")) "esquina BR"

    # 2) Tramos rectos: se estiran solo en su eje
    Invoke-Magick @($work, "-crop", "$($W - 2 * $cx)x${cy}+${cx}+0", "+repage", "-resize", "${ew}x${cy}!", (Join-Path $tmp "top.png")) "borde sup"
    Invoke-Magick @($work, "-crop", "$($W - 2 * $cx)x${cy}+${cx}+$($H - $cy)", "+repage", "-resize", "${ew}x${cy}!", (Join-Path $tmp "bottom.png")) "borde inf"
    Invoke-Magick @($work, "-crop", "${cx}x$($H - 2 * $cy)+0+${cy}", "+repage", "-resize", "${cx}x${eh}!", (Join-Path $tmp "left.png")) "borde izq"
    Invoke-Magick @($work, "-crop", "${cx}x$($H - 2 * $cy)+$($W - $cx)+${cy}", "+repage", "-resize", "${cx}x${eh}!", (Join-Path $tmp "right.png")) "borde der"

    # 3) Centro: muestreo del medio estirado suave
    Invoke-Magick @($work, "-crop", "$($W - 2 * $cx)x$($H - 2 * $cy)+${cx}+${cy}", "+repage", "-resize", "${ew}x${eh}!", (Join-Path $tmp "center.png")) "centro"

    # 4) Ensamblado
    Invoke-Magick @("-size", "${tw}x${th}", "xc:none", (Join-Path $tmp "center.png"), "-geometry", "+${cx}+${cy}", "-composite", (Join-Path $tmp "p1.png")) "comp centro"
    Invoke-Magick @((Join-Path $tmp "p1.png"), (Join-Path $tmp "top.png"), "-geometry", "+${cx}+0", "-composite", (Join-Path $tmp "p2.png")) "comp sup"
    Invoke-Magick @((Join-Path $tmp "p2.png"), (Join-Path $tmp "bottom.png"), "-geometry", "+${cx}+$($th - $cy)", "-composite", (Join-Path $tmp "p3.png")) "comp inf"
    Invoke-Magick @((Join-Path $tmp "p3.png"), (Join-Path $tmp "left.png"), "-geometry", "+0+${cy}", "-composite", (Join-Path $tmp "p4.png")) "comp izq"
    Invoke-Magick @((Join-Path $tmp "p4.png"), (Join-Path $tmp "right.png"), "-geometry", "+$($tw - $cx)+${cy}", "-composite", (Join-Path $tmp "p5.png")) "comp der"
    Invoke-Magick @((Join-Path $tmp "p5.png"), (Join-Path $tmp "tl.png"), "-geometry", "+0+0", "-composite", (Join-Path $tmp "p6.png")) "comp TL"
    Invoke-Magick @((Join-Path $tmp "p6.png"), (Join-Path $tmp "tr.png"), "-geometry", "+$($tw - $cx)+0", "-composite", (Join-Path $tmp "p7.png")) "comp TR"
    Invoke-Magick @((Join-Path $tmp "p7.png"), (Join-Path $tmp "bl.png"), "-geometry", "+0+$($th - $cy)", "-composite", (Join-Path $tmp "p8.png")) "comp BL"
    Invoke-Magick @((Join-Path $tmp "p8.png"), (Join-Path $tmp "br.png"), "-geometry", "+$($tw - $cx)+$($th - $cy)", "-composite", $outFull) "comp BR"

    # 5) Resplandor cálido opcional (placa completa, para no marcar costuras)
    if ($Glow) {
        $glowPng = Join-Path $tmp "glow.png"
        Invoke-Magick @("-size", "${tw}x${th}", "radial-gradient:#33260f-#000000", "-alpha", "set", "-channel", "A", "-evaluate", "multiply", "0.55", "+channel", $glowPng) "glow"
        Invoke-Magick @($outFull, $glowPng, "-compose", "screen", "-composite", $outFull) "glow comp"
    }

    # 6) Preview sobre fondo oscuro para revisar costuras
    $preview = Join-Path $outDir ([System.IO.Path]::GetFileNameWithoutExtension($outFull) + "_preview.png")
    Invoke-Magick @("-size", "${tw}x${th}", "xc:#1a2433", $outFull, "-composite", $preview) "preview"

    $final = & $magick identify -format "%wx%h %[channels]" $outFull
    Write-Host ("ok: {0} -> {1}" -f $final, $preview)
}
finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
