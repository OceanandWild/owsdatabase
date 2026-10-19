# WildWeapon Mayhem — preview de encuadre de los 12 mapas (entorno + plataformas + rect de arena)
#
# Compone, para cada mapa, la vista real que arma MapGenerator:
#   - el fondo (ww_map_<id>_bg) estirado a TODO el encuadre 16:9
#   - los decks (ww_plat_<id>) en su huella y posicion reales (mirror incluido)
#   - el rectangulo del limite de arena (colo: lo que hoy seria el collider de muros)
# Asi se afina MapDef.backdropArenaFraction (fraccion del encuadre que ocupa la arena)
# sin tener que entrar a jugar.
#
# Uso: powershell -File map-layout-preview.ps1 [-Fraction 0.66] [-OutDir <dir>]

param(
    [double]$Fraction = 0.66,
    [string]$OutDir = "",
    [int]$Width = 1280
)

$ErrorActionPreference = "Stop"
# Formato numerico invariante (evita separador de miles/decimal local al pasar coords a ImageMagick)
[System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::InvariantCulture

$root    = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)   # WildWeapon Mayhem
$sprites = Join-Path $root "Assets\_WildWeapon\Art\Sprites"
$tmp     = Join-Path $env:LOCALAPPDATA "Temp\opencode\ww_map_preview"
if (-not $OutDir) { $OutDir = $tmp }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$H = [int][math]::Round($Width * 9 / 16)

# id, arena (w,h), fraction propia, decks: (cx, cy, w, h, mirrored)
$maps = @(
    @{ id='duela';    arena=@(16,9);   f=0.68; decks=@(@(0,0,3.6,2,$false),@(5,2.6,3.8,2,$true)) },
    @{ id='neon';     arena=@(16,9);   f=0.66; decks=@(@(0,0,3.4,1.8,$false),@(4.8,-2.4,4.2,2.2,$true)) },
    @{ id='camara';   arena=@(16,9);   f=0.64; decks=@(@(0,0,4,1.8,$false),@(5.2,2.6,3.6,2,$true)) },
    @{ id='eco';      arena=@(16,9);   f=0.71; decks=@(@(0,0,3.6,2.1,$false),@(5.3,-2.5,3.4,2,$true)) },
    @{ id='leviatan'; arena=@(20,11);  f=0.68; decks=@(@(0,0,4.6,2.4,$false),@(6.4,3,3.6,2,$true),@(6.6,-2.8,3.8,2,$true)) },
    @{ id='boveda';   arena=@(20,11);  f=0.68; decks=@(@(0,0,4.8,2.2,$false),@(7,2.6,3.6,2.2,$true),@(6.8,-2.9,3.6,2,$true)) },
    @{ id='nebula';   arena=@(20,11);  f=0.67; decks=@(@(0,0,5.2,2.2,$false),@(6.8,3,3.6,2,$true),@(6.6,-2.8,4.4,2.4,$true)) },
    @{ id='vivero';   arena=@(20,11);  f=0.66; decks=@(@(0,0,4.4,2.2,$false),@(6.8,2.9,3.8,2.2,$true),@(6.8,-2.9,3.6,2,$true)) },
    @{ id='templo';   arena=@(24,13);  f=0.68; decks=@(@(0,0,5,2.4,$false),@(0,4.3,6.6,2.2,$true),@(8.2,3.2,4.6,2.4,$true),@(8.8,-3.3,3.8,2,$true),@(8.8,0,3.6,2.6,$true)) },
    @{ id='domo';     arena=@(24,13);  f=0.70; decks=@(@(0,0,5.2,2.4,$false),@(0,4.3,6.6,2.2,$true),@(8.4,3.4,4.6,2.4,$true),@(8.8,-3.4,3.6,2,$true),@(8.8,0,3.6,2.4,$true)) },
    @{ id='mercado';  arena=@(24,13);  f=0.67; decks=@(@(0,0,4.8,2.4,$false),@(0,4.2,7,2.2,$true),@(8.2,3.2,4.8,2.4,$true),@(8.8,-3.3,3.6,2,$true),@(8.8,0,3.6,2.6,$true)) },
    @{ id='nucleo';   arena=@(24,13);  f=0.67; decks=@(@(0,0,6.4,2.6,$false),@(0,4.3,6.4,2.2,$true),@(8.4,3.4,4.4,2.2,$true),@(8.8,-3.4,3.6,2.2,$true),@(8.9,0,3.2,2.6,$true)) }
)

$aspect = $Width / $H

foreach ($m in $maps) {
    $id = $m.id
    $aw = [double]$m.arena[0]; $ah = [double]$m.arena[1]
    $f  = if ($null -ne $m.f) { [double]$m.f } else { $Fraction }
    $halfW = $aw / 2; $halfH = $ah / 2
    # misma formula que MapGenerator: ortho = max(halfH/f, halfW/(f*aspect))
    $ortho = [math]::Max($halfH / $f, $halfW / ($f * $aspect))
    $viewW = 2 * $ortho * $aspect; $viewH = 2 * $ortho
    $ppu = $Width / $viewW

    $bg = Join-Path $sprites "ww_map_${id}_bg.png"
    $plat = Join-Path $sprites "ww_plat_${id}.png"
    $out = Join-Path $OutDir "preview_$id.png"

    $args = @($bg, "-resize", "${Width}x${H}!")
    foreach ($d in $m.decks) {
        $cx = [double]$d[0]; $cy = [double]$d[1]; $dw = [double]$d[2]; $dh = [double]$d[3]; $mir = $d[4]
        $centers = @(@($cx, $cy))
        if ($mir -and ($cx -ne 0 -or $cy -ne 0)) { $centers += ,@(-$cx, -$cy) }
        foreach ($c in $centers) {
            $pw = [int][math]::Round($dw * $ppu); $ph = [int][math]::Round($dh * $ppu)
            $px = [int][math]::Round($Width / 2 + $c[0] * $ppu - $pw / 2)
            $py = [int][math]::Round($H / 2 - $c[1] * $ppu - $ph / 2)
            $args += "("
            $args += $plat
            $args += @("-resize", "${pw}x${ph}!")
            $args += ")"
            $args += @("-geometry", "+$px+$py", "-composite")
        }
    }
    # limite de arena (2 px cian translucido) + centro
    $rw = [int][math]::Round($aw * $ppu); $rh = [int][math]::Round($ah * $ppu)
    $rx = [int][math]::Round(($Width - $rw) / 2); $ry = [int][math]::Round(($H - $rh) / 2)
    $drawRect = "rectangle {0},{1} {2},{3}" -f $rx, $ry, ($rx + $rw - 1), ($ry + $rh - 1)
    $drawV = "line {0},0 {0},{1}" -f [int]($Width / 2), $H
    $drawH = "line 0,{0} {1},{0}" -f [int]($H / 2), $Width
    $args += @(
        "-stroke", "#00F3FF", "-strokewidth", "2", "-fill", "none",
        "-draw", $drawRect,
        "-stroke", "#FF59D9", "-strokewidth", "1",
        "-draw", $drawV,
        "-draw", $drawH,
        "-strip"
    )
    & magick @args $out
    Write-Output ("{0,-9} f={1}  ortho={2:n2}  view={3:n2}x{4:n2}  px/u={5:n1}" -f $id, $f, $ortho, $viewW, $viewH, $ppu)
}

Write-Output ("previews en " + $OutDir)
