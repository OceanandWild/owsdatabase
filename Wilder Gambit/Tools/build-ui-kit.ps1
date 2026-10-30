# ---------------------------------------------------------------------------
# build-ui-kit.ps1 - Arma el kit de UI del tema (Resources/UI/Wg) a partir de
# las placas generadas con Google Flow (_art-source/UI-Kit).
#
#   * placas 9-slice: pasan por make-ui-plate.ps1 (esquinas sin deformar)
#   * ornamentos (divisor, medalla): se copian tal como los dejó flow-gen
#
# Los ajustes de importación los aplica WgUiArtImporter.cs (Editor), así que acá
# no hace falta escribir .meta a mano.
# ---------------------------------------------------------------------------
$ErrorActionPreference = "Stop"

$proj = Split-Path -Parent $PSScriptRoot
$kit = Join-Path $proj "_art-source\UI-Kit"
$dest = Join-Path $proj "Assets\Resources\UI\Wg"
$plateTool = Join-Path $PSScriptRoot "make-ui-plate.ps1"

if (-not (Test-Path $kit)) { throw "no existe la carpeta del kit: $kit" }
if (-not (Test-Path $dest)) { New-Item -ItemType Directory -Force -Path $dest | Out-Null }

# nombre | ancho | alto | cornerX | cornerY | shave superior
$plates = @(
    @{ Name = "wg_window";   W = 1400; H = 880; CX = 150; CY = 150; Shave = 0; Src = "wg_window_keyed.png" },
    @{ Name = "wg_panel";    W = 1200; H = 760; CX = 130; CY = 130; Shave = 0; Src = "wg_panel_keyed.png" },
    @{ Name = "wg_card";     W = 480;  H = 640; CX = 72;  CY = 72;  Shave = 0; Src = "wg_card_keyed.png" },
    @{ Name = "wg_btn";      W = 620;  H = 180; CX = 110; CY = 40;  Shave = 8; Src = "wg_btn_keyed.png" },
    @{ Name = "wg_btn_dark"; W = 620;  H = 180; CX = 110; CY = 40;  Shave = 0; Src = "wg_btn_dark_keyed.png" },
    @{ Name = "wg_tile";     W = 560;  H = 140; CX = 30;  CY = 30;  Shave = 0; Src = "wg_tile_keyed.png" },
    @{ Name = "wg_chip";     W = 320;  H = 96;  CX = 26;  CY = 18;  Shave = 0; Src = "wg_chip_keyed.png" }
)

foreach ($p in $plates) {
    $src = Join-Path $kit $p.Src
    if (-not (Test-Path $src)) { Write-Warning ("falta {0}: se saltea {1}" -f $p.Src, $p.Name); continue }
    $out = Join-Path $dest ($p.Name + ".png")
    & powershell -NoProfile -ExecutionPolicy Bypass -File $plateTool `
        -In $src -Out $out -Width $p.W -Height $p.H `
        -CornerX $p.CX -CornerY $p.CY -TopShave $p.Shave
    if ($LASTEXITCODE -ne 0) { throw ("falló la placa " + $p.Name) }

    # El keying de Flow deja un resto claro pegado al filo superior del botón:
    # se tapa clonando una franja limpia del mismo borde.
    if ($p.Name -eq "wg_btn") {
        & magick $out "(" $out "-crop" "90x26+280+2" "+repage" ")" -geometry "+372+2" -composite $out
    }
}

# Ornamentos: no llevan 9-slice, se usan con scale-to-fit a tamaño exacto.
$plain = @("wg_divider", "wg_medal", "wg_banner")
foreach ($n in $plain) {
    $src = Join-Path $kit ($n + ".png")
    if (-not (Test-Path $src)) { Write-Warning ("falta {0}.png: se saltea" -f $n); continue }
    Copy-Item -LiteralPath $src -Destination (Join-Path $dest ($n + ".png")) -Force
}

# Las previews NO van en Resources (se compilarían al build): quedan archivadas.
$previewDir = Join-Path $kit "plates"
New-Item -ItemType Directory -Force -Path $previewDir | Out-Null
Get-ChildItem -LiteralPath $dest -Filter "*_preview.png" -File | ForEach-Object {
    Move-Item -LiteralPath $_.FullName -Destination (Join-Path $previewDir $_.Name) -Force
}

Write-Host "`n=== kit en Resources/UI/Wg ==="
Get-ChildItem -LiteralPath $dest -Filter *.png -File |
    ForEach-Object { "{0,-18} {1,10} bytes  {2}" -f $_.Name, $_.Length, (& magick identify -format "%wx%h" $_.FullName) }
