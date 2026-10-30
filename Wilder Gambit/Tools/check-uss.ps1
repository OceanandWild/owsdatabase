# ---------------------------------------------------------------------------
# check-uss.ps1 - Sanidad de las hojas USS del proyecto, sin abrir Unity.
#
#   * llaves balanceadas y ausencia de "!important"
#   * propiedades desconocidas para USS (typos típicos: box-shadow, filter, gap)
#   * url("project://database/...") que apunten a archivos inexistentes
#   * coherencia entre -unity-slice-* del tema y los bordes de WgUiArtImport.cs
#
# Uso: powershell -ExecutionPolicy Bypass -File Tools/check-uss.ps1 [-Verbose]
# ---------------------------------------------------------------------------
param([switch]$Verbose)

$ErrorActionPreference = "Stop"
$proj = Split-Path -Parent $PSScriptRoot
$uiDir = Join-Path $proj "Assets\_Project\UI"
$themePath = Join-Path $uiDir "WgTheme.uss"
$importerPath = Join-Path $proj "Assets\_Project\Editor\WgUiArtImport.cs"

# Propiedades que UI Toolkit NO entiende (las que suelen colarse por copiar CSS web).
$unsupported = @(
    "box-shadow", "filter", "backdrop-filter", "animation", "transform",
    "transform-origin", "will-change", "z-index", "float", "clear",
    "overflow-x", "overflow-y", "outline", "cursor", "background-blend-mode",
    "grid-template-columns", "grid-template-rows"
)

$problems = New-Object System.Collections.Generic.List[string]
$checked = 0

Get-ChildItem -LiteralPath $uiDir -Filter *.uss -File | ForEach-Object {
    $path = $_.FullName
    $name = $_.Name
    $checked++
    $text = [System.IO.File]::ReadAllText($path)

    $open = ([regex]::Matches($text, '\{')).Count
    $close = ([regex]::Matches($text, '\}')).Count
    if ($open -ne $close) { $problems.Add("$name : llaves desbalanceadas ($open / $close)") }

    if ($name -eq "WgTheme.uss") {
        foreach ($prop in $unsupported) {
            if ($text -match ('(?m)^\s*' + [regex]::Escape($prop) + '\s*:')) {
                $problems.Add("$name : propiedad no soportada '$prop'")
            }
        }
        if ($text -match '!important') { $problems.Add("$name : USS no soporta !important") }
    }

    foreach ($m in [regex]::Matches($text, 'url\("project://database/([^"]+)"\)')) {
        $asset = Join-Path $proj $m.Groups[1].Value.Replace('/', '\')
        if (-not (Test-Path -LiteralPath $asset)) { $problems.Add("$name : url roto -> $($m.Groups[1].Value)") }
    }
}

# Coherencia de 9-slice entre el tema y el importador
$theme = [System.IO.File]::ReadAllText($themePath)
$importer = [System.IO.File]::ReadAllText($importerPath)

function Get-ThemeSliceBlock([string]$text, [string]$selector) {
    # Acepta reglas agrupadas: ".modal-dialog,\n.settings-modal-dialog { ... }"
    $text = [regex]::Replace($text, '/\*[\s\S]*?\*/', '')
    $body = $null
    foreach ($m in [regex]::Matches($text, '(?m)([^{}]+)\{([^}]*)\}')) {
        $sels = $m.Groups[1].Value -split ',' | ForEach-Object { ($_ -replace '\s+', ' ').Trim() }
        if ($sels -contains $selector) { $body = $m.Groups[2].Value; break }
    }
    if ($null -eq $body) { return $null }
    return @{
        L = [regex]::Match($body, '-unity-slice-left:\s*(\d+)(?:px)?').Groups[1].Value
        R = [regex]::Match($body, '-unity-slice-right:\s*(\d+)(?:px)?').Groups[1].Value
        T = [regex]::Match($body, '-unity-slice-top:\s*(\d+)(?:px)?').Groups[1].Value
        B = [regex]::Match($body, '-unity-slice-bottom:\s*(\d+)(?:px)?').Groups[1].Value
    }
}

$map = @(
    @{ Selector = ".shop2-window"; Asset = "wg_window.png" },
    @{ Selector = ".modal-dialog"; Asset = "wg_panel.png" },
    @{ Selector = ".bg-card"; Asset = "wg_card.png" },
    @{ Selector = ".btn-primary"; Asset = "wg_btn.png" },
    @{ Selector = ".menu-tile"; Asset = "wg_tile.png" },
    @{ Selector = ".menu-wallet"; Asset = "wg_chip.png" }
)

foreach ($entry in $map) {
    $slice = Get-ThemeSliceBlock $theme $entry.Selector
    if ($null -eq $slice) { $problems.Add("tema: falta el bloque $($entry.Selector)"); continue }
    $m = [regex]::Match($importer, [regex]::Escape('"' + $entry.Asset + '"') + '\s*,\s*new Vector4\(([^)]*)\)')
    if (-not $m.Success) { $problems.Add("importador: falta el borde de $($entry.Asset)"); continue }
    $nums = $m.Groups[1].Value -split ',' | ForEach-Object { [int][double](($_.Trim()) -replace 'f$','') }
    $expected = @($nums[0], $nums[1], $nums[2], $nums[3])
    $actual = @([int]$slice.L, [int]$slice.B, [int]$slice.R, [int]$slice.T)
    if (($expected -join ',') -ne ($actual -join ',')) {
        $problems.Add("desalineado $($entry.Selector) [$($entry.Asset)]: tema=$($actual -join '/') importador=$($expected -join '/')")
    }
    elseif ($Verbose) {
        Write-Host ("ok: {0,-16} {1} = {2}" -f $entry.Selector, $entry.Asset, ($expected -join '/'))
    }
}

Write-Host ("hojas revisadas: {0}" -f $checked)
if ($problems.Count -eq 0) {
    Write-Host "RESULTADO: OK" -ForegroundColor Green
    exit 0
}
foreach ($p in $problems) { Write-Host ("  ! " + $p) -ForegroundColor Yellow }
Write-Host ("RESULTADO: {0} problemas" -f $problems.Count) -ForegroundColor Red
exit 1
