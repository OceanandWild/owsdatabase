# OWS Store - NSIS Post-Build Patch Script
# Patches the generated NSIS script to add dark theme and custom bitmaps
# Run AFTER `cargo tauri build`
param(
    [string]$ProjectDir = "OWS Store"
)

$scriptPath = "$ProjectDir/src-tauri/target/release/nsis/x64/installer.nsi"
$resourceDir = "$ProjectDir/src-tauri/target/release/nsis/x64"
$bmpSrc = "$ProjectDir/src-tauri/installer"

if (-not (Test-Path $scriptPath)) {
    Write-Error "NSIS script not found at $scriptPath"
    exit 1
}

$content = Get-Content -Raw $scriptPath

# 1) Inject MUI2 bitmap defines AFTER the MUI2 include but BEFORE page macros
$muiInject = @'
; ── OWS Custom Branding ────────────────────────────────────────────────
!define MUI_BGCOLOR 1210A16
!define MUI_TEXTCOLOR F0E6FF
!define MUI_WELCOMEFINISHPAGE_BITMAP "installer-side.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "installer-side.bmp"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "installer-header.bmp"
!define MUI_HEADERIMAGE_UNBITMAP "installer-header.bmp"

'@

# Insert BEFORE `!include MUI2.nsh`
$insertPoint = '!include MUI2.nsh'
if ($content -match [regex]::Escape($insertPoint)) {
    $content = $content -replace [regex]::Escape($insertPoint), ($muiInject + "`r`n" + $insertPoint)
    Write-Output "Injected MUI2 bitmap defines before !include MUI2.nsh"
} else {
    Write-Warning "Could not find !include MUI2.nsh"
}

# 2) Add a modern dark-themed welcome page text override
$welcomeInject = @'
; ── OWS Custom Welcome Text ────────────────────────────────────────────
LangString MUI_TEXT_WELCOME_INFO_TITLE ${LANG_SPANISH} "Bienvenido a ${PRODUCTNAME}"
LangString MUI_TEXT_WELCOME_INFO_TEXT ${LANG_SPANISH} "Este asistente te guiará en la instalación de ${PRODUCTNAME}.$\r$\n$\r$\n${PRODUCTNAME} es el launcher oficial del ecosistema Ocean and Wild Studios."
LangString MUI_TEXT_FINISH_INFO_TITLE ${LANG_SPANISH} "Instalación completada"
LangString MUI_TEXT_FINISH_INFO_TEXT ${LANG_SPANISH} "${PRODUCTNAME} se ha instalado correctamente en tu sistema."
LangString MUI_TEXT_FINISH_SHOWRUN_TEXT ${LANG_SPANISH} "Ejecutar ${PRODUCTNAME} ahora"

'@
$insertAfter = '!insertmacro MUI_LANGUAGE "English"'
$langFound = $false
if ($content -match [regex]::Escape($insertAfter)) {
    $content = $content -replace [regex]::Escape($insertAfter), ($insertAfter + "`r`n" + $welcomeInject)
    $langFound = $true
    Write-Output "Injected custom welcome text"
}
if (-not $langFound) {
    # Try alternative - search for any MUI_LANGUAGE line
    if ($content -match '(?m)^(!insertmacro MUI_LANGUAGE "[^"]+")') {
        $content = $content -replace [regex]::Escape($matches[1]), ($matches[1] + "`r`n" + $welcomeInject)
        Write-Output "Injected custom welcome text (alternative match)"
    } else {
        Write-Warning "Could not find MUI_LANGUAGE line"
    }
}

# 3) Write the patched script
[System.IO.File]::WriteAllText($scriptPath, $content, (New-Object System.Text.UTF8Encoding($false)))
Write-Output "Patched NSIS script written"

# 4) Copy bitmap resources to NSIS working directory
if (Test-Path $bmpSrc) {
    Copy-Item "$bmpSrc/installer-side.bmp" $resourceDir -Force -ErrorAction SilentlyContinue
    Copy-Item "$bmpSrc/installer-header.bmp" $resourceDir -Force -ErrorAction SilentlyContinue
    Write-Output "Copied bitmap resources to NSIS directory"
} else {
    Write-Warning "Bitmap source directory not found: $bmpSrc"
}
