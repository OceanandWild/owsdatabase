# OWS Store - NSIS Post-Build Patch Script (Dark Edition v2)
# Patches the generated NSIS script to add dark theme, custom bitmaps, and premium nsDialogs pages
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

# ── 1) Inject MUI2 bitmap defines before !include MUI2.nsh ──────────────────
$muiInject = @'
; ── OWS Custom Branding ────────────────────────────────────────────────
!define MUI_BGCOLOR 0A0816
!define MUI_TEXTCOLOR F0E6FF
!define MUI_WELCOMEFINISHPAGE_BITMAP "installer-side.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "installer-side.bmp"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "installer-header.bmp"
!define MUI_HEADERIMAGE_UNBITMAP "installer-header.bmp"
'@

$insertPoint = '!include MUI2.nsh'
if ($content -match [regex]::Escape($insertPoint)) {
    $content = $content -replace [regex]::Escape($insertPoint), ($muiInject + "`r`n" + $insertPoint)
    Write-Output "Injected MUI2 bitmap defines before !include MUI2.nsh"
} else {
    Write-Warning "Could not find !include MUI2.nsh"
}

# ── 2) Replace MUI_PAGE_WELCOME with custom nsDialogs welcome page ─────────
$customWelcomeCode = @'
; ── OWS Custom Welcome Page (nsDialogs) ───────────────────────────────
!define MUI_PAGE_CUSTOMFUNCTION_PRE SkipIfPassive
Page custom fnOWS_WelcomePageCreate fnOWS_WelcomePageLeave

Var OWS_Welcome_Title
Var OWS_Welcome_Subtitle
Var OWS_Welcome_Desc
Var OWS_Welcome_Version
Var OWS_Welcome_Copyright
Var OWS_Welcome_DecorLine1
Var OWS_Welcome_DecorLine2

Function fnOWS_WelcomePageCreate
  nsDialogs::Create 1044
  Pop $R0

  ${If} $(^RTL) = 1
    nsDialogs::SetRTL $(^RTL)
  ${EndIf}

  SetCtlColors $R0 "" "0A0816"

  ; Title - "OWS STORE" in primary color
  ${NSD_CreateLabel} 16u 12u 250u 22u "OWS STORE"
  Pop $OWS_Welcome_Title
  SetCtlColors $OWS_Welcome_Title "98CBFF" "0A0816"

  ; Subtitle - version
  ${NSD_CreateLabel} 16u 36u 250u 10u "Versión ${VERSION}"
  Pop $OWS_Welcome_Subtitle
  SetCtlColors $OWS_Welcome_Subtitle "98CBFF" "0A0816"

  ; Decorator line 1 (thin colored label as line)
  ${NSD_CreateLabel} 16u 50u 250u 2u ""
  Pop $OWS_Welcome_DecorLine1
  SetCtlColors $OWS_Welcome_DecorLine1 "98CBFF" "98CBFF"

  ; Description text
  ${NSD_CreateLabel} 16u 58u 250u 55u "Bienvenido al instalador oficial de OWS Store.$\r$\n$\r$\nEste asistente te guiará en la instalación del launcher del ecosistema Ocean and Wild Studios.$\r$\n$\r$\nSe recomienda cerrar cualquier instancia de OWS Store antes de continuar."
  Pop $OWS_Welcome_Desc
  SetCtlColors $OWS_Welcome_Desc "BEC7D4" "0A0816"

  ; Decorator line 2
  ${NSD_CreateLabel} 16u 118u 250u 2u ""
  Pop $OWS_Welcome_DecorLine2
  SetCtlColors $OWS_Welcome_DecorLine2 "98CBFF" "98CBFF"

  ; Copyright/version footer
  ${NSD_CreateLabel} 16u 128u 120u 10u "© 2026 Ocean and Wild Studios"
  Pop $OWS_Welcome_Copyright
  SetCtlColors $OWS_Welcome_Copyright "64748B" "0A0816"

  ; Version badge
  ${NSD_CreateLabel} 180u 128u 80u 10u "v${VERSION}-STABLE"
  Pop $OWS_Welcome_Version
  SetCtlColors $OWS_Welcome_Version "4BE260" "0A0816"

  nsDialogs::Show
FunctionEnd

Function fnOWS_WelcomePageLeave
  ; No validation needed, just proceed
FunctionEnd

'@

# Find MUI_PAGE_WELCOME and replace it
if ($content -match '(?m)^!define MUI_PAGE_CUSTOMFUNCTION_PRE SkipIfPassive\r?\n!insertmacro MUI_PAGE_WELCOME') {
    $content = $content -replace [regex]::Escape($Matches[0]), $customWelcomeCode
    Write-Output "Replaced MUI_PAGE_WELCOME with custom nsDialogs welcome page"
} else {
    Write-Warning "Could not find MUI_PAGE_WELCOME pattern - trying alternative match"
    # Try matching without carriage return
    if ($content -match '(?m)^!define MUI_PAGE_CUSTOMFUNCTION_PRE SkipIfPassive\n!insertmacro MUI_PAGE_WELCOME') {
        $content = $content -replace [regex]::Escape($Matches[0]), $customWelcomeCode
        Write-Output "Replaced MUI_PAGE_WELCOME with custom nsDialogs welcome page (alt)"
    } else {
        Write-Warning "Could not match MUI_PAGE_WELCOME at all"
    }
}

# ── 3) Custom finish page text in Spanish ──────────────────────────────────
$welcomeInject = @'
; ── OWS Custom Welcome Text ────────────────────────────────────────────
LangString MUI_TEXT_FINISH_INFO_TITLE ${LANG_SPANISH} "Instalación completada"
LangString MUI_TEXT_FINISH_INFO_TEXT ${LANG_SPANISH} "OWS Store se ha instalado correctamente en tu sistema.$\r$\n$\r$\nGracias por elegir Ocean and Wild Studios. Disfruta del ecosistema."
LangString MUI_TEXT_FINISH_SHOWRUN_TEXT ${LANG_SPANISH} "Ejecutar OWS Store ahora"

'@
$insertAfter = '!insertmacro MUI_LANGUAGE "English"'
$langFound = $false
if ($content -match [regex]::Escape($insertAfter)) {
    $content = $content -replace [regex]::Escape($insertAfter), ($insertAfter + "`r`n" + $welcomeInject)
    $langFound = $true
    Write-Output "Injected custom finish text"
}
if (-not $langFound) {
    if ($content -match '(?m)^(!insertmacro MUI_LANGUAGE "[^"]+")') {
        $content = $content -replace [regex]::Escape($matches[1]), ($matches[1] + "`r`n" + $welcomeInject)
        Write-Output "Injected custom finish text (alternative match)"
    } else {
        Write-Warning "Could not find MUI_LANGUAGE line"
    }
}

# ── 4) Enhance install page with a custom completion sound/vibe ────────────
# Keep MUI_PAGE_INSTFILES but add a post-function for final polish
$installFooterCode = @'

; ── OWS Install Complete Enhancement ──────────────────────────────────
Function .onInstSuccess
  ; Flash window to grab attention
  HideWindow
  FindWindow $R0 "_NSIS_CONFIG"
  IfSilent +2
  BringToFront
FunctionEnd

'@

$content += $installFooterCode
Write-Output "Added install complete enhancement"

# ── 5) Write the patched script ────────────────────────────────────────────
[System.IO.File]::WriteAllText($scriptPath, $content, (New-Object System.Text.UTF8Encoding($false)))
Write-Output "Patched NSIS script written"

# ── 6) Copy bitmap resources to NSIS working directory ────────────────────
if (Test-Path $bmpSrc) {
    Copy-Item "$bmpSrc/installer-side.bmp" "$resourceDir/installer-side.bmp" -Force -ErrorAction SilentlyContinue
    Copy-Item "$bmpSrc/installer-header.bmp" "$resourceDir/installer-header.bmp" -Force -ErrorAction SilentlyContinue
    Write-Output "Copied bitmap resources to NSIS directory"
} else {
    Write-Warning "Bitmap source directory not found: $bmpSrc"
}

Write-Output "=== Patch complete ==="
