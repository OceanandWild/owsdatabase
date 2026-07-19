; OWS Store - NSIS Installer Template (Dark Edition)
; Modern UI 2 with dark theme, custom bitmaps, and smooth animations

!define PRODUCT_NAME "{app_name}"
!define PRODUCT_VERSION "{version}"
!define PRODUCT_PUBLISHER "Ocean and Wild Studios"

; ── Modern UI 2 ─────────────────────────────────────────────────────────────
!include "MUI2.nsh"
!include "FileFunc.nsh"
!include "WinVer.nsh"

; ── Dark Theme Colors ───────────────────────────────────────────────────────
!define MUI_BGCOLOR 1210A16
!define MUI_TEXTCOLOR F0E6FF
!define MUI_LICENSEPAGE_BGCOLOR 1210A16
!define MUI_PROGRESSBAR_COLOR 7C3AED

; ── Custom Bitmaps ──────────────────────────────────────────────────────────
!define MUI_WELCOMEFINISHPAGE_BITMAP "installer-side.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "installer-side.bmp"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "installer-header.bmp"
!define MUI_HEADERIMAGE_UNBITMAP "installer-header.bmp"

; ── Installer Properties ────────────────────────────────────────────────────
Name "{app_name}"
OutFile "{output_name}"
InstallDir "$PROGRAMFILES64\{app_name}"
RequestExecutionLevel admin
ShowInstDetails hide
ShowUninstDetails hide
SetCompressor /SOLID lzma
SetCompressorDictSize 64
BrandingText "Ocean and Wild Studios"

; ── Version Info ────────────────────────────────────────────────────────────
VIProductVersion "{version}.0"
VIAddVersionKey ProductName "{app_name}"
VIAddVersionKey ProductVersion "{version}"
VIAddVersionKey CompanyName "Ocean and Wild Studios"
VIAddVersionKey FileVersion "{version}"
VIAddVersionKey FileDescription "{app_name} Installer"
VIAddVersionKey LegalCopyright "© {author}"

; ── Pages ───────────────────────────────────────────────────────────────────
!insertmacro MUI_PAGE_WELCOME
; License page omitted for this release
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; ── Language ────────────────────────────────────────────────────────────────
!insertmacro MUI_LANGUAGE "Spanish"
!insertmacro MUI_RESERVEFILE_INSTALLOPTIONS

; ── Custom Welcome Page Text ────────────────────────────────────────────────
LangString MUI_TEXT_WELCOME_INFO_TITLE ${LANG_SPANISH} "Bienvenido a $(^NameDA)"
LangString MUI_TEXT_WELCOME_INFO_TEXT ${LANG_SPANISH} "Este asistente te guiará en la instalación de $(^NameDA) $\r$\n$\r$\n$(^NameDA) es el launcher oficial del ecosistema Ocean and Wild Studios.$\r$\n$\r$\nSe recomienda cerrar cualquier instancia de $(^NameDA) antes de continuar."

LangString MUI_TEXT_FINISH_INFO_TITLE ${LANG_SPANISH} "Instalación completada"
LangString MUI_TEXT_FINISH_INFO_TEXT ${LANG_SPANISH} "$(^NameDA) se ha instalado correctamente en tu sistema.$\r$\n$\r$\nGracias por elegir Ocean and Wild Studios."
LangString MUI_TEXT_FINISH_SHOWRUN_TEXT ${LANG_SPANISH} "Ejecutar $(^NameDA) ahora"

; ── Macros ──────────────────────────────────────────────────────────────────
!macro DELETE_IF_EXISTS path
  IfFileExists `${path}` 0 +2
    Delete `${path}`
!macroend

!macro RMDIR_IF_EXISTS path
  IfFileExists `${path}` 0 +2
    RmDir /r `${path}`
!macroend

; ── Sections ────────────────────────────────────────────────────────────────
Section "Install"
  SetOutPath "$INSTDIR"
  SetOverwrite on

  ; Extract all files from the archive
  {files}

  ; Create shortcuts
  CreateDirectory "$SMPROGRAMS\{app_name}"
  CreateShortCut "$SMPROGRAMS\{app_name}\{app_name}.lnk" "$INSTDIR\{app_exe}" "" "$INSTDIR\{app_exe}" 0
  CreateShortCut "$DESKTOP\{app_name}.lnk" "$INSTDIR\{app_exe}" "" "$INSTDIR\{app_exe}" 0

  ; Write uninstaller
  WriteUninstaller "$INSTDIR\uninstall.exe"

  ; Register in Add/Remove Programs
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\{app_name}" "DisplayName" "{app_name}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\{app_name}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\{app_name}" "DisplayIcon" "$INSTDIR\{app_exe},0"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\{app_name}" "DisplayVersion" "{version}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\{app_name}" "Publisher" "Ocean and Wild Studios"
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\{app_name}" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\{app_name}" "NoRepair" 1
SectionEnd

; ── Uninstall ────────────────────────────────────────────────────────────────
Section "Uninstall"
  ; Remove shortcuts
  !insertmacro DELETE_IF_EXISTS "$SMPROGRAMS\{app_name}\{app_name}.lnk"
  !insertmacro DELETE_IF_EXISTS "$DESKTOP\{app_name}.lnk"
  RmDir "$SMPROGRAMS\{app_name}"

  ; Remove installation directory
  !insertmacro RMDIR_IF_EXISTS "$INSTDIR"

  ; Remove registry keys
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\{app_name}"
SectionEnd
