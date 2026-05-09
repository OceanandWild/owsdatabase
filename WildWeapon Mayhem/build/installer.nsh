!macro customInit
  ; Avoid stale process lock during update/install.
  nsExec::ExecToLog 'taskkill /F /T /IM "WildWeapon Mayhem.exe"'
!macroend

!macro customInstall
  ; Ensure Apps & Features uses the app executable icon instead of the Electron default.
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${UNINSTALL_REGISTRY_KEY}" "DisplayIcon" "$INSTDIR\${APP_EXECUTABLE_FILENAME}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${UNINSTALL_REGISTRY_KEY}" "DisplayIcon" "$INSTDIR\${APP_EXECUTABLE_FILENAME}"
  ; Recreate shortcuts with explicit icon to reduce stale Electron icon cache.
  Delete "$DESKTOP\${SHORTCUT_NAME}.lnk"
  Delete "$SMPROGRAMS\${SHORTCUT_NAME}.lnk"
  CreateShortCut "$DESKTOP\${SHORTCUT_NAME}.lnk" "$INSTDIR\${APP_EXECUTABLE_FILENAME}" "" "$INSTDIR\${APP_EXECUTABLE_FILENAME}" 0
  CreateShortCut "$SMPROGRAMS\${SHORTCUT_NAME}.lnk" "$INSTDIR\${APP_EXECUTABLE_FILENAME}" "" "$INSTDIR\${APP_EXECUTABLE_FILENAME}" 0
  ; Remove stale pinned shortcuts that can keep Electron's default icon cached.
  Delete "$APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\WildWeapon Mayhem.lnk"
  Delete "$APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Electron.lnk"
!macroend
