!macro customInit
  ; Close stale app process so installer does not block on a false "app is running" state.
  nsExec::ExecToLog 'taskkill /F /T /IM "OWS Store.exe"'
  nsExec::ExecToLog 'taskkill /F /T /IM "OWS Nexus Store.exe"'
!macroend

!macro customInstall
  ; Ensure Apps & Features uses the app executable icon instead of the Electron default.
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${UNINSTALL_REGISTRY_KEY}" "DisplayIcon" "$INSTDIR\${APP_EXECUTABLE_FILENAME}"
  ; Recreate shortcuts with explicit icon to reduce stale Electron icon cache.
  Delete "$DESKTOP\${SHORTCUT_NAME}.lnk"
  Delete "$SMPROGRAMS\${SHORTCUT_NAME}.lnk"
  CreateShortCut "$DESKTOP\${SHORTCUT_NAME}.lnk" "$INSTDIR\${APP_EXECUTABLE_FILENAME}" "" "$INSTDIR\${APP_EXECUTABLE_FILENAME}" 0
  CreateShortCut "$SMPROGRAMS\${SHORTCUT_NAME}.lnk" "$INSTDIR\${APP_EXECUTABLE_FILENAME}" "" "$INSTDIR\${APP_EXECUTABLE_FILENAME}" 0
!macroend
