; ═══════════════════════════════════════════════════════════════════
; OWS Store — Custom NSIS Hooks
; Kills any running instance before installation to prevent os error 32
; ═══════════════════════════════════════════════════════════════════

!macro customInit
  ; ── Kill running OWS Store instances ──────────────────────────────
  ; This prevents "os error 32: file is being used by another process"
  ; when the installer tries to replace the main executable or DLLs.

  ; Try to gracefully close via WM_CLOSE first (waits up to 3 seconds)
  nsExec::ExecToStack 'cmd /c "tasklist /FI \"IMAGENAME eq ows-store.exe\" /NH"'
  Pop $0
  Pop $1

  ${If} $0 == "0"
    ; Process exists — try graceful close via PowerShell
    DetailPrint "Closing running OWS Store instance..."
    nsExec::ExecToStack 'cmd /c "powershell -NoProfile -Command "$proc = Get-Process -Name ows-store -ErrorAction SilentlyContinue; if ($proc) { $proc.CloseMainWindow() | Out-Null; Start-Sleep -Milliseconds 500; if (!$proc.HasExited) { $proc.Kill() | Out-Null } }""
    Pop $0
    ; Wait for process to actually exit
    Sleep 1000
  ${EndIf}

  ; Force-kill any remaining instances (belt and suspenders)
  nsExec::ExecToStack 'cmd /c "taskkill /F /IM ows-store.exe /T 2>nul"'
  Pop $0
  Sleep 500

  ; Also kill any orphaned child processes (e.g. WebView2)
  nsExec::ExecToStack 'cmd /c "taskkill /F /IM ows-store.exe /T 2>nul & exit /b 0"'
  Pop $0
  Sleep 300
!macroend

!macro customInstallMode
  ; Always install for current user (no elevation prompt needed)
!macroend
