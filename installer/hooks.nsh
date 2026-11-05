; Tauri v2 NSIS extension. Per-machine setup is elevated; the app stays asInvoker.
!include "LogicLib.nsh"
!define AEGIS_HOOK_DIR "${__FILEDIR__}"

!macro NSIS_HOOK_PREINSTALL
  InitPluginsDir
  File /oname=$PLUGINSDIR\prepare-vault.ps1 "${AEGIS_HOOK_DIR}\prepare-vault.ps1"
  nsExec::ExecToLog '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PLUGINSDIR\prepare-vault.ps1"'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "Impossibile preparare la cartella protetta di Aegis Security. Installazione interrotta."
    Abort
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
  SetShellVarContext all
  CreateShortcut "$DESKTOP\Aegis Security.lnk" "$INSTDIR\aegis-security.exe"
  WriteRegStr HKLM "Software\Classes\*\shell\AegisSecurityScan" "" "Analizza con Aegis Security"
  WriteRegStr HKLM "Software\Classes\*\shell\AegisSecurityScan" "Icon" '$\"$INSTDIR\aegis-security.exe$\",0'
  WriteRegStr HKLM "Software\Classes\*\shell\AegisSecurityScan\command" "" '$\"$INSTDIR\aegis-security.exe$\" --scan $\"%1$\"'
  WriteRegStr HKLM "Software\Classes\Directory\shell\AegisSecurityScan" "" "Analizza con Aegis Security"
  WriteRegStr HKLM "Software\Classes\Directory\shell\AegisSecurityScan" "Icon" '$\"$INSTDIR\aegis-security.exe$\",0'
  WriteRegStr HKLM "Software\Classes\Directory\shell\AegisSecurityScan\command" "" '$\"$INSTDIR\aegis-security.exe$\" --scan $\"%1$\"'
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  DeleteRegKey HKLM "Software\Classes\*\shell\AegisSecurityScan"
  DeleteRegKey HKLM "Software\Classes\Directory\shell\AegisSecurityScan"
  SetShellVarContext all
  Delete "$DESKTOP\Aegis Security.lnk"
  ; Intentionally preserve ProgramData and quarantined files on uninstall/upgrade.
!macroend
