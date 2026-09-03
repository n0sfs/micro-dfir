; Micro DFIR Windows Agent Installer
;
; Bundles Python's official "embeddable" distribution so no system-wide Python install
; is a prerequisite anymore (see agents/micro_agent_windows.py's own Deployment-tab
; note about the plain-script path needing one). Built once, here, not rebuilt per
; download -- the per-deployment host/token/cert live in a small agent_config.json that
; the Flask backend generates fresh per download and zips up alongside this static .exe
; (see api_agent_download_windows_installer in src/app.py). This installer picks that
; file up at RUN time from its own directory ($EXEDIR), not at build time, so the same
; compiled .exe works for every deployment/tenant.
;
; Build: installer/build.ps1 (downloads the embeddable Python zip if missing, then
; invokes makensis on this script). Output: installer/dist/MicroDFIRAgentSetup.exe,
; checked into the repo since the production download route serves it directly --
; the Linux appliance has no way to compile a Windows installer itself.

!include "MUI2.nsh"

Name "Micro DFIR Agent"
OutFile "dist\MicroDFIRAgentSetup.exe"
InstallDir "C:\Program Files\MicroDFIR"
RequestExecutionLevel admin
ShowInstDetails show
ShowUninstDetails show

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "Install"
    ; The embeddable Python runtime -- permanent home, since install_agent() (in the
    ; script this launches) bakes THIS exact path into the scheduled tasks it creates
    ; (both the ONSTART task and the 5-minute watchdog), via sys.executable at install
    ; time. It must still exist at this path on every future reboot/relaunch.
    SetOutPath "$INSTDIR\python-embed"
    File /r "vendor\python-embed\*.*"

    ; Per-deployment config, generated fresh per download by the Flask backend and
    ; zipped alongside this installer .exe -- picked up from wherever THIS installer is
    ; currently running from (its own directory), not baked into the compiled .exe.
    ; Falls back to the script's own built-in placeholders if absent (e.g. this .exe was
    ; copied away from its config file) -- see _load_external_config() in the script.
    IfFileExists "$EXEDIR\agent_config.json" have_config no_config
    have_config:
        CopyFiles "$EXEDIR\agent_config.json" "$INSTDIR\agent_config.json"
    no_config:
        DetailPrint "No agent_config.json found next to this installer -- the agent will fall back to its own built-in placeholders (likely unconfigured)."

    ; Staged OUTSIDE $INSTDIR deliberately -- install_agent() (inside this script) copies
    ; its own running source into $INSTDIR\micro_agent_windows.py by opening that exact
    ; path for both read and write; if $EXEDIR/__FILE__ were already that same path, that
    ; open-for-read + open-for-write-truncate pair would race against itself on the same
    ; file. $PLUGINSDIR is NSIS's own per-run temp directory, already used for exactly
    ; this kind of "extract, run once, then discard" staging.
    SetOutPath "$PLUGINSDIR"
    File "..\agents\micro_agent_windows.py"

    DetailPrint "Installing the Micro DFIR agent (this runs the bundled Python against the staged script)..."
    nsExec::ExecToLog '"$INSTDIR\python-embed\python.exe" "$PLUGINSDIR\micro_agent_windows.py" install'
    Pop $0
    DetailPrint "Agent install exit code: $0"

    WriteUninstaller "$INSTDIR\Uninstall.exe"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MicroDFIRAgent" "DisplayName" "Micro DFIR Agent"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MicroDFIRAgent" "UninstallString" "$INSTDIR\Uninstall.exe"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MicroDFIRAgent" "InstallLocation" "$INSTDIR"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MicroDFIRAgent" "Publisher" "Micro DFIR"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MicroDFIRAgent" "DisplayVersion" "1.0"
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MicroDFIRAgent" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MicroDFIRAgent" "NoRepair" 1
SectionEnd

Section "Uninstall"
    IfFileExists "$INSTDIR\micro_agent_windows.py" have_script no_script
    have_script:
        DetailPrint "Removing scheduled tasks and background process..."
        nsExec::ExecToLog '"$INSTDIR\python-embed\python.exe" "$INSTDIR\micro_agent_windows.py" uninstall'
    no_script:

    RMDir /r "$INSTDIR"
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MicroDFIRAgent"
SectionEnd
