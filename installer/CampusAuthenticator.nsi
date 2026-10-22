; NSIS alternative installer. The application bundle is supplied unchanged.
Unicode true
!ifndef ExecutionLevel
  !define ExecutionLevel admin
!endif
RequestExecutionLevel ${ExecutionLevel}
ManifestDPIAware true
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"
!include "WinVer.nsh"

!ifndef DisplayName
  !define DisplayName "校园网助手"
!endif
!ifndef UninstallKey
  !define UninstallKey "Software\Microsoft\Windows\CurrentVersion\Uninstall\CampusAuthenticatorNSIS"
!endif
!ifndef DefaultDirectory
  !define DefaultDirectory "$PROGRAMFILES64\CampusAuthenticator"
!endif
Name "${DisplayName}"
Caption "${DisplayName} ${AppVersion} 安装"
OutFile "${OutputFile}"
InstallDir "${DefaultDirectory}"
InstallDirRegKey HKLM "${UninstallKey}" "InstallLocation"
SetCompressor /SOLID lzma
ShowInstDetails show
ShowUninstDetails show
Icon "..\icon\app.ico"
UninstallIcon "..\icon\app.ico"
Var Journal
Var LaunchFailed

!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "立即运行${DisplayName}"
!define MUI_FINISHPAGE_RUN_FUNCTION LaunchHelper
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "SimpChinese"

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "需要 64 位 Windows。" /SD IDOK
    Abort
  ${EndIf}
  ${IfNot} ${AtLeastWin10}
    MessageBox MB_ICONSTOP "需要 Windows 10 或更新版本。" /SD IDOK
    Abort
  ${EndIf}
  SetRegView 64
  SetShellVarContext all
  ReadRegStr $0 HKLM "${UninstallKey}" "InstallLocation"
  ${If} $0 != ""
    StrCpy $INSTDIR $0
  ${EndIf}
  StrCpy $LaunchFailed 0
FunctionEnd

!macro CheckHelper PREFIX
Function ${PREFIX}CheckHelper
  ; The application holds a non-writable shared lock. Never terminate it.
  SetShellVarContext current
  IfFileExists "$APPDATA\CampusLogin\authenticator.lock" 0 unlocked
  System::Call 'kernel32::CreateFileW(w "$APPDATA\CampusLogin\authenticator.lock", i 0xC0000000, i 0, p 0, i 3, i 0, p 0) p .r0'
  ${If} $0 == -1
    MessageBox MB_ICONSTOP "助手正在运行。请先从系统托盘退出，再重试。" /SD IDOK
    SetErrorLevel 21
    Abort
  ${EndIf}
  System::Call 'kernel32::CloseHandle(p r0)'
unlocked:
  SetShellVarContext all
FunctionEnd
!macroend
!insertmacro CheckHelper ""
!insertmacro CheckHelper "un."

Section "助手程序（必选）" Main
  SectionIn RO
  Call CheckHelper
  ; Avoid leaving two incompatible uninstallers owning the same directory.
  IfFileExists "$INSTDIR\unins000.dat" 0 +4
    MessageBox MB_ICONSTOP "此目录由旧安装器管理。请先卸载旧安装版（账号和设置会保留），再安装。" /SD IDOK
    SetErrorLevel 22
    Abort
  SetOutPath "$INSTDIR"
  ClearErrors
  FileOpen $Journal "$INSTDIR\installation.log" a
  IfErrors logFailed
  FileWrite $Journal "version=${AppVersion} stage=copy_begin$\r$\n"
  ClearErrors
  !include "${PayloadInclude}"
  IfErrors copyFailed
  FileWrite $Journal "stage=copy_complete startup=unchanged helper=not_started$\r$\n"
  ClearErrors
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  WriteRegStr HKLM "${UninstallKey}" "DisplayName" "${DisplayName}"
  WriteRegStr HKLM "${UninstallKey}" "DisplayVersion" "${AppVersion}"
  WriteRegStr HKLM "${UninstallKey}" "Publisher" "ruijie_helper"
  WriteRegStr HKLM "${UninstallKey}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UninstallKey}" "UninstallString" '$\"$INSTDIR\Uninstall.exe$\"'
  WriteRegStr HKLM "${UninstallKey}" "DisplayIcon" "$INSTDIR\CampusAuthenticatorFlet.exe"
  WriteRegDWORD HKLM "${UninstallKey}" "NoModify" 1
  WriteRegDWORD HKLM "${UninstallKey}" "NoRepair" 1
  CreateShortcut "$SMPROGRAMS\${DisplayName}.lnk" "$INSTDIR\CampusAuthenticatorFlet.exe" "" "$INSTDIR\CampusAuthenticatorFlet.exe"
  IfErrors copyFailed
  FileWrite $Journal "stage=registration_complete$\r$\n"
  FileClose $Journal
  Goto done
copyFailed:
  FileWrite $Journal "stage=install_failed$\r$\n"
  FileClose $Journal
logFailed:
  SetErrorLevel 20
  MessageBox MB_ICONSTOP "安装未完成。请检查文件访问权限和 Windows 安全中心保护历史记录。" /SD IDOK
  Abort
done:
SectionEnd

Section "创建桌面快捷方式" Desktop
  ClearErrors
  CreateShortcut "$DESKTOP\${DisplayName}.lnk" "$INSTDIR\CampusAuthenticatorFlet.exe" "" "$INSTDIR\CampusAuthenticatorFlet.exe"
  ${If} ${Errors}
    SetErrorLevel 20
    MessageBox MB_ICONEXCLAMATION "无法创建桌面快捷方式。" /SD IDOK
    Abort
  ${EndIf}
SectionEnd

Function LaunchHelper
  ; Called only by the finish-page checkbox, never by silent installation.
  ${If} $LaunchFailed == 1
    Return
  ${EndIf}
  FileOpen $Journal "$INSTDIR\installation.log" a
  FileWrite $Journal "stage=desktop_launch_requested$\r$\n"
  SetOutPath "$INSTDIR"
  ClearErrors
  Exec '"$INSTDIR\CampusAuthenticatorFlet.exe"'
  ${If} ${Errors}
    StrCpy $LaunchFailed 1
    FileWrite $Journal "stage=desktop_launch_failed$\r$\n"
    SetErrorLevel 20
    MessageBox MB_ICONSTOP "助手未能运行。请检查 Windows 安全中心的保护历史记录。安装器不会再次尝试启动。"
  ${Else}
    FileWrite $Journal "stage=process_created readiness=not_verified$\r$\n"
  ${EndIf}
  FileClose $Journal
FunctionEnd

Function un.onInit
  SetRegView 64
  SetShellVarContext all
  Call un.CheckHelper
  ReadRegStr $0 HKLM "${UninstallKey}" "InstallLocation"
  ${If} $0 != $INSTDIR
    MessageBox MB_ICONSTOP "卸载记录与此目录不一致，请从 Windows 已安装的应用中选择当前版本。" /SD IDOK
    SetErrorLevel 23
    Abort
  ${EndIf}
FunctionEnd

Section "Uninstall"
  ; This command removes only a task pointing to this exact executable.
  ClearErrors
  ExecWait '"$INSTDIR\CampusAuthenticatorFlet.exe" --setup-startup remove-owned' $0
  ${If} ${Errors}
    MessageBox MB_ICONEXCLAMATION "无法清理本版本的启动项，请在任务计划程序中确认。" /SD IDOK
  ${ElseIf} $0 != 0
    MessageBox MB_ICONEXCLAMATION "启动项清理未完成，请在任务计划程序中确认。" /SD IDOK
  ${EndIf}
  !include "${UninstallInclude}"
  Delete "$INSTDIR\installation.log"
  Delete "$INSTDIR\Uninstall.exe"
  Delete "$SMPROGRAMS\${DisplayName}.lnk"
  Delete "$DESKTOP\${DisplayName}.lnk"
  DeleteRegKey HKLM "${UninstallKey}"
  ; No recursive deletion: user-created files and AppData are preserved.
  RMDir "$INSTDIR"
SectionEnd
