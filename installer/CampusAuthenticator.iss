#ifndef BundleDir
  #error BundleDir is required
#endif
#ifndef ReleaseDir
  #error ReleaseDir is required
#endif
#ifndef AppVersion
  #define AppVersion "6.2.3"
#endif

[Setup]
AppId={{9B75CF4A-E68B-44E2-829F-B8D86A94BF50}
AppName=校园网助手
AppVersion={#AppVersion}
AppPublisher=ruijie_helper
AppPublisherURL=https://github.com/wiizZ82066/ruijie_helper
DefaultDirName={autopf}\CampusAuthenticator
DefaultGroupName=校园网助手
DisableProgramGroupPage=yes
DisableDirPage=no
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#ReleaseDir}
OutputBaseFilename=CampusAuthenticator-Setup-{#AppVersion}-win-x64
SetupIconFile=..\icon\app.ico
UninstallDisplayIcon={app}\CampusAuthenticatorFlet.exe
WizardStyle=modern
Compression=lzma2
SolidCompression=yes
CloseApplications=no
RestartApplications=no
SetupLogging=yes

[Languages]
Name: "chinesesimp"; MessagesFile: "{#ChineseMessages}"

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "快捷方式："
Name: "startup"; Description: "开机自启动（后台运行）"; GroupDescription: "启动选项："; Flags: unchecked

[Files]
Source: "{#BundleDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\校园网助手"; Filename: "{app}\CampusAuthenticatorFlet.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\校园网助手"; Filename: "{app}\CampusAuthenticatorFlet.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[InstallDelete]
Type: files; Name: "{autodesktop}\校园网助手.lnk"; Check: not WizardIsTaskSelected('desktopicon')

[Run]
Filename: "{app}\CampusAuthenticatorFlet.exe"; Description: "立即运行校园网助手"; WorkingDir: "{app}"; Flags: postinstall nowait skipifsilent runascurrentuser

[Code]
function CreateFileW(FileName: String; DesiredAccess, ShareMode, SecurityAttributes,
  CreationDisposition, FlagsAndAttributes, TemplateFile: Cardinal): THandle;
  external 'CreateFileW@kernel32.dll stdcall';
function CloseHandle(Handle: THandle): Boolean;
  external 'CloseHandle@kernel32.dll stdcall';

function HelperIsRunning: Boolean;
var
  LockPath: String;
  Handle: THandle;
begin
  LockPath := ExpandConstant('{userappdata}\CampusLogin\authenticator.lock');
  Result := False;
  if not FileExists(LockPath) then exit;
  { The running helper holds this file with read sharing only. Never terminate
    an active authentication process or delete its lock during an upgrade. }
  Handle := CreateFileW(LockPath, $C0000000, 0, 0, 3, 0, 0);
  Result := Handle = THandle(-1);
  if not Result then CloseHandle(Handle);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if HelperIsRunning then
    Result := '助手正在运行。请在系统托盘右键校园网助手，选择“退出”，然后点击重试。';
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Code: Integer;
  Mode: String;
begin
  if CurStep = ssPostInstall then begin
    if WizardIsTaskSelected('startup') then Mode := 'enable' else Mode := 'disable';
    if not Exec(ExpandConstant('{app}\CampusAuthenticatorFlet.exe'),
        '--setup-startup ' + Mode, ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, Code)
        or (Code <> 0) then begin
      Log('Startup configuration failed; user must check the app settings.');
      MsgBox('助手已安装，但开机自启动设置未成功。请打开助手，在设置中重新确认。', mbError, MB_OK);
    end;
  end;
end;

function InitializeUninstall: Boolean;
begin
  Result := not HelperIsRunning;
  if not Result then
    MsgBox('请先从系统托盘退出校园网助手，再卸载。账号和设置会保留。', mbInformation, MB_OK);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Code: Integer;
begin
  if CurUninstallStep = usUninstall then begin
    { Do not remove a startup task which now belongs to a newer copy elsewhere. }
    if not Exec(ExpandConstant('{app}\CampusAuthenticatorFlet.exe'),
        '--setup-startup remove-owned', ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, Code)
        or (Code <> 0) then
      MsgBox('无法自动清理本版本的启动项，请在助手设置或任务计划程序中确认。', mbError, MB_OK);
  end;
end;
