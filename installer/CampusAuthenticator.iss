#ifndef BundleDir
  #error BundleDir is required
#endif
#ifndef ReleaseDir
  #error ReleaseDir is required
#endif
#ifndef AppVersion
  #define AppVersion "6.2.4"
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

[Files]
Source: "{#BundleDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\校园网助手"; Filename: "{app}\CampusAuthenticatorFlet.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\校园网助手"; Filename: "{app}\CampusAuthenticatorFlet.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[InstallDelete]
Type: files; Name: "{autodesktop}\校园网助手.lnk"; Check: not WizardIsTaskSelected('desktopicon')

[Code]
var
  LaunchFailed: Boolean;
  RunAfterInstall: TNewCheckBox;

function LaunchFailureMessage(Code: Integer): String;
begin
  if (Code = 225) or (Code = 226) then
    Result := 'Windows 安全防护已拦截或隔离助手（错误 ' + IntToStr(Code) + '）。' + #13#10 +
      '请查看 Windows 安全中心的“保护历史记录”，记录威胁名称并反馈给开发者。' + #13#10 +
      '无需关闭杀毒防护或添加排除项。安装程序不会再次自动启动助手。'
  else
    Result := '助手未能运行（错误 ' + IntToStr(Code) + '）。请检查程序文件是否完整、' +
      'Windows 安全中心的保护历史记录及本地日志。';
end;

procedure InitializeWizard;
begin
  RunAfterInstall := TNewCheckBox.Create(WizardForm);
  RunAfterInstall.Parent := WizardForm.FinishedPage;
  RunAfterInstall.Left := WizardForm.FinishedLabel.Left;
  RunAfterInstall.Top := WizardForm.FinishedLabel.Top + WizardForm.FinishedLabel.Height + ScaleY(12);
  RunAfterInstall.Width := WizardForm.FinishedLabel.Width;
  RunAfterInstall.Caption := '立即运行校园网助手';
  RunAfterInstall.Checked := True;
  RunAfterInstall.Visible := False;
end;

procedure ShowIncompleteInstallation;
begin
  RunAfterInstall.Checked := False;
  RunAfterInstall.Visible := False;
  WizardForm.FinishedHeadingLabel.Caption := '安装尚需处理';
  WizardForm.FinishedLabel.Caption := '程序文件已复制，但助手未能运行。' + #13#10 +
    '本次安装未完成运行验证。请先处理前面的错误提示，再尝试运行。';
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = wpFinished then begin
    RunAfterInstall.Visible := not WizardSilent and not LaunchFailed;
    if LaunchFailed then ShowIncompleteInstallation;
  end;
end;

function GetCustomSetupExitCode: Integer;
begin
  if LaunchFailed then Result := 20 else Result := 0;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Code: Integer;
begin
  Result := True;
  if (CurPageID = wpFinished) and not WizardSilent and not LaunchFailed and RunAfterInstall.Checked then begin
    Log('Stage: user requested desktop launch');
    if not Exec(ExpandConstant('{app}\CampusAuthenticatorFlet.exe'), '', ExpandConstant('{app}'),
        SW_SHOWNORMAL, ewNoWait, Code) then begin
      LaunchFailed := True;
      ShowIncompleteInstallation;
      Result := False;
      Log('Helper launch failed, Windows error ' + IntToStr(Code));
      MsgBox(LaunchFailureMessage(Code), mbError, MB_OK);
    end else Log('Stage: desktop process created; UI readiness is not yet confirmed');
  end;
end;

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
begin
  if CurStep = ssPostInstall then
    Log('Stage: files installed; startup configuration unchanged; helper not launched');
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
