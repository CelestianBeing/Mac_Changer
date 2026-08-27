; PrivacyKit installer — Inno Setup 6
;
; Build the application first (python build.py), then compile this with
; the Inno Setup Compiler, or let build.py do both.

#define AppName      "PrivacyKit"
#define AppVersion   "2.1.0"
#define AppPublisher "Nilotpal Vyas"
#define AppExeName   "PrivacyKit.exe"
#define AppId        "{{B7E4C1A2-9D3F-4E58-A16C-2F8D5E9A7C31}"

[Setup]
AppId={#AppId}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE.txt
InfoBeforeFile=..\build_tools\preinstall.txt
OutputDir=..\dist
OutputBaseFilename={#AppName}-Setup-{#AppVersion}
SetupIconFile=privacykit.ico
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; Per-machine install: the toolkit edits HKLM and firewall rules, so it needs
; to be available to an elevated process regardless of which user installed it.
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
UninstallDisplayIcon={app}\{#AppExeName}
VersionInfoVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription=Windows privacy and anti-forensics toolkit

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; \
    GroupDescription: "Additional shortcuts:"
Name: "startupicon"; Description: "Start the &tray agent when Windows starts"; \
    GroupDescription: "Startup:"; Flags: unchecked
Name: "associatepkv"; Description: "Associate &.pkv vault files with PrivacyKit"; \
    GroupDescription: "File associations:"

[Files]
Source: "..\dist\PrivacyKit\*"; DestDir: "{app}"; \
    Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\docs\USER_MANUAL.md"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{group}\{#AppName} User Manual"; Filename: "{app}\docs\USER_MANUAL.md"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; \
    Tasks: desktopicon

[Registry]
; File association for encrypted vault files.
Root: HKA; Subkey: "Software\Classes\.pkv"; ValueType: string; \
    ValueName: ""; ValueData: "PrivacyKit.Vault"; \
    Flags: uninsdeletevalue; Tasks: associatepkv
Root: HKA; Subkey: "Software\Classes\PrivacyKit.Vault"; ValueType: string; \
    ValueName: ""; ValueData: "PrivacyKit encrypted vault"; \
    Flags: uninsdeletekey; Tasks: associatepkv
Root: HKA; Subkey: "Software\Classes\PrivacyKit.Vault\DefaultIcon"; \
    ValueType: string; ValueName: ""; ValueData: "{app}\{#AppExeName},0"; \
    Tasks: associatepkv
Root: HKA; Subkey: "Software\Classes\PrivacyKit.Vault\shell\open\command"; \
    ValueType: string; ValueName: ""; \
    ValueData: """{app}\{#AppExeName}"" ""%1"""; Tasks: associatepkv

; Startup entry for the tray agent.
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
    ValueType: string; ValueName: "PrivacyKit"; \
    ValueData: """{app}\{#AppExeName}"" --tray"; \
    Flags: uninsdeletevalue; Tasks: startupicon

[Run]
Filename: "{app}\{#AppExeName}"; \
    Description: "Launch {#AppName}"; \
    Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Leave the change journal and licence in place by default — an uninstall
; should not silently strand a machine with unreverted changes and no record
; of them. The uninstaller offers to revert first (see below).
Type: filesandordirs; Name: "{app}\docs"

[Code]
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    if MsgBox('Revert every change PrivacyKit has made to this machine before uninstalling?'#13#10#13#10
              'This restores MAC addresses, DNS servers, firewall rules, the '
              'computer name, location settings, and Windows privacy settings.'#13#10#13#10
              'Choosing No leaves those changes in place. The change journal is '
              'kept either way, so you can still revert later.',
              mbConfirmation, MB_YESNO) = IDYES then
    begin
      Exec(ExpandConstant('{app}\{#AppExeName}'), '--restore-all --silent', '',
           SW_HIDE, ewWaitUntilTerminated, ResultCode);
    end;
  end;
end;
