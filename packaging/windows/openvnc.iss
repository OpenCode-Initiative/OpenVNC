; Instalador do OpenVNC para Windows (Inno Setup 6).
;   ISCC.exe /DBinDir=<pasta com os exes> /DAppVersion=0.4.3 openvnc.iss
#ifndef BinDir
  #define BinDir "..\..\target\release"
#endif
#ifndef AppVersion
  #define AppVersion "0.4.3"
#endif

[Setup]
AppId={{6F1D2C3B-8A4E-4C5D-9B7A-0E1F2A3B4C5D}
AppName=OpenVNC
AppVersion={#AppVersion}
AppPublisher=OpenCode Initiative
DefaultDirName={autopf}\OpenVNC
DefaultGroupName=OpenVNC
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputBaseFilename=OpenVNC-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=force
UninstallDisplayIcon={app}\openvnc-desktop.exe

[Languages]
Name: "ptbr"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Files]
Source: "{#BinDir}\openvnc-server.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BinDir}\openvnc.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BinDir}\openvnc-desktop.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BinDir}\openvnc-config.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "setup.ps1"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\OpenVNC Cliente"; Filename: "{app}\openvnc-desktop.exe"
Name: "{group}\OpenVNC Configuracoes"; Filename: "{app}\openvnc-config.exe"
Name: "{group}\Desinstalar OpenVNC"; Filename: "{uninstallexe}"
Name: "{autodesktop}\OpenVNC Cliente"; Filename: "{app}\openvnc-desktop.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Criar atalho na area de trabalho"; Flags: unchecked

[Run]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\setup.ps1"" -Install -Dir ""{app}"""; StatusMsg: "Configurando o servidor..."; Flags: runhidden waituntilterminated
Filename: "{app}\openvnc-config.exe"; Description: "Configurar o servidor agora (assistente)"; Flags: postinstall nowait skipifsilent

[UninstallRun]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\setup.ps1"" -Uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "OpenVNCUninstall"

[Code]
// Para o servidor antes de copiar (o .exe em uso bloquearia a atualizacao)
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  R: Integer;
begin
  Exec(ExpandConstant('{sys}\schtasks.exe'), '/End /TN "OpenVNC Server"', '', SW_HIDE, ewWaitUntilTerminated, R);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM openvnc-server.exe', '', SW_HIDE, ewWaitUntilTerminated, R);
  Result := '';
end;
