#ifndef Version
  #error Version is required
#endif
[Setup]
AppId={param:NightBuoyInstallId|NightBuoy}
AppName=NightBuoy
AppVersion={#Version}
DefaultDirName={localappdata}\Programs\NightBuoy
DefaultGroupName={param:NightBuoyInstallId|NightBuoy}
PrivilegesRequired=lowest
ArchitecturesAllowed={#TargetArch}
ArchitecturesInstallIn64BitMode={#TargetArch}
OutputDir={#Output}
OutputBaseFilename=nightbuoy-{#Version}-{#TargetArch}-setup
Compression=lzma2
SolidCompression=yes
UninstallDisplayIcon={app}\nightbuoy.exe
[Files]
Source: "{#Stage}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
[Tasks]
Name: desktopicon; Description: "Create a desktop shortcut"; Flags: unchecked
[Icons]
Name: "{group}\NightBuoy"; Filename: "{app}\nightbuoy.exe"
Name: "{autodesktop}\NightBuoy"; Filename: "{app}\nightbuoy.exe"; Tasks: desktopicon
