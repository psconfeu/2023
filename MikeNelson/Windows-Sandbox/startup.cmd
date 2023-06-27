rem install chocolately
%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "((new-object net.webclient).DownloadFile('https://community.chocolatey.org/install.ps1','%DIR%install.ps1'))"
%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& '%DIR%install.ps1' %*"

rem choco install sql-server-management-studio -y

rem scoop install MyDevPackage.json

rem install vscode portable
curl -L "https://update.code.visualstudio.com/latest/win32-x64-user/stable" --output C:\users\WDAGUtilityAccount\Desktop\vscode.exe
C:\users\WDAGUtilityAccount\Desktop\vscode.exe /verysilent /suppressmsgboxes

rem install SSMS
rem curl -L "https://aka.ms/ssmsfullsetup" --output C:\users\WDAGUtilityAccount\Desktop\ssmsfullsetup.exe
rem "C:\users\WDAGUtilityAccount\Desktop\ssmsfullsetup.exe /Install /Passive"

rem install PowerShell Preview
rem msiexec /i "c:\temp\PowerShell-7.2.0-rc.1-win-x64.msi" /q /passive

rem install Pure SDK
rem msiexec /i "c:\temp\PurePowerShellSDKInstaller_1.19.15.msi" /q /passive

rem install Pure SSMS extension
rem msiexec /i "c:\temp\PureSSMSInstaller.msi" /q /passive

rem start vscode in browser
rem start microsoft-edge:https://vscode.dev/
