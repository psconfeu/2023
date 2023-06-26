# https://gist.github.com/mwallner/8e62f86082db0387c8042629ddbcd089

# Windows config
Update-ExecutionPolicy RemoteSigned

Disable-GameBarTips
Disable-BingSearch
Move-LibraryDirectory "Personal" "$env:UserProfile\skydrive\documents"
Set-WindowsExplorerOptions -EnableShowFileExtensions -EnableExpandToOpenFolder
Set-TaskbarSmall
Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol
Enable-RemoteDesktop

# This will install NuGet module if missing
Get-PackageProvider -Name NuGet -ForceBootstrap

# PowerShellGet. Do this early as reboots are required
if (-not (Get-InstalledModule -Name PowerShellGet -ErrorAction SilentlyContinue)) {
    Write-Host "Install-Module PowerShellGet"
    Install-Module -Name "PowerShellGet" -AllowClobber -Force -Scope AllUsers

    # Exit equivalent
    Invoke-Reboot
}

# Write-Host "Set-PSRepository"
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

# Windows features
choco install TelnetClient -source windowsfeatures
# choco install NetFx3 -source windowsfeatures # actually skipping for the demo, this takes ages to complete

#PowerShell help
Update-Help -ErrorAction SilentlyContinue

# Software
choco install firefox
choco install FiraCode
choco install vscode

# Avoid clash with builtin function
Boxstarter.WinConfig\Install-WindowsUpdate -getUpdatesFromMS -acceptEula

Enable-UAC
