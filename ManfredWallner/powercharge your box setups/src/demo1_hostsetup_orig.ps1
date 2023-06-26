
Set-ExecutionPolicy RemoteSigned

# Disbale "Game Bar Tips"
$path = "HKCU:\SOFTWARE\Microsoft\GameBar"
if (!(Test-Path $path)) {
    New-Item $path
}
New-ItemProperty -LiteralPath $path -Name "ShowStartupPanel" -Value 0 -PropertyType "DWord" -ErrorAction SilentlyContinue
Set-ItemProperty -LiteralPath $path -Name "ShowStartupPanel" -Value 0


# Disable BingSearch
$path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'
$windows2004AndLaterPath = 'HKCU:\Software\Policies\Microsoft\Windows\Explorer'
$windows2004Version = '10.0.19041'

$osVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Version
if ([version]$osVersion -ge [version]$windows2004Version) {
    if (-not (Test-Path -Path $windows2004AndLaterPath)) {
        $null = New-Item -Path $windows2004AndLaterPath
    }

    $null = New-ItemProperty -Path $windows2004AndLaterPath -Name 'DisableSearchBoxSuggestions' -Value 1 -PropertyType 'DWORD'
}
else {
    if ( -not (Test-Path -Path $path)) {
        $null = New-Item -Path $path
    }

    $null = New-ItemProperty -Path $path -Name "BingSearchEnabled" -Value 0 -PropertyType "DWORD"
}

# move personal documents to onedrive
$libraryName = "Personal"
$newPath = "$env:UserProfile\skydrive\documents"
if ($libraryName.ToLower() -eq "downloads") { $libraryName = "{374DE290-123F-4565-9164-39C4925E467B}" }
$shells = (Get-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders')
if (-not ($shells.Property -Contains $libraryName)) {
    throw "$libraryName is not a valid Library"
}
$oldPath = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -name "$libraryName")."$libraryName"
if (-not (test-path "$newPath")) {
    New-Item $newPath -type directory
}
if ((resolve-path $oldPath).Path -eq (resolve-path $newPath).Path) { return }
Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' $libraryName $newPath
Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' $libraryName $newPath
Restart-Explorer
if (!$DoNotMoveOldContent) { Move-Item -Force $oldPath/* $newPath -ErrorAction SilentlyContinue }


# Set some Windows Explorer Options
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer'
$advancedKey = "$key\Advanced"
Set-ItemProperty $advancedKey HideFileExt 0
Set-ItemProperty $advancedKey NavPaneExpandToCurrentFolder 1

# set taskbar sizie to 'Small'
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
Set-ItemProperty -Path $key -Name TaskbarSmallIcons -Value 1

Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol

# enable remote desktop
$obj = Get-WmiObject -Class "Win32_TerminalServiceSetting" -Namespace root\cimv2\terminalservices
if ($obj -eq $null) {
    Write-BoxstarterMessage "Unable to locate terminalservices namespace. Remote Desktop is not enabled"
    return
}
try {
    $obj.SetAllowTsConnections(1, 1) | Out-Null
}
catch {
    throw "There was a problem enabling remote desktop. Make sure your operating system supports remote desktop and there is no group policy preventing you from enabling it."
}

$obj2 = Get-WmiObject -class Win32_TSGeneralSetting -Namespace root\cimv2\terminalservices -ComputerName . -Filter "TerminalName='RDP-tcp'"

if ($obj2.UserAuthenticationRequired -eq $null) {
    Write-Host "Unable to locate Remote Desktop NLA namespace. Remote Desktop NLA is not enabled"
    return
}
try {
    if ($DoNotRequireUserLevelAuthentication) {
        $obj2.SetUserAuthenticationRequired(0) | Out-Null
        Write-Host "Disabling Remote Desktop NLA ..."
    }
    else {
        $obj2.SetUserAuthenticationRequired(1) | Out-Null
        Write-Host "Enabling Remote Desktop NLA ..."
    }
}
catch {
    throw "There was a problem enabling Remote Desktop NLA. Make sure your operating system supports Remote Desktop NLA and there is no group policy preventing you from enabling it."
}


# This will install NuGet module if missing
Get-PackageProvider -Name NuGet -ForceBootstrap

if (-not (Get-InstalledModule -Name PowerShellGet -ErrorAction SilentlyContinue)) {
    Write-Host "Install-Module PowerShellGet"
    Install-Module -Name "PowerShellGet" -AllowClobber -Force -Scope AllUsers

    Restart-Computer
}

# Write-Host "Set-PSRepository"
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

# Windows features
choco install TelnetClient -source windowsfeatures
choco install NetFx3 -source windowsfeatures

#PowerShell help
Update-Help -ErrorAction SilentlyContinue

# Software
choco install firefox
choco install FiraCode
choco install vscode

Write-Host "please install all available windows updates now..."
