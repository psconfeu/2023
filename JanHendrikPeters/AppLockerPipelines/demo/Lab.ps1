param
(
    [Parameter()]
    [string]
    $LabName = 'psconfapplocker'
)
New-LabDefinition -Name $labName -DefaultVirtualizationEngine HyperV

#make the network definition
Add-LabVirtualNetworkDefinition -Name $labName -AddressSpace 192.168.111.0/24
Add-LabVirtualNetworkDefinition -Name 'Default Switch' -HyperVProperties @{ SwitchType = 'External'; AdapterName = 'Wi-Fi' }

#and the domain definition with the domain admin account
Add-LabDomainDefinition -Name contoso.com -AdminUser Install -AdminPassword Somepass1

#these credentials are used for connecting to the machines. As this is a lab we use clear-text passwords
Set-LabInstallationCredential -Username Install -Password Somepass1

# Add the reference to our necessary ISO files
Add-LabIsoImageDefinition -Name AzDevOps -Path $labSources\ISOs\mul_azure_devops_server_2022_rc2_x64_dvd_765babeb.iso #from https://docs.microsoft.com/en-us/azure/devops/server/download/azuredevopsserver?view=azure-devops
Add-LabIsoImageDefinition -Name SQLServer2019 -Path $labsources\ISOs\en_sql_server_2019_enterprise_x64_dvd_5e1ecc6b.iso #from https://www.microsoft.com/en-us/evalcenter/evaluate-sql-server-2019. The EXE downloads the ISO.

#defining default parameter values, as these ones are the same for all the machines
$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:Network'         = $labName
    'Add-LabMachineDefinition:ToolsPath'       = "$labSources\Tools"
    'Add-LabMachineDefinition:DomainName'      = 'contoso.com'
    'Add-LabMachineDefinition:DnsServer1'      = '192.168.111.10'
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2022 Datacenter (Desktop Experience)'
    'Add-LabMachineDefinition:Gateway'         = '192.168.111.50'
}

#The PostInstallationActivity is just creating some users
$postInstallActivity = @()
$postInstallActivity += Get-LabInstallationActivity -ScriptFileName 'New-ADLabAccounts 2.0.ps1' -DependencyFolder $labSources\PostInstallationActivities\PrepareFirstChildDomain
$postInstallActivity += Get-LabInstallationActivity -ScriptFileName PrepareRootDomain.ps1 -DependencyFolder $labSources\PostInstallationActivities\PrepareRootDomain
Add-LabMachineDefinition -Name PSCONFDC01 -Memory 1GB -Roles RootDC -IpAddress 192.168.111.10 -PostInstallationActivity $postInstallActivity

#file server and router
$netAdapter = @()
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $labName -Ipv4Address 192.168.111.50
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp

# SQL and PKI
$null = New-Item -ItemType Directory -Path (Join-Path -Path $env:TEMP -ChildPath AppLockerLab) -Force -ErrorAction SilentlyContinue
@"
Install-WindowsFeature RSAT-AD-Tools
New-ADOrganizationalUnit -Name Test
New-ADOrganizationalUnit -Name Prod
"@ | Set-Content -Path (Join-Path -Path $env:TEMP -ChildPath AppLockerLab\PreInstall.ps1) -Force
$act = Get-LabInstallationActivity -ScriptFileName PreInstall.ps1 -DependencyFolder (Join-Path -Path $env:TEMP -ChildPath AppLockerLab)
Add-LabMachineDefinition -Name PSCONFCA01 -Memory 3GB -Roles CaRoot, SQLServer2019, Routing -NetworkAdapter $netAdapter -PreInstallationActivity $act

# Build Server
Add-LabMachineDefinition -Name PSCONFDO01 -Memory 4GB -Roles AzDevOps, (Get-LabMachineRoleDefinition -Role TfsBuildWorker -Properties @{
    NumberOfBuildWorkers = '2'
}) -IpAddress 192.168.111.70

# AppLocker target nodes
# Servers in Prod
Add-LabMachineDefinition -Name PSCONFFile01 -Memory 1GB -Roles FileServer -IpAddress 192.168.111.100 -OrganizationalUnit "OU=Prod,dc=contoso,dc=com"
Add-LabMachineDefinition -Name PSCONFWeb01 -Memory 1GB -Roles WebServer -IpAddress 192.168.111.101 -OrganizationalUnit "OU=Prod,dc=contoso,dc=com"

# Servers in Test
Add-LabMachineDefinition -Name PSCONFFile02 -Memory 1GB -Roles FileServer -IpAddress 192.168.111.110 -OrganizationalUnit "OU=Test,dc=contoso,dc=com"
Add-LabMachineDefinition -Name PSCONFWeb02 -Memory 1GB -Roles WebServer -IpAddress 192.168.111.111 -OrganizationalUnit "OU=Test,dc=contoso,dc=com"

Install-Lab

Enable-LabCertificateAutoenrollment -Computer -User
Install-LabWindowsFeature -ComputerName (Get-LabVM -Role AzDevOps) -FeatureName RSAT-AD-Tools
Invoke-LabCommand -ActivityName 'Disable Windows Update Service and DisableRealtimeMonitoring' -ComputerName (Get-LabVM) -ScriptBlock {
    Stop-Service -Name wuauserv
    Set-Service -Name wuauserv -StartupType Disabled
    Set-MpPreference -DisableRealtimeMonitoring $true
}

Send-ModuleToPsSession -Session (New-LabPSSession -ComputerName PSCONFDO01) -Module (Get-Module -ListAvailable PSModuleDevelopment)[0] -IncludeDependencies

Invoke-LabCommand -ComputerName PSCONFDO01 -ScriptBlock {
    Get-PackageProvider -Name nuget -ForceBootstrap
    Install-Module -Name Chocolatey -Force -Repository PSGallery -Scope AllUsers
    Install-ChocolateySoftware
    choco install git /y
    choco install vscode /y
    choco install vscode-powershell /y
    Install-Module -Name PackageManagement, PowerShellGet -Force -Repository PSGallery -Scope AllUsers
    [Environment]::SetEnvironmentVariable('PATH', ("C:\Program Files\Microsoft VS Code\bin;$Path"), 'Machine')
}

Remove-LabPSSession

Invoke-LabCommand -ComputerName PSCONFDO01 -ScriptBlock {
    git config --global http.sslBackend schannel
    git config --global user.name Install
    git config --global user.email Install@contoso.com
}

Install-LabSoftwarePackage -Path $labSources\SoftwarePackages\7z2300-x64.msi -ComputerName PSCONFDO01

$param = Get-LabTfsParameter -ComputerName PSCONFDO01
New-TfsProject @param -ProjectName 'AppLocker' -ProjectDescription 'AppLocker Build Automation' -SourceControlType Git -TemplateName Basic

Write-Host "1. - Creating Snapshot 'AfterInstall'" -ForegroundColor Magenta
Checkpoint-LabVM -All -SnapshotName AfterInstall
#endregion

Show-LabDeploymentSummary -Detailed
