<#Setup
$vcCred = Get-Credential -UserName 'administrator@vsphere.local'
Connect-VIServer -Server 'flashstack-vcenter.puretec.purestorage.com' -Force -Protocol https -ErrorAction Stop -Credential $vcCred
cd T:\Code\PSHSummit23-PowerCLI-API\
#>

#Get-VM : .NET Objects
$VMs = Get-VM
$dotNetVM = $VMs | Where-Object { $_.Name -eq 'win-jump' }

$dotNetVM

$dotNetVM | Format-List -Property *

$VMs | Select-Object Name, @{n = 'Snapshot' ; `
e = { ($_.ExtensionData.Layout.Snapshot).SnapshotFile } } | `
Where-Object Snapshot


