<#Setup
$vcCred = Get-Credential -UserName 'administrator@vsphere.local'
Connect-VIServer -Server 'flashstack-vcenter.puretec.purestorage.com' -Force -Protocol https -ErrorAction Stop -Credential $vcCred
cd T:\Code\PSHSummit23-PowerCLI-API\
#>

# PowerCLI - .NET Objects
$Stopwatch = [System.Diagnostics.Stopwatch]::new()
$Stopwatch.Start()

$VMs = Get-VM
$VMs | Get-Snapshot
$VMs | Get-HardDisk

$Stopwatch.Stop()
$Stopwatch.Elapsed.TotalSeconds

# Script - vSphere Objects (Get-View)

. ./Get-VMData.ps1

$Stopwatch = [System.Diagnostics.Stopwatch]::new()
$Stopwatch.Start()

Get-VMData

$Stopwatch.Stop()
$Stopwatch.Elapsed.TotalSeconds
