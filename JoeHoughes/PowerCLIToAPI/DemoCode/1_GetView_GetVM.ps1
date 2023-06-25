<#Setup
$vcCred = Get-Credential -UserName 'administrator@vsphere.local'
Connect-VIServer -Server 'flashstack-vcenter.puretec.purestorage.com' -Force -Protocol https -ErrorAction Stop -Credential $vcCred
cd T:\Code\PSHSummit23-PowerCLI-API\
#>

#Overhead

$Stopwatch = [System.Diagnostics.Stopwatch]::new()
$Stopwatch.Start()

$OverheadVMs = Get-VM
$OverheadVMs | Get-Snapshot | Select-Object -Property VM, Name

$Stopwatch.Stop()
$Stopwatch.Elapsed.TotalSeconds

#Fast

$Stopwatch = [System.Diagnostics.Stopwatch]::new()
$Stopwatch.Start()

$FastVMs = Get-View -ViewType VirtualMachine
$FastVMs | Select-Object -Property Name, `
@{n = 'Snapshot'; e = { $PSItem.Snapshot.RootSnapshotList[0].Name } } | `
Where-Object Snapshot

$Stopwatch.Stop()
$Stopwatch.Elapsed.TotalSeconds

