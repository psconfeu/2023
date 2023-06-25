Connect-VIServer -Server corevcenter.lab.fullstackgeek.net

Get-Datacenter
Get-Cluster
Get-VMHost
Get-Cluster -Name Physical | Get-VMHost

Get-Cluster -Name Physical | Get-Member

Get-Command -ParameterType

Get-VM | Sort-Object -Property Name

Get-VM -Name windev01 | Select-Object -Property *
Get-VM -Name windev01 | Show-Object

Get-Help Get-VM
$windev = Get-VM windev01

$windev | Select-Object -Property Name, NumCpu, MemoryGB, UsedSpaceGB, Guest, GuestId

$windev | Select-Object -Property Name, NumCpu, MemoryGB, UsedSpaceGB, Guest, GuestId | Format-Table -AutoSize

($windev).ExtensionData
$windev.ExtensionData.Config
$windev.ExtensionData.Config.CreateDate