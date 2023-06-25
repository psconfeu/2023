<#Setup
# ssh administrator@vsphere.local@flashstack-vcenter.puretec.purestorage.com
# $vcCred = Get-Credential -UserName 'administrator@vsphere.local'
cd T:\Code\PSHSummit23-PowerCLI-API\
#>

Connect-CisServer -Server 'flashstack-vcenter.puretec.purestorage.com' -Credential $vcCred

$shellservice = Get-CisService -Name com.vmware.appliance.access.shell
$shellservice | Get-Member
$shellservice.get()

$shellservice.get() | Format-List

$shellservice.help
$shellservice.help.set
$shellservice.help.set.config | Get-Member


$shellconfig = $shellservice.help.set.config.create()

$shellconfig.enabled = 'true'
$shellconfig.timeout = '600'

$shellservicecurrent = Get-CisService -Name com.vmware.appliance.access.shell

$shellservice.set($shellconfig)

$shellservicecurrent.get()

$shellservicecurrent.get() | Format-List
