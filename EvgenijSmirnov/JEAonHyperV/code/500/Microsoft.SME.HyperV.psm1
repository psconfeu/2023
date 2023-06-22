<#
    HOW TO IMPLEMENT THIS:
    
    - remove signature from PSM1
    - insert the *-RBACVM functions into module (in this example only Get is implemented)
    - Search vor "Get-VM " and replace by "Get-RBACVM " (space is important!)
    - Proceed for all the other RBACVM functions you inserted earlier
    - Resign with own Code Signing cert if needed --> WAC does not need it if ExecutionPolicy allows running unsigned local

    DO NOT RUN THE WAC RBAC DEPLOYMENT ASSISTANT!
    - Create your own role capability
    - Install Microsoft.SME.* and Microsoft.SND.* modules into a path where they will be found
    - don't forget the JEA module holding the role capabilities!
    - Register the endpoint
#>


function Get-RBACVM {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Id
    )
    $authzFilePath = Join-Path -Path $PSScriptRoot -ChildPath 'AuthZ.csv'
    if (-not (Test-Path $authzFilePath -PathType Leaf)) {
        return
    }
    try {
        $authZtable = Import-Csv -Path $authzFilePath -Delimiter ";" -EA Stop
    } catch {
        return
    }
    $allSIDs = $PSSenderInfo.UserInfo.WindowsIdentity.Groups.Value
    $myAuthZItems = $authZtable.Where({$_.SID -in $allSIDs})
    if ($myAuthZItems.Count -gt 0) {
        $myVMNames = $myAuthZItems.VMName
    }
    if ([string]::IsNullOrWhiteSpace($id)) {
        $hvVM = Hyper-V\Get-VM -EA SilentlyContinue
    } else {
        $hvVM = Hyper-V\Get-VM -Id $Id -EA SilentlyContinue
    }
    foreach ($vm in $hvVM) {
        if ($vm.Name -in $myVMNames) {
            $vm
        }
    }
}

function Add-WACVMClusterVirtualMachineRole {
<#

.SYNOPSIS
Configure high availability for VM(s)

.DESCRIPTION
Adds high availability for VM(s) on the server that belongs to a cluster.

.ROLE
Hyper-V-Administrators

.PARAMETER vmIds
    The Ids of the requested virtual machine.

#>

param (
    [Parameter(Mandatory = $true)]
    [String []]
    $vmIds
)


Set-StrictMode -Version 5.0

Import-Module CimCmdlets -ErrorAction SilentlyContinue
Import-Module FailoverClusters -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScript" -Scope Script
Set-Variable -Name ScriptName -Option ReadOnly -Value "Add-ClusterVirtualMachineRole.ps1" -Scope Script


$module = Get-Module -Name FailoverClusters -ErrorAction SilentlyContinue
if (!!$module) {
    foreach ($vmId in $vmIds) {
        Add-ClusterVirtualMachineRole -VMId $vmId -ErrorAction SilentlyContinue -ErrorVariable +err | Out-Null
        if (!!$err) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: $err" -ErrorAction SilentlyContinue
    
            Write-Error @($err)[0]
            return @()
        }
    }
}
else {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: The required PowerShell module (FailoverClusters) was not found. Cannot configure high availablility." -ErrorAction SilentlyContinue

    Write-Error $strings.FailoverClustersModuleRequired
}

}
## [END] Add-WACVMClusterVirtualMachineRole ##
function Checkpoint-WACVMRestoreVirtualMachineCheckpoint {
<#

.SYNOPSIS
Takes a new checkpoint (snapshot) of the passed in virtual machine before applying (retoring) a checkpoint (snapshot)

.DESCRIPTION
Takes a new snapshot of the passed in virtual machine, and optionally names the new snapshot to the
passed in name.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER vmId
    The Id of the requested virtual machine.

.PARAMETER snapshotId
    The Id of the virtual machine checkpoint (snapshot) to apply (restore).

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $vmId,
    [Parameter(Mandatory = $true)]
    [String]
    $snapshotId
)

Set-StrictMode -Version 5.0;
Import-Module Hyper-V;

$vm = Get-RBACVM -id $vmId

$originalState = $vm.State

if ($originalState -ne "Off" -and $originalState -ne "Saved")
{
	$vm | Stop-Vm -Save
}

$vm | checkpoint-vm
get-vmsnapshot -Id $snapshotId | restore-VMSnapshot -Confirm:$false

if ($originalState -eq "Running")
{
	$vm | Start-VM
}

}
## [END] Checkpoint-WACVMRestoreVirtualMachineCheckpoint ##
function Checkpoint-WACVMVirtualMachine {
<#

.SYNOPSIS
Takes a new checkpoint (snapshot) of the passed in virtual machine.

.DESCRIPTION
Takes a new checkpoint (snapshot) of the passed in virtual machine, and optionally names the new snapshot to the
passed in name.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER vmId
    The Id of the requested virtual machine.

.PARAMETER checkpointName
    The optional name to give the new virtual machine checkpoint.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $vmId,
    [Parameter(Mandatory = $false)]
    [String]
    $checkpointName
)  

Set-StrictMode -Version 5.0;
Import-Module Hyper-V;

if ($checkpointName) {
    Get-RBACVM -id $vmId | checkpoint-vm -SnapshotName $checkpointName
} else {
    Get-RBACVM -id $vmId | checkpoint-vm
}

}
## [END] Checkpoint-WACVMVirtualMachine ##
function Export-WACVMVirtualMachine {
<#

.SYNOPSIS
Export a virtual machine.

.DESCRIPTION
Export the passed in virtual machine on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016, Windows Server 2019.

.ROLE
Hyper-V-Administrators

.PARAMETER vmId
    The id of the requested virtual machine.

.PARAMETER exportPath
    The path where the virtual machine should be exported to.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $vmId,
    [Parameter(Mandatory = $true)]
    [String]
    $exportPath
)

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Setup script runtime environment.

.DESCRIPTION
Setup script runtime environment.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScript" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Export-VirtualMachine.ps1" -Scope Script
}

<#

.SYNOPSIS
Cleanup script runtime environment.

.DESCRIPTION
Cleanup script runtime environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
}

<#

.SYNOPSIS
The main function.

.DESCRIPTION
Export the passed in virtual machine on this server.

.PARAMETER vmId
    The id of the requested virtual machine.

.PARAMETER exportPath
    The path where the virtual machine should be exported to.

#>

function main([string]$vmId, [string]$exportPath) {
    $err = $null
    $vm = Get-RBACVM -Id $vmId -ErrorAction SilentlyContinue -ErrorVariable +err
    
    if ($err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Couldn't retrieve the virtual machine. Error: $err"  -ErrorAction SilentlyContinue

        Write-Error @($err)[0]
        return @()
    }
    if ($vm) {
        $err = $null
        $vm | Export-VM -Path $exportPath -ErrorAction SilentlyContinue -ErrorVariable +err

        if ($err) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: Couldn't export the virtual machine. Error: $err"  -ErrorAction SilentlyContinue
    
            Write-Error @($err)[0]
            return @()
        }
    }
}


###############################################################################
# Script execution starts here
###############################################################################
setupScriptEnv

try {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    $module = Get-Module -Name Hyper-V -ErrorAction SilentlyContinue -ErrorVariable +err
    if ($module) {
        return main $vmId $exportPath
    }

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: The required PowerShell module (Hyper-V) was not found."  -ErrorAction SilentlyContinue

    Write-Error @($err)[0]

    return @()
} finally {
    cleanupScriptEnv
}

}
## [END] Export-WACVMVirtualMachine ##
function Get-WACVMASRServiceProperties {
<#

.SYNOPSIS
Gets ASR service properties

.DESCRIPTION
Get the ASR service properties installed on the node.
The supported Operating Systems are Windows Server 2012R2 and Windows Server 2016.

.ROLE
Readers

#>


Set-Variable -Name 'AsrKey' -Option Constant -Value 'HKLM:\SOFTWARE\Microsoft\Azure Site Recovery\Registration' -ErrorAction SilentlyContinue
Set-Variable -Name 'VaultLocationKey' -Option Constant -Value 'VaultLocation' -ErrorAction SilentlyContinue
Set-Variable -Name 'SubscriptionIdKey' -Option Constant -Value 'SubscriptionId' -ErrorAction SilentlyContinue
Set-Variable -Name 'ResourceNameKey' -Option Constant -Value 'ResourceName' -ErrorAction SilentlyContinue
Set-Variable -Name 'ResourceGroupNameKey' -Option Constant -Value 'ResourceGroupName' -ErrorAction SilentlyContinue
Set-Variable -Name 'FabricNameKey' -Option Constant -Value 'SiteName' -ErrorAction SilentlyContinue
Set-Variable -Name 'ContainerIdKey' -Option Constant -Value 'ContainerId' -ErrorAction SilentlyContinue


<#

.SYNOPSIS
    Gets ASR registy value for the given key

.DESCRIPTION
    Looks up a key in the ASR registry path and if it exists, return the value.

.Parameter key
    They key to check
#>

function Get-ASRKeyValue([string] $key) {
    $KeyValue = $null
    $Exists = Get-ItemProperty -Path $AsrKey -Name $key -ErrorAction SilentlyContinue
    if ($Exists)
    {
        $KeyValue = $Exists | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty $key
    }

    return $KeyValue
}

function isAsrServiceRunning($VaultLocationValue, $SubscriptionIdValue, $ResourceNameValue, $ResourceGroupNameValue) {
    $AsrServiceRunning = $false

    if ($VaultLocationValue -and $SubscriptionIdValue -and $ResourceNameValue -and $ResourceGroupNameValue)
    {
        $ServiceName = 'dra'
        $AsrService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

        if ($AsrService)
        {
            $AsrServiceRunning = $AsrService.Status -eq 'Running'
        }
    }

    return $AsrServiceRunning
}

function main() {
    $VaultLocationValue = Get-ASRKeyValue($VaultLocationKey)
    $SubscriptionIdValue = Get-ASRKeyValue($SubscriptionIdKey)
    $ResourceNameValue = Get-ASRKeyValue($resourceNameKey)
    $ResourceGroupNameValue = Get-ASRKeyValue($ResourceGroupNameKey)
    $FabricNameValue = Get-ASRKeyValue($FabricNameKey)
    $ContainerIdValue = Get-ASRKeyValue($ContainerIdKey)

    $AsrServiceRunning = isAsrServiceRunning $VaultLocationValue $SubscriptionIdValue $ResourceNameValue $ResourceGroupNameValue

    $Result = New-Object PSObject

    Add-Member -InputObject $Result -MemberType NoteProperty -Name "SubscriptionId" -Value $SubscriptionIdValue
    Add-Member -InputObject $Result -MemberType NoteProperty -Name "VaultName" -Value $ResourceNameValue
    Add-Member -InputObject $Result -MemberType NoteProperty -Name "VaultResourceGroup" -Value $ResourceGroupNameValue
    Add-Member -InputObject $Result -MemberType NoteProperty -Name "VaultLocation" -Value $VaultLocationValue
    Add-Member -InputObject $Result -MemberType NoteProperty -Name "FabricName" -Value $FabricNameValue
    Add-Member -InputObject $Result -MemberType NoteProperty -Name "ContainerId" -Value $ContainerIdValue
    Add-Member -InputObject $Result -MemberType NoteProperty -Name "ServiceRunning" -Value $AsrServiceRunning

    return $Result
}

if (-not ($env:pester)) {
    return main
}

return $null
}
## [END] Get-WACVMASRServiceProperties ##
function Get-WACVMAccessControlLists {
<#

.SYNOPSIS
Gets the  Access Control Lists.

.DESCRIPTION
Gets the Access Control Lists objects from the SDN Network Controller.

.ROLE
Readers

.PARAMETER uri
    The uri used to connect to the SDN Network controller
    
#>

param (
		[Parameter(Mandatory = $true)]
		[String]
        $uri
)

Set-StrictMode -Version 5.0;
Import-Module NetworkController;
Import-Module Microsoft.PowerShell.Management;

$acls = @(Get-NetworkControllerAccessControlList -ConnectionUri $uri)
$acls | ConvertTo-Json -depth 100 | ConvertFrom-Json
}
## [END] Get-WACVMAccessControlLists ##
function Get-WACVMAffinityRules {
<#

.SYNOPSIS
Gets a cluster's affinity rules

.DESCRIPTION
Gets a cluster's affinity rules

.ROLE
Readers

#>


param (
  [Parameter(Mandatory = $false)]
  [String]
  $vmName
)
Set-StrictMode -Version 5.0

if ($vmName) {
  $rules = Get-ClusterAffinityRule | Microsoft.PowerShell.Core\Where-Object { $_.Groups -like $vmName }
}
else {
  $rules = Get-ClusterAffinityRule
}

$rules | ForEach-Object {
  $groups = [System.Collections.ArrayList]@()
  $_.Groups | ForEach-Object {

    $resourceObject = Get-ClusterGroup $_ | Where-Object { $_.GroupType -eq "ClusterSharedVolume" } | Get-ClusterResource
    if ($resourceObject) {
      $groups.Add($resourceObject.Name) | Out-Null
    }
    else {
      $groups.Add($_) | Out-Null
    }

  }
  $_ | Add-Member -MemberType NoteProperty -Name "DisplayGroups" -Value $groups
}
$rules

}
## [END] Get-WACVMAffinityRules ##
function Get-WACVMAvailableVirtualMachines {
<#

.SYNOPSIS
Get available virtual machines

.DESCRIPTION
Get all available virtual machines in the path provided
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER importPath
The path containing the virtual machines to import.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $importPath
)

Set-StrictMode -Version 5.0
Import-Module Microsoft.PowerShell.Management -ErrorAction SilentlyContinue
Import-Module Hyper-V -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Setup script runtime environment.

.DESCRIPTION
Setup script runtime environment.

#>

function setupScriptEnv() {
  Set-Variable -Name ClassName -Option ReadOnly -Value "Msvm_VirtualSystemManagementService" -Scope Script
  Set-Variable -Name Namespace -Option ReadOnly -Value "root\virtualization\v2" -Scope Script
  Set-Variable -Name VmcxFilter -Option ReadOnly -Value "*.vmcx" -Scope Script
  Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
  Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScript" -Scope Script
  Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-AvailableVirtualMachines.ps1" -Scope Script
}

<#

.SYNOPSIS
Cleanup script runtime environment.

.DESCRIPTION
Cleanup script runtime environment.

#>

function cleanupScriptEnv() {
  Remove-Variable -Name ClassName -Scope Script -Force
  Remove-Variable -Name Namespace -Scope Script -Force
  Remove-Variable -Name VmcxFilter -Scope Script -Force
  Remove-Variable -Name LogName -Scope Script -Force
  Remove-Variable -Name LogSource -Scope Script -Force
  Remove-Variable -Name ScriptName -Scope Script -Force
}


<#

.SYNOPSIS
The main function.

.DESCRIPTION
Export the passed in virtual machine on this server.

.PARAMETER importPath
The path containing the virtual machines to import.

#>

function main([string]$importPath) {

  $err = $null
  $vmPath = '{0}\Virtual Machines' -f $importPath

  if($vmPath | Test-Path) {
    $vmcxFiles = $vmPath | Get-ChildItem -Filter $VmcxFilter -ErrorAction SilentlyContinue -ErrorVariable +err

    if ($err) {
      Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
          -Message "[$ScriptName]: Couldn't get the child items. Error: $err"  -ErrorAction SilentlyContinue

      Write-Error @($err)[0]
      return @()
    }

    if ($vmcxFiles) {
      $definitionFiles = getFileNames($vmcxFiles)

      if (-not $definitionFiles -or $definitionFiles.Count -eq 0) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Couldn't get the summary information . Error: $err"  -ErrorAction SilentlyContinue

        Write-Error @("No configuration files found")
        return @()
      }

      $instance = Get-CimInstance -Namespace $Namespace -ClassName $ClassName -ErrorAction SilentlyContinue -ErrorVariable +err

      if ($err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Couldn't get the CimInstance . Error: $err"  -ErrorAction SilentlyContinue
  
        Write-Error @($err)[0]
        return @()
      }

      $result = $instance | Invoke-CimMethod -MethodName GetDefinitionFileSummaryInformation -Arguments @{ DefinitionFiles = $definitionFiles } `
                -ErrorAction SilentlyContinue -ErrorVariable +err

      if ($err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Couldn't get the summary information . Error: $err"  -ErrorAction SilentlyContinue
  
        Write-Error @($err)[0]
        return @()
      }

      $availableVms = getVmNames($result.SummaryInformation)

      if ($availableVms.Count -eq 0) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Couldn't find any virtual machines in the specified path."  -ErrorAction SilentlyContinue
  
        Write-Error @("No virtual machines found")
        return @()
      }

      return $availableVms
    } else {
      Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Couldn't find any virtual machine configuration files in the specified path."  -ErrorAction SilentlyContinue
  
      Write-Error @("No configuration files found")
      return @()
    }
  } else {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Invalid path"  -ErrorAction SilentlyContinue
  
    Write-Error @("Invalid path")
    return @()
  }

}

<#

.SYNOPSIS
The function to extract virtual machine names from summary information

.DESCRIPTION
Extracts the available virtual machines from the summary information object
Returns an array of the name and elementName of the extracted virtual machines

.PARAMETER summaryInfo
The SummaryInformation array returned after invoking the CimMethod

#>

function getVmNames([Object[]]$summaryInfo) {
  $vmNames =  New-Object System.Collections.Generic.List[System.Object]

  foreach ($info in $summaryInfo) {
    $vmNames.Add(@{'name'= $info.name; 'elementName' = $info.ElementName})
  }
  
  return $vmNames
}

<#

.SYNOPSIS
The function to retrieve configuration files inside an import path

.DESCRIPTION
Retrieves all the virtual machine configuration file names in a given import path

.PARAMETER vmcxFiles
A list of file objects inside the import path

#>

function getFileNames([Object[]]$vmcxFiles) {
  $fileNames = New-Object System.Collections.Generic.List[System.Object]
  foreach ($vmcxFile in $vmcxFiles) {
    $fileNames.Add($vmcxFile.fullName)
  }

  return ,$fileNames;
}


###############################################################################
# Script execution starts here
###############################################################################
setupScriptEnv

try {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    $module = Get-Module -Name Hyper-V -ErrorAction SilentlyContinue -ErrorVariable +err
    if ($module) {
      return main $importPath
    }

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: The required PowerShell module (Hyper-V) was not found."  -ErrorAction SilentlyContinue

    Write-Error @($err)[0]

    return @()
} finally {
    cleanupScriptEnv
}
}
## [END] Get-WACVMAvailableVirtualMachines ##
function Get-WACVMBritannicaStatus {
<#

.SYNOPSIS
Determines if Britannica (sddc management resources) are available on the cluster

.DESCRIPTION

Use the existance of the cim namespace root/sddc/Management and class name to determine if Britannica
is supported or not.

.ROLE
Readers

#>

return !!(Get-CimInstance -Namespace "root\SDDC\Management" -ClassName SDDC_VirtualMachine -ErrorAction SilentlyContinue)
}
## [END] Get-WACVMBritannicaStatus ##
function Get-WACVMCPUUsage {
<#

.SYNOPSIS
Gets a computer's CPU usage perf counter data.

.DESCRIPTION
Gets a computer's CPU usage perf counter data.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0
import-module CimCmdlets;

$idlePercent = Get-CimInstance -ClassName Win32_PerfFormattedData_HvStats_HyperVHypervisorLogicalProcessor -Property PercentIdleTime | Where-Object {$_.Name -eq '_Total'}
if ($idlePercent -and $idlePercent.PercentIdleTime) {
  $overallUsage = 100 - $idlePercent.PercentIdleTime

  $overallUsage
}

}
## [END] Get-WACVMCPUUsage ##
function Get-WACVMClusterAlerts {
<#

.SYNOPSIS
Gets all the cluster/Node/VM related alerts from Cluster Health Service.

.DESCRIPTION
Gets all the cluster/Node/VM related alerts from Cluster Health Service.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0
Import-Module CimCmdlets -ErrorAction SilentlyContinue
Import-Module FailoverClusters -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

###############################################################################
# Constants
###############################################################################

Set-Variable -Name LogName -Option Constant -Value "Microsoft-ServerManagementExperience" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SMEScripts" -ErrorAction SilentlyContinue
Set-Variable -Name ScriptName -Option Constant -Value "Get-ClusterAlerts.ps1" -ErrorAction SilentlyContinue
Set-Variable -Name FaultTypeVirtualMachine -Option Constant -Value "Microsoft.Health.EntityType.VM" -ErrorAction SilentlyContinue
Set-Variable -Name FaultTypeServer -Option Constant -Value "Microsoft.Health.EntityType.Server" -ErrorAction SilentlyContinue
Set-Variable -Name FaultTypeCluster -Option Constant -Value "Microsoft.Health.EntityType.Cluster" -ErrorAction SilentlyContinue
Set-Variable -Name VmResourceNamePattern -Option Constant -Value "Virtual Machine " -ErrorAction SilentlyContinue
##SkipCheck=true##
Set-Variable -Name ClusterResourceToVmIdQuery -Option Constant -Value "select Name, OwnerNode, PrivateProperties from mscluster_resource where type='virtual machine' and PrivateProperties.VmId='{0}'" -ErrorAction SilentlyContinue
##SkipCheck=false##

<#

.SYNOPSIS
Determines if Britannica virtual machine suppirt is available on this cluster

.DESCRIPTION
Use the existance of the cim namespace root/sddc to determine if Britannica
virtual machine supported is present or not.

#>

function isBritannicaVmSupportEnabled() {
    return !!(Get-CimInstance -Namespace "root\SDDC\Management" -ClassName SDDC_VirtualMachine -ErrorAction SilentlyContinue)
}

<#

.SYNOPSIS
Get the VM using the Britannica interface.

.DESCRIPTION
Use the Britannica virtual machine interface to get the VM info.  This is preferred
since no double hop is needed.
#>

function getVmFromBritannica([string]$vmId) {
    $vm = Get-CimInstance -Namespace "root\SDDC\Management" -ClassName SDDC_VirtualMachine | Where-Object { $_.Id -ieq $vmId }

    return $vm
}

<#

.SYNOPSIS
Get the VM name from the cluster.

.DESCRIPTION
Use all available mechanisms to get the VM name from the cluster, in order of preference.
#>

function getVmNameFromCluster([string]$vmId) {
    if (isBritannicaVmSupportEnabled) {
        $vm = getVmFromBritannica $vmId

        if (!!$vm) {
            return $vm.Name
        }
    } else {
        return getVmResourceNameFromCluster $vmId
    }

    return $null
}

<#

.SYNOPSIS
Get the best name possible of the VM from the cluster.

.DESCRIPTION
Since we cannot go to the host node of the VM we must get the best name we
can from the cluster, and this means using the VM resource name.

#>

function getVmResourceNameFromCluster([string]$vmId) {
    $queryString = $ClusterResourceToVmIdQuery -f $vmId
    $clusterResource = Get-CimInstance -Namespace Root\MSCluster -Query $queryString -ErrorAction SilentlyContinue

    if (!!$clusterResource) {
        return $clusterResource.Name.SubString($VmResourceNamePattern.length)
    }

    return $null
}

<#

.SYNOPSIS
Get the name of the virtual machine.

.DESCRIPTION
The Id of the virtual machine is part of the description.

#>

function getVmName([string] $objectType, [string] $alertDescription) {
    if ($objectType -eq $FaultTypeVirtualMachine) {
        $parts = $alertDescription.split(' ')

        # Did we get the VMId?
        if ($parts.length -eq 4) {
            $vmId = $parts[3]

            # If the VM is on this host then simply get the name...
            $vm = Get-RBACVM -Id $vmId -ErrorAction SilentlyContinue

            if (!!$vm) {
                return $vm.Name
            }

            return getVmNameFromCluster $vmId
        }
    }

    return $null
}

<#

.SYNOPSIS
Get the name of the cluster node hosting this VM.

.DESCRIPTION
The FQDN of the server host.

#>

function getHostServerName([string] $objectType, [string] $alertDescription) {
    if ($objectType -eq $FaultTypeVirtualMachine) {
        $parts = $alertDescription.split(' ')

        # Did we get the VMId?
        if ($parts.length -eq 4) {
            $vmId = $parts[3]
            $queryString = $ClusterResourceToVmIdQuery -f $vmId
            $clusterResource = Get-CimInstance -Namespace Root\MSCluster -Query $queryString -ErrorAction SilentlyContinue

            if (!!$clusterResource) {
                return [System.Net.DNS]::GetHostByName($clusterResource.ownerNode).HostName
            }
        }
    }

    return $null
}

<#

.SYNOPSIS
The main function of this script.

.DESCRIPTION
Get the health alerts for this cluster.

#>

function main() {
    $cluster = Get-Cluster -ErrorAction SilentlyContinue
    $faults = @()

    if ($cluster -and ($cluster.S2DEnabled -gt 0)) {
        $faults = Get-HealthFault | `
        Where-Object { $_.FaultingObjectType -eq $FaultTypeCluster -or $_.FaultingObjectType -eq $FaultTypeServer -or $_.FaultingObjectType -eq $FaultTypeVirtualMachine } | `
        Microsoft.PowerShell.Utility\Select-Object PerceivedSeverity, `
        FaultingObjectDescription, `
        FaultingObjectLocation, `
        FaultingObjectType, `
        FaultingObjectUniqueId, `
        FaultTime, `
        FaultType, `
        Reason, `
        RecommendedActions, `
        @{N='virtualMachineName';E={getVmName $_.FaultingObjectType $_.FaultingObjectDescription}},
        @{N='hostServerFqdn';E={getHostServerName $_.FaultingObjectType $_.FaultingObjectDescription}}
    }

    return $faults
}

###############################################################################
# Script execution starts here.
###############################################################################

if (-not($env:pester)) {
  $module = Get-Module -Name FailoverClusters -ErrorAction SilentlyContinue
  if ($module) {
      return main
  }

  Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue
  Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
      -Message "[$ScriptName]: The required PowerShell module (FailoverClusters) was not found."  -ErrorAction SilentlyContinue

  Write-Error $strings.FailoverClustersModuleRequired

  return @()
}

}
## [END] Get-WACVMClusterAlerts ##
function Get-WACVMClusterFeaturesSupported {
 <#

.SYNOPSIS
Checks if the machine has storage spaces direct and time series database.

.DESCRIPTION
checks if the machine has storage spaces direct and time series database.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0
Import-Module CimCmdlets -ErrorAction SilentlyContinue
Import-Module Microsoft.PowerShell.Management -ErrorAction SilentlyContinue
Import-Module Storage -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

###############################################################################
# Constants
###############################################################################

Set-Variable -Name LogName -Option Constant -Value "Microsoft-ServerManagementExperience" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SMEScripts" -ErrorAction SilentlyContinue
Set-Variable -Name ScriptName -Option Constant -Value "Get-ClusterFeaturesSupported.ps1" -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Get the MSCluster Cluster CIM instance from this server.

.DESCRIPTION
Get the MSCluster Cluster CIM instance from this server.

#>
function getClusterCimInstance() {
    $namespace = Get-CimInstance -Namespace root/MSCluster -ClassName __NAMESPACE -ErrorAction SilentlyContinue
    if ($namespace) {
        return Get-CimInstance -Namespace root/mscluster MSCluster_Cluster -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object S2DEnabled
    }

    return $null
}

<#

.SYNOPSIS
Determines if the current cluster supports Failover Clusters Time Series Database.

.DESCRIPTION
Use the existance of the path value of cmdlet Get-StorageHealthSetting to determine if TSDB 
is supported or not.

#>
function getClusterPerformanceHistoryPath() {
    return (Get-StorageSubSystem clus* | Get-StorageHealthSetting -Name "System.PerformanceHistory.Path") -ne $null
}

<#

.SYNOPSIS
Get some basic information about the cluster from the cluster.

.DESCRIPTION
Get the needed cluster properties from the cluster.

#>
function getClusterFeatureInfo() {
    $result = New-Object PSObject

    $cluster = getClusterCimInstance
    
    $isS2dEnabled = $false
    if ($cluster) {
        $isS2dEnabled = !!(Get-Member -InputObject $cluster -Name "S2DEnabled") -and ($cluster.S2DEnabled -eq 1)
    }
    
    $isTsdbEnabled = getClusterPerformanceHistoryPath
    
    $result | Add-Member -MemberType NoteProperty -Name 'IsS2dEnabled' -Value $isS2dEnabled
    $result | Add-Member -MemberType NoteProperty -Name 'IsTsdbEnabled' -Value $isTsdbEnabled
    
    return $result
}

###############################################################################
# main
###############################################################################
$module = Get-Module -Name Storage -ErrorAction SilentlyContinue
if ($module) {
    return getClusterFeatureInfo
}

Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue
Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
    -Message "[$ScriptName]: The required PowerShell module (FailoverClusters) was not found." -ErrorAction SilentlyContinue

Write-Error $strings.FailoverClustersModuleRequired

return $null
}
## [END] Get-WACVMClusterFeaturesSupported ##
function Get-WACVMClusterNodeClusterStatus {
<#

.SYNOPSIS
Is this server a running cluster node?

.DESCRIPTION
Returns true when the server is a running cluster node.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0;

$service = Microsoft.PowerShell.Management\Get-Service -Name "CLUSSVC" -ErrorAction SilentlyContinue;

 # enum System.ServiceProcess.ServiceControllerStatus = {
 #      Stopped = 0x00000001
 #      StartPending = 0x00000002
 #      StopPending =0 x00000003
 #      Running = 0x00000004
 #      ContinuePending = 0x00000005
 #      PausePending = 0x00000006
 #      Paused = 0x00000007
 #  }

 # Is the cluster service present, and is it running?
 return ($service -and $service.Name -eq "CLUSSVC" -and $service.status -eq 4);
}
## [END] Get-WACVMClusterNodeClusterStatus ##
function Get-WACVMClusterNodeState {
<#

.SYNOPSIS
Get the current state of the nodes in the cluster.

.DESCRIPTION
Get the current state of the nodes in the cluster from this server (node).
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0

Import-Module FailoverClusters -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.  Create read only (constant) variables
that add context to the said constants.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-ClusterNodeState.ps1" -Scope Script
    Set-Variable -Name NamePropertyName -Option ReadOnly -Value "Name" -Scope Script
    Set-Variable -Name FQDNPropertyName -Option ReadOnly -Value "FQDN" -Scope Script
}

<#

.SYNOPSIS
Cleanup the script environment.

.DESCRIPTION
Cleanup the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name NamePropertyName -Scope Script -Force
    Remove-Variable -Name FQDNPropertyName -Scope Script -Force
}

<#

.SYNOPSIS
Get the fully qualified domain name for the passed in server name from DNS.

.DESCRIPTION
Get the fully qualified domain name for the passed in server name from DNS.

#>

function getServerFqdn([string]$netBIOSName) {
    try {
        return ([System.Net.DNS]::GetHostByName($netBIOSName).HostName)
    } catch {
        $errMessage = $_.Exception.Message

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: There was an error looking up the FQDN for server $netBIOSName.  Error: $errMessage"  -ErrorAction SilentlyContinue

        return $netBIOSName
    }
}

<#

.SYNOPSIS
Main

.DESCRIPTION
Get the list of cluster nodes and their states...

.PARAMETER parameters

#>

function main() {
    $cluster = Get-Cluster -ErrorAction SilentlyContinue -ErrorVariable +err

    if ($err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: There was an error getting the cluster on this server. Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return @()
    }

    $nodes = $cluster | Get-ClusterNode -ErrorAction SilentlyContinue -ErrorVariable +err| Microsoft.PowerShell.Utility\Select-Object `
    State, `
    @{ Name = $NamePropertyName; Expression = { $_.Name } }, `
    @{ Name = $FQDNPropertyName; Expression = { getServerFqdn $_.Name } }

    if ($err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: There was an error getting the cluster nodes on this server. Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return @()
    }

    return $nodes
}

###############################################################################
# Script execution starts here
###############################################################################

setupScriptEnv

try {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    $clusterModule = Get-Module -Name FailoverClusters -ErrorAction SilentlyContinue

    if (-not($clusterModule)) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: The required PowerShell module (FailoverClusters) was not found." -ErrorAction SilentlyContinue

        Write-Error $strings.FailoverClustersModuleRequired

        return @()
    }

    return main
} finally {
    cleanupScriptEnv
}

}
## [END] Get-WACVMClusterNodeState ##
function Get-WACVMClusterSharedVolumesRoot {
<#

.SYNOPSIS
Get the root path of the Cluster Shared Volumes (CSV) storage.

.DESCRIPTION
Get the root path of the Cluster Shared Volumes (CSV) storage on this server/node.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0
Import-Module FailoverClusters -ErrorAction SilentlyContinue
 
Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

###############################################################################
# Constants
###############################################################################

Set-Variable -Name LogName -Option Constant -Value "Microsoft-ServerManagementExperience" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SMEScripts" -ErrorAction SilentlyContinue
Set-Variable -Name ScriptName -Option Constant -Value "Get-ClusterSharedVolumesRoot.ps1" -ErrorAction SilentlyContinue

function main() {
    return (Get-Cluster | Microsoft.PowerShell.Utility\Select-Object SharedVolumesRoot)
}

$module = Get-Module -Name FailoverClusters -ErrorAction SilentlyContinue
if ($module) {
    return main
}

Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue
Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
    -Message "[$ScriptName]: The required PowerShell module (FailoverClusters) was not found." -ErrorAction SilentlyContinue

Write-Error $strings.FailoverClustersModuleRequired

return $null
}
## [END] Get-WACVMClusterSharedVolumesRoot ##
function Get-WACVMClusteredVirtualMachineIds {
<#

.SYNOPSIS
Get the list of clustered virtual machine Ids and owner nodes from the cluster.

.DESCRIPTION
Get the list of clustered virtual machine Ids and owner nodes from the cluster on this node.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0
Import-Module CimCmdlets -ErrorAction SilentlyContinue

###############################################################################
# Constants
###############################################################################

##SkipCheck=true##
Set-Variable -Name QueryString -Option Constant -Value "select OwnerNode, PrivateProperties from mscluster_resource where type='virtual machine'" -ErrorAction SilentlyContinue
##SkipCheck=false##
Set-Variable -Name ClusterCimNameSpace -Option Constant -Value "root/MSCluster" -ErrorAction SilentlyContinue
Set-Variable -Name LogName -Option Constant -Value "Microsoft-ServerManagementExperience" -ErrorAction SilentlyContinue
Set-Variable -Name ScriptName -Option Constant -Value "Get-ClusteredVirtualMachineIds.ps1" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SMEScripts" -ErrorAction SilentlyContinue

<#

.SYNOPSIS
is the cluster CIM (WMI) provider installed on this server?

.DESCRIPTION
Returns true when the cluster CIM provider is installed on this server.

#>

function isClusterCimProviderAvailable() {
    $namespace = Get-CimInstance -Namespace $ClusterCimNamespace -ClassName __NAMESPACE -ErrorAction SilentlyContinue

    return !!$namespace
}

<#

.SYNOPSIS
Get the clustered virtual machine Ids.

.DESCRIPTION
Use the cluster CIM provider to fetch the Ids of all clustered virutal machines.

#>

function getVirtualMachineIds() {
    $results = @()

    $clusterResources = Get-CimInstance -Namespace $ClusterCimNameSpace -Query $QueryString -ErrorAction SilentlyContinue

    foreach ($clusterResource in $clusterResources) {
        $result = New-Object PSObject

        Add-Member -InputObject $result -MemberType NoteProperty -Name "VmId" -Value $clusterResource.PrivateProperties.vmId.ToLower()
        Add-Member -InputObject $result -MemberType NoteProperty -Name "OwnerNode" -Value $clusterResource.OwnerNode
        $results += $result
    }

    $results
}

<#

.SYNOPSIS
Main function.

.DESCRIPTION
All biz logic should start in this function.

#>

function main() {
    if (isClusterCimProviderAvailable) {
        return getVirtualMachineIds
    } else {
        Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Warning `
            -Message "[$ScriptName]: The required Failover Clusters CIM provider was not found."  -ErrorAction SilentlyContinue

    }

    return @()
}

###############################################################################
# Script execution starts here.
###############################################################################

if (-not ($env:pester)) {
    return main
}

return @()
}
## [END] Get-WACVMClusteredVirtualMachineIds ##
function Get-WACVMClusteredVirtualMachineIdsOfServer {
<#

.SYNOPSIS
Get the list of clustered virtual machine Ids from the cluster for the passed in server.

.DESCRIPTION
Get the list of clustered virtual machine Ids from the cluster on this node for the passed in server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER server
    The name of the server.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $server
)  

Set-StrictMode -Version 5.0;
Import-Module CimCmdlets;

##SkipCheck=true##
$queryString = "select PrivateProperties from mscluster_resource where type='virtual machine' and ownernode='{0}'" -f $server;
##SkipCheck=false##

$results = Get-CimInstance -Namespace Root\MSCluster -Query $queryString -ErrorAction SilentlyContinue

$vmIds = @();

foreach ($resource in $results) {
    $vmIds += $resource.PrivateProperties.vmId;
}

return $vmIds;
}
## [END] Get-WACVMClusteredVirtualMachineIdsOfServer ##
function Get-WACVMDefaultNetworkPolicySupport {
<#

.SYNOPSIS
Get whether a "disable DNP" key is present on the cluster node

.DESCRIPTION
Get whether a "disable DNP" key is present on the cluster node

.ROLE
Readers

#>

$result = $false

Try {
  $key = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters' -ErrorAction Stop).DisableDefaultNetworkPolicies

  # Check if the key says to disable the policies
  $result = $key -eq 'true'
}
Catch [System.Management.Automation.ItemNotFoundException] {
  # Key doesn't exist so don't disable the policy
}

$result

}
## [END] Get-WACVMDefaultNetworkPolicySupport ##
function Get-WACVMFaultDomainConfig {
<#

.SYNOPSIS
Gets a cluster's stretch status

.DESCRIPTION
Gets a cluster's stretch status

.ROLE
Readers

#>
Set-StrictMode -Version 5.0

if (Get-Command "Get-ClusterFaultDomain" -ErrorAction SilentlyContinue) {
  $sites = Get-ClusterFaultDomain | Microsoft.PowerShell.Core\Where-Object { $_.Type -eq 'Site' }
  return $null -ne $sites -and $sites.PSobject.Properties.name -match "length" -and $sites.length -gt 1
}

return $false

}
## [END] Get-WACVMFaultDomainConfig ##
function Get-WACVMFilePathValidity {
<#

.SYNOPSIS
Validate a file path.

.DESCRIPTION
Validates a file path passed in the import file explorer

.ROLE
Hyper-V-Administrators

.PARAMETER filePath
The path containing the virtual machines to import.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $filePath
)

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue

<#

.SYNOPSIS
The main function.

.DESCRIPTION
Validate the file path passed in as a parammeter

.PARAMETER filePath
The path containing the virtual machines to import.

#>

function main([string]$filePath) {

  return $filePath | Test-Path

}


###############################################################################
# Script execution starts here
###############################################################################
$module = Get-Module -Name Hyper-V -ErrorAction SilentlyContinue

if ($module) {
    return main $filePath
}

}
## [END] Get-WACVMFilePathValidity ##
function Get-WACVMFreeVolumeDiskSpace {
<#

.SYNOPSIS
Gets the free space size of cluster shared volume (CSV) or local disks.

.DESCRIPTION
Gets the free space size of cluster shared volume (CSV) or local disks.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER clusterStorageRequested
    Has the client requested clustered storage?

#>

param (
    [Parameter(Mandatory = $true)]
    [boolean]
    $clusterStorageRequested
)  

Set-StrictMode -Version 5.0

Import-Module CimCmdlets -ErrorAction SilentlyContinue
Import-Module FailoverClusters -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue


function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-FreeVolumeDiskSpace.ps1" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
}

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
}

<#

.SYNOPSIS
Determine if the required PowerShell module(s) are present.

.DESCRIPTION
Return true when the required PowerShell modules are present.

#>

function AreRequiredPowerShellModulesInstalled() {
    $module = Get-Module -Name FailoverClusters -ErrorAction SilentlyContinue

    return !!$module
}

<#

.SYNOPSIS
Write the error(s) for the required PowerShell module(s) not being present on this server.

.DESCRIPTION
Write the error(s) for the required PowerShell module(s) not being present on this server.

#>

function WriteRequiredPowerShellModulesNotAvailableError() {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: The required PowerShell module (FailoverClusters) was not found." -ErrorAction SilentlyContinue

    Write-Error $strings.FailoverClustersModuleRequired
}
 
<#

.SYNOPSIS
Main function of this script.

.DESCRIPTION
Main function of this script.

.PARAMETER clusterStorageRequested
    Has the client requested clustered storage?

#>

function main([boolean]$clusterStorageRequested) {
    $Error.Clear()

    $service = Microsoft.PowerShell.Management\Get-Service -Name "CLUSSVC" -ErrorAction SilentlyContinue;
    $isCluster = ($service -and $service.Name -eq "CLUSSVC" -and $service.status -eq 4);
    $Result = @{}
        
    # Was cluster storage requested?
    if ($clusterStorageRequested) {
        # Are we connected to a cluster?
        if ($isCluster) {
            if (AreRequiredPowerShellModulesInstalled) {
                # Try to get CSV space using given cmdlet
                $Result = Get-ClusterSharedVolume | Microsoft.PowerShell.Utility\Select-Object -Expand SharedVolumeInfo -ErrorAction SilentlyContinue | `
                    Microsoft.PowerShell.Utility\Select-Object @{n="Name"; e={$_.FriendlyVolumeName}}, @{n="FreeSpace";e={$_.Partition.Size - $_.Partition.UsedSpace}}
            } else {
                WriteRequiredPowerShellModulesNotAvailableError
            }
        } else {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error
                -Message "[$ScriptName]: Cluster storage was requested, but this server is not a cluster node."
        }
    } else {
        # If not a cluster then get the disks of a server.
        $Result = Get-CimInstance -NameSpace "root\cimv2" -ClassName "Win32_LogicalDisk" | Microsoft.PowerShell.Utility\Select-Object @{n="Name"; e={$_.DeviceID}}, FreeSpace -ErrorAction SilentlyContinue
    }

    return $Result
}

###############################################################################
# Script execution starts here...
###############################################################################

setupScriptEnv

try {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    return main $clusterStorageRequested
} finally {
    cleanupScriptEnv
}

}
## [END] Get-WACVMFreeVolumeDiskSpace ##
function Get-WACVMHistoricalIOData {
<#

.SYNOPSIS
Gets the historical performance data for the volumes of a cluster.

.DESCRIPTION
Gets the historical performance data for the volumes of a cluster from Britannica if available,
otherwise get from TSDB.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0
Import-Module CimCmdlets -ErrorAction SilentlyContinue
Import-Module FailoverClusters -ErrorAction SilentlyContinue
Import-Module Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.  Create read only (constant) variables
that add context to the said constants.

#>

function setupScriptEnv() {
    Set-Variable -Name TimeRangeHourValue -Option ReadOnly -Value 0 -Scope Script
    Set-Variable -Name TimeRangeDayValue -Option ReadOnly -Value 1 -Scope Script
    Set-Variable -Name TimeRangeWeekValue -Option ReadOnly -Value 2 -Scope Script
    Set-Variable -Name TimeRangeMonthValue -Option ReadOnly -Value 3 -Scope Script
    Set-Variable -Name TimeRangeYearValue -Option ReadOnly -Value 4 -Scope Script
    Set-Variable -Name MsConversion -Option ReadOnly -Value 1000 -Scope Script
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-HistoricalIOData.ps1" -Scope Script
}

<#

.SYNOPSIS
Cleanup the script environment.

.DESCRIPTION
Cleanup the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name TimeRangeHourValue -Scope Script -Force
    Remove-Variable -Name TimeRangeDayValue -Scope Script -Force
    Remove-Variable -Name TimeRangeWeekValue -Scope Script -Force
    Remove-Variable -Name TimeRangeMonthValue -Scope Script -Force
    Remove-Variable -Name TimeRangeYearValue -Scope Script -Force
    Remove-Variable -Name MsConversion -Scope Script -Force
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
}

<#

.SYNOPSIS
Determines if Britannica (sddc management resources) are available on the cluster

.DESCRIPTION
Use the existance of the cim namespace root/sddc to determine if Britannica
is supported or not.

#>
function isBritannicaEnabled() {
    return !!(Get-CimInstance -Namespace "root\SDDC\Management" -ClassName SDDC_Cluster -ErrorAction SilentlyContinue)
}

<#

.SYNOPSIS
Determines if the current cluster supports Failover Clusters Time Series Database.

.DESCRIPTION
Use the existance of the path value of cmdlet Get-StorageHealthSetting to determine if TSDB
is supported or not.

#>
function isTsdbEnabled() {
    $path = $null
    if ((Get-Command Get-StorageSubSystem -ErrorAction SilentlyContinue) -and (Get-Command Get-StorageHealthSetting -ErrorAction SilentlyContinue)) {
        $path = Get-StorageSubSystem clus* | Get-StorageHealthSetting -Name "System.PerformanceHistory.Path" -ErrorAction SilentlyContinue
    }

    return !!$path
}


<#

.SYNOPSIS
Get historical data from Britannica (sddc management resources)

.DESCRIPTION
Get raw historical hourly, daily, weekly, monthly, yearly data from Britannica

#>
function getDataFromBritannica()
{
    $cluster = Get-CimInstance -Namespace "root\SDDC\Management" -ClassName SDDC_Cluster
    if (!$cluster) {
        return $null
    }

    $returnValues = @{}

    $hourlyIopsRaw = getMetrics $cluster "Volume.IOPS.Total" $TimeRangeHourValue
    # In RS1 Britannica name space exists but GetMetrics return empty, in this case no need continue
    if (!$hourlyIopsRaw) {
        return $null
    }

    $returnValues.hourlyIopsRaw = $hourlyIopsRaw
    $returnValues.dailyIopsRaw = getMetrics $cluster "Volume.IOPS.Total" $TimeRangeDayValue
    $returnValues.weeklyIopsRaw = getMetrics $cluster "Volume.IOPS.Total" $TimeRangeWeekValue
    $returnValues.monthlyIopsRaw = getMetrics $cluster "Volume.IOPS.Total" $TimeRangeMonthValue
    $returnValues.yearlyIopsRaw = getMetrics $cluster "Volume.IOPS.Total" $TimeRangeYearValue

    $returnValues.hourlyThroughputRaw = getMetrics $cluster "Volume.Throughput.Total" $TimeRangeHourValue
    $returnValues.dailyThroughputRaw = getMetrics $cluster "Volume.Throughput.Total" $TimeRangeDayValue
    $returnValues.weeklyThroughputRaw = getMetrics $cluster "Volume.Throughput.Total" $TimeRangeWeekValue
    $returnValues.monthlyThroughputRaw = getMetrics $cluster "Volume.Throughput.Total" $TimeRangeMonthValue
    $returnValues.yearlyThroughputRaw = getMetrics $cluster "Volume.Throughput.Total" $TimeRangeYearValue

    $returnValues.hourlyLatencyRaw = getMetrics $cluster "Volume.Latency.Average" $TimeRangeHourValue
    $returnValues.dailyLatencyRaw = getMetrics $cluster "Volume.Latency.Average" $TimeRangeDayValue
    $returnValues.weeklyLatencyRaw = getMetrics $cluster "Volume.Latency.Average" $TimeRangeWeekValue
    $returnValues.monthlyLatencyRaw = getMetrics $cluster "Volume.Latency.Average" $TimeRangeMonthValue
    $returnValues.yearlyLatencyRaw = getMetrics $cluster "Volume.Latency.Average" $TimeRangeYearValue

    return $returnValues
}

<#

.SYNOPSIS
Get historical metrics data from Britannica (sddc management resources)

.DESCRIPTION
Get raw data through cim method "GetMetrics" with given seriesName and timeFrame

.PARAMETER cluster
The PsObject of target cluster

.PARAMETER seriesName
The string of seriesName for query argument

.PARAMETER timeFrame
The number of timeFrame for query argument

#>
function getMetrics {
    param(
        [Parameter(Mandatory = $true)]
        [PsObject]
        $cluster,
        [Parameter(Mandatory = $true)]
        [string]
        $seriesName,
        [Parameter(Mandatory = $true)]
        [uint16]
        $timeFrame
    )

    # don't use !$timeFrame since it can be evaluated as $true when $timeFrame is zero
    if (!$cluster -or !$seriesName -or ($null -eq $timeFrame)) {
        return $null
    }

    $metric = $cluster | Invoke-CimMethod -MethodName "GetMetrics" -Arguments @{ SeriesName = $seriesName; TimeFrame = [uint16]$timeFrame}
    if ($metric.Metric -and $metric.Metric.Datapoints) {
        return $metric.Metric.Datapoints
    } else {
        return $null
    }
}

<#

.SYNOPSIS
Get historical data from failover cluster TSDB (time series database)

.DESCRIPTION
Get raw historical hourly, daily, weekly, monthly, yearly data from failover cluster TSDB

#>
function getDataFromTsdb()
{
    $cluster = Get-Cluster
    if (!$cluster) {
        return $null
    }

    $returnValues = @{}

    $hourlyIopsRaw = getHistoryData $cluster "Volume.IOPS.Total" "LastHour"
    # In some case performance history storage path exists but getHistoryData return empty, in this case no need continue
    if (!$hourlyIopsRaw) {
        return $null
    }

    $returnValues.hourlyIopsRaw = $hourlyIopsRaw
    $returnValues.dailyIopsRaw = getHistoryData $cluster "Volume.IOPS.Total" "LastDay"
    $returnValues.weeklyIopsRaw = getHistoryData $cluster "Volume.IOPS.Total" "LastWeek"
    $returnValues.monthlyIopsRaw = getHistoryData $cluster "Volume.IOPS.Total" "LastMonth"
    $returnValues.yearlyIopsRaw = getHistoryData $cluster "Volume.IOPS.Total" "LastYear"

    $returnValues.hourlyThroughputRaw = getHistoryData $cluster "Volume.Throughput.Total" "LastHour"
    $returnValues.dailyThroughputRaw = getHistoryData $cluster "Volume.Throughput.Total" "LastDay"
    $returnValues.weeklyThroughputRaw = getHistoryData $cluster "Volume.Throughput.Total" "LastWeek"
    $returnValues.monthlyThroughputRaw = getHistoryData $cluster "Volume.Throughput.Total" "LastMonth"
    $returnValues.yearlyThroughputRaw = getHistoryData $cluster "Volume.Throughput.Total" "LastYear"

    $returnValues.hourlyLatencyRaw = getHistoryData $cluster "Volume.Latency.Average" "LastHour"
    $returnValues.dailyLatencyRaw = getHistoryData $cluster "Volume.Latency.Average" "LastDay"
    $returnValues.weeklyLatencyRaw = getHistoryData $cluster "Volume.Latency.Average" "LastWeek"
    $returnValues.monthlyLatencyRaw = getHistoryData $cluster "Volume.Latency.Average" "LastMonth"
    $returnValues.yearlyLatencyRaw = getHistoryData $cluster "Volume.Latency.Average" "LastYear"

    return $returnValues
}

<#

.SYNOPSIS
Get historical performance data from failover cluster TSDB (time series database)

.DESCRIPTION
Get raw data through Get-ClusterPerformanceHistory with given seriesName and timeFrame

.PARAMETER cluster
The PsObject of target cluster

.PARAMETER seriesName
The string of seriesName for query argument

.PARAMETER timeFrame
The number of timeFrame for query argument

#>
function getHistoryData {
    param(
        [Parameter(Mandatory = $true)]
        [PsObject]
        $cluster,
        [Parameter(Mandatory = $true)]
        [string]
        $seriesName,
        [Parameter(Mandatory = $true)]
        [string]
        $timeFrame
    )

    if (!$cluster -or !$seriesName -or !$timeFrame) {
        return $null
    }

    return $cluster | Get-ClusterPerformanceHistory -ClusterSeriesName $seriesName -TimeFrame $timeFrame
}

<#

.SYNOPSIS
Create all graph data from Britannica raw data

.DESCRIPTION
Create all graph data from Britannica raw data

#>
function createAllGraphDataFromBritannica() {
    $rawData = getDataFromBritannica
    if (!$rawData){
        return $null
    }

    $returnValues = @{}

    $returnValues.hourlyIops = createGraphDataFromBritannica $rawData.hourlyIopsRaw
    $returnValues.dailyIops = createGraphDataFromBritannica $rawData.dailyIopsRaw
    $returnValues.weeklyIops = createGraphDataFromBritannica $rawData.weeklyIopsRaw
    $returnValues.monthlyIops = createGraphDataFromBritannica $rawData.monthlyIopsRaw
    $returnValues.yearlyIops = createGraphDataFromBritannica $rawData.yearlyIopsRaw

    $returnValues.hourlyThroughput = createGraphDataFromBritannica $rawData.hourlyThroughputRaw
    $returnValues.dailyThroughput = createGraphDataFromBritannica $rawData.dailyThroughputRaw
    $returnValues.weeklyThroughput = createGraphDataFromBritannica $rawData.weeklyThroughputRaw
    $returnValues.monthlyThroughput = createGraphDataFromBritannica $rawData.monthlyThroughputRaw
    $returnValues.yearlyThroughput = createGraphDataFromBritannica $rawData.yearlyThroughputRaw

    $returnValues.hourlyLatency = createGraphDataFromBritannica $rawData.hourlyLatencyRaw $MsConversion
    $returnValues.dailyLatency = createGraphDataFromBritannica $rawData.dailyLatencyRaw $MsConversion
    $returnValues.weeklyLatency = createGraphDataFromBritannica $rawData.weeklyLatencyRaw $MsConversion
    $returnValues.monthlyLatency = createGraphDataFromBritannica $rawData.monthlyLatencyRaw $MsConversion
    $returnValues.yearlyLatency = createGraphDataFromBritannica $rawData.yearlyLatencyRaw $MsConversion

    return $returnValues
}

<#

.SYNOPSIS
Create all graph data from TSDB raw data

.DESCRIPTION
Create all graph data from TSDB raw data

#>
function createAllGraphDataFromTsdb() {
    $rawData = getDataFromTsdb
    if (!$rawData){
        return $null
    }

    $returnValues = @{}

    $returnValues.hourlyIops = createGraphDataFromTsdb $rawData.hourlyIopsRaw
    $returnValues.dailyIops = createGraphDataFromTsdb $rawData.dailyIopsRaw
    $returnValues.weeklyIops = createGraphDataFromTsdb $rawData.weeklyIopsRaw
    $returnValues.monthlyIops = createGraphDataFromTsdb $rawData.monthlyIopsRaw
    $returnValues.yearlyIops = createGraphDataFromTsdb $rawData.yearlyIopsRaw

    $returnValues.hourlyThroughput = createGraphDataFromTsdb $rawData.hourlyThroughputRaw
    $returnValues.dailyThroughput = createGraphDataFromTsdb $rawData.dailyThroughputRaw
    $returnValues.weeklyThroughput = createGraphDataFromTsdb $rawData.weeklyThroughputRaw
    $returnValues.monthlyThroughput = createGraphDataFromTsdb $rawData.monthlyThroughputRaw
    $returnValues.yearlyThroughput = createGraphDataFromTsdb $rawData.yearlyThroughputRaw

    $returnValues.hourlyLatency = createGraphDataFromTsdb $rawData.hourlyLatencyRaw $MsConversion
    $returnValues.dailyLatency = createGraphDataFromTsdb $rawData.dailyLatencyRaw $MsConversion
    $returnValues.weeklyLatency = createGraphDataFromTsdb $rawData.weeklyLatencyRaw $MsConversion
    $returnValues.monthlyLatency = createGraphDataFromTsdb $rawData.monthlyLatencyRaw $MsConversion
    $returnValues.yearlyLatency = createGraphDataFromTsdb $rawData.yearlyLatencyRaw $MsConversion

    return $returnValues
}

<#

.SYNOPSIS
Create graph data from Britannica raw data

.DESCRIPTION
Create graph data from Britannica raw data

.PARAMETER rawData
The array of dataValues, if might be null when the raw data is not avaiable

.PARAMETER conversion
The conversion number for value adjustment. This parameter is optional, default is 1

#>
function createGraphDataFromBritannica {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [array]
        $rawData,
        [Parameter(Mandatory = $false)]
        [float]
        $conversion = 1 #default
    )

    $graphData = New-Object System.Collections.ArrayList
    if ($rawData) {
        $graphData = $rawData | Microsoft.PowerShell.Utility\Select-Object @{N='Value'; E={[math]::Round($_.Value * $conversion,2)}}, TimeStamp
    }

    return $graphData
}

<#

.SYNOPSIS
Create graph data from TSDB raw data

.DESCRIPTION
Create graph data from TSDB raw data

.PARAMETER rawData
The array of dataValues, if might be null when the raw data is not avaiable

.PARAMETER conversion
The conversion number for value adjustment. This parameter is optional, default is 1

#>
function createGraphDataFromTsdb {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [array]
        $rawData,
        [Parameter(Mandatory = $false)]
        [float]
        $conversion = 1 #default
    )

    $graphData = New-Object System.Collections.ArrayList
    if ($rawData) {
        $graphData = $rawData | Microsoft.PowerShell.Utility\Select-Object @{N='Value'; E={[math]::Round($_.Value * $conversion,2)}}, @{N='TimeStamp'; E={$_.Time}}
    }

    return $graphData
}

<#

.SYNOPSIS
Get historical data

.DESCRIPTION
Get historical data from the Britannica first if avaiable, then Tsdb, otherwise return null
return $null means neither Britannica nor Tsdb is enabled

#>
function getHistoricalData() {
    $data = $null

    if (isBritannicaEnabled) {
        $data = createAllGraphDataFromBritannica
    }
    if (!$data -and (isTsdbEnabled)) {
        return createAllGraphDataFromTsdb
    }

    return $data
}

function main() {
    $returnValues = getHistoricalData
    if ($returnValues) {
        $result = New-Object PSObject
        $result | Add-Member -MemberType NoteProperty -Name 'hourlyIops' -Value $returnValues.hourlyIops
        $result | Add-Member -MemberType NoteProperty -Name 'dailyIops' -Value $returnValues.dailyIops
        $result | Add-Member -MemberType NoteProperty -Name 'weeklyIops' -Value $returnValues.weeklyIops
        $result | Add-Member -MemberType NoteProperty -Name 'monthlyIops' -Value $returnValues.monthlyIops
        $result | Add-Member -MemberType NoteProperty -Name 'yearlyIops' -Value $returnValues.yearlyIops

        $result | Add-Member -MemberType NoteProperty -Name 'hourlyThroughput' -Value $returnValues.hourlyThroughput
        $result | Add-Member -MemberType NoteProperty -Name 'dailyThroughput' -Value $returnValues.dailyThroughput
        $result | Add-Member -MemberType NoteProperty -Name 'weeklyThroughput' -Value $returnValues.weeklyThroughput
        $result | Add-Member -MemberType NoteProperty -Name 'monthlyThroughput' -Value $returnValues.monthlyThroughput
        $result | Add-Member -MemberType NoteProperty -Name 'yearlyThroughput' -Value $returnValues.yearlyThroughput

        $result | Add-Member -MemberType NoteProperty -Name 'hourlyLatency' -Value $returnValues.hourlyLatency
        $result | Add-Member -MemberType NoteProperty -Name 'dailyLatency' -Value $returnValues.dailyLatency
        $result | Add-Member -MemberType NoteProperty -Name 'weeklyLatency' -Value $returnValues.weeklyLatency
        $result | Add-Member -MemberType NoteProperty -Name 'monthlyLatency' -Value $returnValues.monthlyLatency
        $result | Add-Member -MemberType NoteProperty -Name 'yearlyLatency' -Value $returnValues.yearlyLatency

        return $result
    } else {
        # return $null will delete the chart
        return $null
    }
}


###############################################################################
# Script execution starts here.
###############################################################################

if (-not($env:pester)) {
    setupScriptEnv

    try {
        $module = Get-Module -Name FailoverClusters -ErrorAction SilentlyContinue
        if ($module) {
            return main
        }

        Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: The required PowerShell module (FailoverClusters) was not found."  -ErrorAction SilentlyContinue

        Write-Error $strings.FailoverClustersModuleRequired

        return $null
    } finally {
        cleanupScriptEnv
    }
}

}
## [END] Get-WACVMHistoricalIOData ##
function Get-WACVMHostClusterName {
<#

.SYNOPSIS
Get the host cluster FQDN of which this server is a member.

.DESCRIPTION
Get the host cluster FQDN of which this server is a member.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0

Import-Module FailoverClusters -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.  Create read only (constant) variables
that add context to the said constants.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-HostClusterName.ps1" -Scope Script
}

<#

.SYNOPSIS
Cleanup the script environment.

.DESCRIPTION
Cleanup the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
}

function main() {
    $cluster = Get-Cluster -ErrorAction SilentlyContinue -ErrorVariable +err

    if ($err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: There was an error getting the cluster. Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return $null
    }

    $hostClusterName = "{0}.{1}" -f $cluster.Name, $cluster.Domain

    return $hostClusterName
}

###############################################################################
# Script execution starts here
###############################################################################

setupScriptEnv

try {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    $clusterModule = Get-Module -Name FailoverClusters -ErrorAction SilentlyContinue

    if (-not($clusterModule)) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: The required PowerShell module (FailoverClusters) was not found." -ErrorAction SilentlyContinue

        Write-Error $strings.FailoverClustersModuleRequired

        return $null
    }

    return main
} finally {
    cleanupScriptEnv
}

}
## [END] Get-WACVMHostClusterName ##
function Get-WACVMHostFqdn {
<#

.SYNOPSIS
Returns the FQDN of the computer/server/node.

.DESCRIPTION
Returns the FQDN of the computer/server/node on which this script runs.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0;

return [System.Net.DNS]::GetHostByName('').HostName
}
## [END] Get-WACVMHostFqdn ##
function Get-WACVMHostSecureBootTemplates {
<#

.SYNOPSIS
Gets a computer's Hyper-V Host Secure Boot Templates

.DESCRIPTION
Gets computer's Hyper-V Host templates list.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0;
Import-Module Hyper-V;

function getSecureBootTemplates([string] $ss) {
    return Get-VMHost | Microsoft.PowerShell.Utility\Select-Object SecureBootTemplates
}

###########################################################################
# main()
###########################################################################

$isDownlevel = [Environment]::OSVersion.Version.Major -lt 10

$templates = getSecureBootTemplates

$result = New-Object PSObject

$result | Add-Member -MemberType NoteProperty -Name 'isDownlevel' -Value $isDownlevel
$result | Add-Member -MemberType NoteProperty -Name 'templates' -Value $templates

$result

}
## [END] Get-WACVMHostSecureBootTemplates ##
function Get-WACVMHyperVBestHostNode {
<#

.SYNOPSIS
Returns the list of available cluster node names, and the best node name to host a new virtual machine.

.DESCRIPTION
Use the cluster CIM provider (MSCluster) to ask the cluster which node is the best to host a new virtual machine.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0

Import-Module CimCmdlets -ErrorAction SilentlyContinue
Import-Module FailoverClusters -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue


<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.  Create read only (constant) variables
that add context to the said constants.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name clusterCimNameSpace -Option ReadOnly -Value "root/MSCluster" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-HyperVBestHostNode.ps1" -Scope Script
    Set-Variable -Name BestNodePropertyName -Option ReadOnly -Value "BestNode" -Scope Script
    Set-Variable -Name StateUp -Option ReadOnly -Value "0" -Scope Script
}

<#

.SYNOPSIS
Cleanup the script environment.

.DESCRIPTION
Cleanup the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name clusterCimNameSpace -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name BestNodePropertyName -Scope Script -Force
    Remove-Variable -Name StateUp -Scope Script -Force
}

<#

.SYNOPSIS
Get the fully qualified domain name for the passed in server name from DNS.

.DESCRIPTION
Get the fully qualified domain name for the passed in server name from DNS.

#>

function GetServerFqdn([string]$netBIOSName) {
    try {
        $fqdn = [System.Net.DNS]::GetHostByName($netBIOSName).HostName

        return $fqdn.ToLower()
    } catch {
        $errMessage = $_.Exception.Message

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: There was an error looking up the FQDN for server $netBIOSName.  Error: $errMessage"  -ErrorAction SilentlyContinue

        return $netBIOSName
    }
}

<#

.SYNOPSIS
Are the cluster PowerShell cmdlets installed on this server?

.DESCRIPTION
Are the cluster PowerShell cmdlets installed on this server?

#>

function getIsClusterCmdletsAvailable() {
    $cmdlet = Get-Command "Get-Cluster" -ErrorAction SilentlyContinue

    return !!$cmdlet
}

<#

.SYNOPSIS
is the cluster CIM (WMI) provider installed on this server?

.DESCRIPTION
Returns true when the cluster CIM provider is installed on this server.

#>

function isClusterCimProviderAvailable() {
    $namespace = Get-CimInstance -Namespace $clusterCimNamespace -ClassName __NAMESPACE -ErrorAction SilentlyContinue

    return !!$namespace
}

<#

.SYNOPSIS
Get the MSCluster Cluster Service CIM instance from this server.

.DESCRIPTION
Get the MSCluster Cluster Service CIM instance from this server.

#>

function getClusterServiceCimInstance() {
    return Get-CimInstance -Namespace $clusterCimNamespace MSCluster_ClusterService -ErrorAction SilentlyContinue
}

<#

.SYNOPSIS
Get the list of the cluster nodes that are running.

.DESCRIPTION
Returns a list of cluster node names that are running using PowerShell.

#>

function getAllUpClusterNodeNames() {
    # Constants
    Set-Variable -Name stateUp -Option Readonly -Value "up" -Scope Local

    try {
        return Get-ClusterNode | Where-Object { $_.State -eq $stateUp } | ForEach-Object { (GetServerFqdn $_.Name) }
    } finally {
        Remove-Variable -Name stateUp -Scope Local -Force
    }
}

<#

.SYNOPSIS
Get the list of the cluster nodes that are running.

.DESCRIPTION
Returns a list of cluster node names that are running using CIM.

#>

function getAllUpClusterCimNodeNames() {
##SkipCheck=true##
    $query = "select name, state from MSCluster_Node Where state = '{0}'" -f $StateUp
##SkipCheck=false##
    return Get-CimInstance -Namespace $clusterCimNamespace -Query $query | ForEach-Object { (GetServerFqdn $_.Name) }
}

<#

.SYNOPSIS
Create a new instance of the "results" PS object.

.DESCRIPTION
Create a new PS object and set the passed in nodeNames to the appropriate property.

#>

function newResult([string []] $nodeNames) {
    $result = new-object PSObject
    $result | Add-Member -Type NoteProperty -Name Nodes -Value $nodeNames

    return $result;
}

<#

.SYNOPSIS
Remove any old lingering reservation for our typical VM.

.DESCRIPTION
Remove the reservation from the passed in id.

#>

function removeReservation($clusterService, [string] $rsvId) {
    Set-Variable removeReservationMethodName -Option Constant -Value "RemoveVmReservation"

    Invoke-CimMethod -CimInstance $clusterService -MethodName $removeReservationMethodName -Arguments @{ReservationId = $rsvId} -ErrorVariable +err | Out-Null
}

<#

.SYNOPSIS
Create a reservation for our typical VM.

.DESCRIPTION
Create a reservation for the passed in id.

#>

function createReservation($clusterService, [string] $rsvId) {
    Set-Variable -Name createReservationMethodName -Option ReadOnly -Value "CreateVmReservation" -Scope Local
    Set-Variable -Name reserveSettings -Option ReadOnly -Value @{VmMemory = 2048; VmVirtualCoreCount = 2; VmCpuReservation = 0; VmFlags = 0; TimeSpan = 2000; ReservationId = $rsvId; LocalDiskSize = 0; Version = 0} -Scope Local

    try {
        $vmReserve = Invoke-CimMethod -CimInstance $clusterService -MethodName $createReservationMethodName -ErrorAction SilentlyContinue -ErrorVariable va -Arguments $reserveSettings

        if (!!$vmReserve -and $vmReserve.ReturnValue -eq 0 -and !!$vmReserve.NodeId) {
            return $vmReserve.NodeId
        }

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Could not create a reservation for a virtual machine. Output from $createReservationMethodName is $vmReserve"  -ErrorAction SilentlyContinue

        return $null
    } finally {
        Remove-Variable -Name createReservationMethodName -Scope Local -Force
        Remove-Variable -Name reserveSettings -Scope Local -Force
    }
}

<#

.SYNOPSIS
Use the Cluster CIM provider to find the best host name for a typical VM.

.DESCRIPTION
Returns the best host node name, or null when none are found.

#>

function askClusterServiceForBestHostNode() {
    # API parameters
    Set-Variable -Name rsvId -Option ReadOnly -Value "TempVmId1" -Scope Local

    try {
        # If the class exist, using api to get optimal host
        $clusterService = getClusterServiceCimInstance
        if (!!$clusterService) {
            $nodeNames = @(getAllUpClusterCimNodeNames)
            $result = newResult $nodeNames

            # remove old reserveration if there is any
            removeReservation $clusterService $rsvId

            $id = createReservation $clusterService $rsvId

            if (!!$id) {
    ##SkipCheck=true##
                $query = "select name, id from MSCluster_Node where id = '{0}'" -f $id
    ##SkipCheck=false##
                $bestNode = Get-CimInstance -Namespace $clusterCimNamespace -Query $query -ErrorAction SilentlyContinue

                if ($bestNode) {
                    $result | Add-Member -Type NoteProperty -Name $BestNodePropertyName -Value (GetServerFqdn $bestNode.Name)

                    return $result
                }
            }
        }

        return $null
    } finally {
        Remove-Variable -Name rsvId -Scope Local -Force
    }
}

<#

.SYNOPSIS
Get the name of the cluster node that has the least number of VMs running on it.

.DESCRIPTION
Return the name of the cluster node that has the least number of VMs running on it.

#>

function getLeastLoadedNode() {
    # Constants
    Set-Variable -Name vmResourceTypeName -Option ReadOnly -Value "Virtual Machine" -Scope Local
    Set-Variable -Name OwnerNodePropertyName -Option ReadOnly -Value "OwnerNode" -Scope Local

    try {
        $nodeNames = @(getAllUpClusterNodeNames)
        $bestNodeName = $null;

        $result = newResult $nodeNames

        $virtualMachinesPerNode = @{}

        # initial counts as 0
        $nodeNames | ForEach-Object { $virtualMachinesPerNode[$_] = 0 }

        $ownerNodes = Get-ClusterResource | Where-Object { $_.ResourceType -eq $vmResourceTypeName } | Microsoft.PowerShell.Utility\Select-Object $OwnerNodePropertyName
        $ownerNodes | ForEach-Object { $virtualMachinesPerNode[$_.OwnerNode.Name]++ }

        # find node with minimum count
        $bestNodeName = $nodeNames[0]
        $min = $virtualMachinesPerNode[$bestNodeName]

        $nodeNames | ForEach-Object {
            if ($virtualMachinesPerNode[$_] -lt $min) {
                $bestNodeName = $_
                $min = $virtualMachinesPerNode[$_]
            }
        }

        $result | Add-Member -Type NoteProperty -Name $BestNodePropertyName -Value (GetServerFqdn $bestNodeName)

        return $result
    } finally {
        Remove-Variable -Name vmResourceTypeName -Scope Local -Force
        Remove-Variable -Name OwnerNodePropertyName -Scope Local -Force
    }
}

<#

.SYNOPSIS
Main

.DESCRIPTION
Use the various mechanism available to determine the best host node.

#>

function main() {
    if (isClusterCimProviderAvailable) {
        $bestNode = askClusterServiceForBestHostNode
        if (!!$bestNode) {
            return $bestNode
        }
    }

    if (getIsClusterCmdletsAvailable) {
        return getLeastLoadedNode
    } else {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Warning `
            -Message "[$ScriptName]: The required PowerShell module (FailoverClusters) was not found."  -ErrorAction SilentlyContinue

        Write-Warning $strings.FailoverClustersModuleRequired
    }

    return $null
}

###############################################################################
# Script execution begins here.
###############################################################################

if (-not ($env:pester)) {
    setupScriptEnv

    try {
        Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

        $result = main
        if (!!$result) {
            return $result
        }

        # If neither cluster CIM provider or PowerShell cmdlets are available then simply
        # return this computer's name as the best host node...
        $nodeName = GetServerFqdn $env:COMPUTERNAME

        $result = newResult @($nodeName)
        $result | Add-Member -Type NoteProperty -Name $BestNodePropertyName -Value $nodeName

        return $result
    } finally {
        cleanupScriptEnv
    }
}

}
## [END] Get-WACVMHyperVBestHostNode ##
function Get-WACVMHyperVHostSettings {
<#

.SYNOPSIS
Gets a computer's Hyper-V Host General settings.

.DESCRIPTION
Gets a computer's Hyper-V Host General settings.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

<#

.SYNOPSIS
WindowsServerVersion

.DESCRIPTION
This enum is used for various Windows Server versions.

#>
enum WindowsServerVersion
{
    Unknown
    Server2008R2
    Server2012
    Server2012R2
    Server2016
    Server2019
}

<#

.SYNOPSIS
HypervisorSchedulerType

.DESCRIPTION
The Hypervisor scheduler type that is in effect on this host server.

#>

enum HypervisorSchedulerType {
    Unknown = 0
    ClassicSmtDisabled = 1
    Classic = 2
    Core = 3
    Root = 4
}

###############################################################################
# Constants
###############################################################################

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.  Create read only (constant) variables
that add context to the said constants.

#>

function setupScriptEnv() {
    ##SkipCheck=true##
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-HyperVHostSettings.ps1" -Scope Script
    Set-Variable -Name VirtualHardDiskPathPropertyName -Option ReadOnly -Value "VirtualHardDiskPath" -Scope Script
    Set-Variable -Name VirtualMachinePathPropertyName -Option ReadOnly -Value "VirtualMachinePath" -Scope Script
    Set-Variable -Name EnableEnhancedSessionModePropertyName -Option ReadOnly -Value "EnableEnhancedSessionMode" -Scope Script
    Set-Variable -Name MaximumVirtualMachineMigrationsPropertyName -Option ReadOnly -Value "MaximumVirtualMachineMigrations" -Scope Script
    Set-Variable -Name VirtualMachineMigrationAuthenticationTypePropertyName -Option ReadOnly -Value "VirtualMachineMigrationAuthenticationType" -Scope Script
    Set-Variable -Name VirtualMachineMigrationEnabledPropertyName -Option ReadOnly -Value "VirtualMachineMigrationEnabled" -Scope Script
    Set-Variable -Name VirtualMachineMigrationPerformanceOptionPropertyName -Option ReadOnly -Value "VirtualMachineMigrationPerformanceOption" -Scope Script
    Set-Variable -Name NumaSpanningEnabledPropertyName -Option ReadOnly -Value "NumaSpanningEnabled" -Scope Script
    Set-Variable -Name MaximumStorageMigrationsPropertyName -Option ReadOnly -Value "MaximumStorageMigrations" -Scope Script
    Set-Variable -Name Smt2016PatchInstalledPropertyName -Option ReadOnly -Value "smt2016PatchInstalled" -Scope Script
    Set-Variable -Name SchedulerTypePropertyName -Option ReadOnly -Value "schedulerType" -Scope Script
    Set-Variable -Name HypervisorEventChannelName -Option ReadOnly -Value "Microsoft-Windows-Hyper-V-Hypervisor" -Scope Script
    Set-Variable -Name Server2008R2BuildNumber -Option ReadOnly -Value 7600 -Scope Script
    Set-Variable -Name Server2012BuildNumber -Option ReadOnly -Value 9200 -Scope Script
    Set-Variable -Name Server2012R2BuildNumber -Option ReadOnly -Value 9600 -Scope Script
    Set-Variable -Name Server2016BuildNumber -Option ReadOnly -Value 14393 -Scope Script
    Set-Variable -Name Server2019BuildNumber -Option ReadOnly -Value 17763  -Scope Script
    Set-Variable -Name ClassicSmtDisabled -Option ReadOnly -Value "0x1" -Scope Script
    Set-Variable -Name Classic -Option ReadOnly -Value "0x2" -Scope Script
    Set-Variable -Name Core -Option ReadOnly -Value "0x3" -Scope Script
    Set-Variable -Name Root -Option ReadOnly -Value "0x4" -Scope Script
    Set-Variable -Name UseAnyNetworkForMigrationArgumentName -Option ReadOnly -Value "UseAnyNetworkForMigration" -Scope Script
##SkipCheck=false##
}

<#

.SYNOPSIS
Cleanup the script environment.

.DESCRIPTION
Cleanup the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name VirtualHardDiskPathPropertyName -Scope Script -Force
    Remove-Variable -Name VirtualMachinePathPropertyName -Scope Script -Force
    Remove-Variable -Name EnableEnhancedSessionModePropertyName -Scope Script -Force
    Remove-Variable -Name MaximumVirtualMachineMigrationsPropertyName -Scope Script -Force
    Remove-Variable -Name VirtualMachineMigrationAuthenticationTypePropertyName -Scope Script -Force
    Remove-Variable -Name VirtualMachineMigrationEnabledPropertyName -Scope Script -Force
    Remove-Variable -Name VirtualMachineMigrationPerformanceOptionPropertyName -Scope Script -Force
    Remove-Variable -Name NumaSpanningEnabledPropertyName -Scope Script -Force
    Remove-Variable -Name MaximumStorageMigrationsPropertyName -Scope Script -Force
    Remove-Variable -Name Smt2016PatchInstalledPropertyName -Scope Script -Force
    Remove-Variable -Name SchedulerTypePropertyName -Scope Script -Force
    Remove-Variable -Name HypervisorEventChannelName -Scope Script -Force
    Remove-Variable -Name Server2008R2BuildNumber -Scope Script -Force
    Remove-Variable -Name Server2012BuildNumber -Scope Script -Force
    Remove-Variable -Name Server2012R2BuildNumber -Scope Script -Force
    Remove-Variable -Name Server2016BuildNumber -Scope Script -Force
    Remove-Variable -Name Server2019BuildNumber -Scope Script -Force
    Remove-Variable -Name ClassicSmtDisabled -Scope Script -Force
    Remove-Variable -Name Classic -Scope Script -Force
    Remove-Variable -Name Core -Scope Script -Force
    Remove-Variable -Name Root -Scope Script -Force
    Remove-Variable -Name UseAnyNetworkForMigrationArgumentName -Scope Script -Force
}

<#

.SYNOPSIS
Get the the build number for the OS installed on this server.

.DESCRIPTION
Get the the build number for the OS installed on this server.

#>

function getBuildNumber {
    return [System.Environment]::OSVersion.Version.Build
}

<#

.SYNOPSIS
Get the Windows Server version for the OS installed on this server.

.DESCRIPTION
Get the Windows Server version for the OS installed on this server.

#>

function getServerVersion {
    $build = getBuildNumber

    if ($build -eq $Server2008R2BuildNumber) {
        return [WindowsServerVersion]::Server2008R2
    }

    if ($build -eq $Server2012BuildNumber) {
        return [WindowsServerVersion]::Server2012
    }

    if ($build -eq $Server2012R2BuildNumber) {
        return [WindowsServerVersion]::Server2012R2
    }

    if ($build -eq $Server2016BuildNumber) {
        return [WindowsServerVersion]::Server2016
    }

    #TODO: This isn't right.  Need to update with 2019 build number once known.
    if ($build -ge $Server2019BuildNumber) {
        return [WindowsServerVersion]::Server2019
    }

    return [WindowsServerVersion]::Unknown
}

<#

.SYNOPSIS
Determine if this Windows Server 2016 server has been patched.

.DESCRIPTION
Returns true if the patch for CVE-2018-3646 has been installed on this Windows 2016 server.

#>

function isServer2016Patched {
    $event = Get-WinEvent -FilterHashTable @{ProviderName = $HypervisorEventChannelName; ID = 156}  -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object -First 1

    return !!$event
}

<#

.SYNOPSIS
Get the Hypervisor scheduler type for this server.

.DESCRIPTION
Convert the event string value into an enum that is the current Hypervisor scheduler type.

The message looks like this:

 "Hypervisor scheduler type is 0x1."

 Since the hex value is all we care about this localized message should not be a problem...

#>

function getSchedulerType {
    $event = Get-WinEvent -FilterHashTable @{ProviderName = $HypervisorEventChannelName; ID = 2} -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object -First 1 Message

    # $event.message may not exist on downlevel servers
    if ($null -ne $event -AND $null -ne $event.message) {

        if ($event.message -match $ClassicSmtDisabled) {
            return [HypervisorSchedulerType]::ClassicSmtDisabled
        }

        if ($event.message -match $Classic) {
            return [HypervisorSchedulerType]::Classic
        }

        if ($event.message -match $Core) {
            return [HypervisorSchedulerType]::Core
        }

        if ($event.message -match $Root) {
            return [HypervisorSchedulerType]::Root
        }
    }

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: The Hyper-V scheduler type could not be determined. The event that contains the scheduler type was not found in event log $HypervisorEventChannelName."  -ErrorAction SilentlyContinue

    return [HypervisorSchedulerType]::Unknown
}

<#

.SYNOPSIS
Main

.DESCRIPTION
An explicit main function to fetch the settings.

#>

function main() {
    $schedulerType = getSchedulerType
    $serverVersion = getServerVersion
    $isServer2016Patched = $null

    if ($serverVersion -eq [WindowsServerVersion]::Server2016) {
        $isServer2016Patched = isServer2016Patched
    }

    $retValue =  Get-VMHost -ErrorAction SilentlyContinue -ErrorVariable +err | Microsoft.PowerShell.Utility\Select-Object `
        $EnableEnhancedSessionModePropertyName, `
        $VirtualHardDiskPathPropertyName, `
        $VirtualMachinePathPropertyName, `
        $MaximumVirtualMachineMigrationsPropertyName, `
        $VirtualMachineMigrationAuthenticationTypePropertyName, `
        $VirtualMachineMigrationEnabledPropertyName, `
        $VirtualMachineMigrationPerformanceOptionPropertyName, `
        $NumaSpanningEnabledPropertyName, `
        $MaximumStorageMigrationsPropertyName, `
        $UseAnyNetworkForMigrationArgumentName, `
        @{ Name = $Smt2016PatchInstalledPropertyName; Expression = { $isServer2016Patched }}, `
        @{ Name = $SchedulerTypePropertyName; Expression = { $schedulerType }}

    if ($err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Could not get the Hyper-V host settings. Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return $null
    }

    return $retValue
}

###############################################################################
# Script execution starts here...
###############################################################################

if (-not ($env:pester)) {
    setupScriptEnv

    try {
        Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

        $hyperVModule = Get-Module -Name Hyper-V -ErrorAction SilentlyContinue

        if (-not($hyperVModule)) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: The required PowerShell module (Hyper-V) was not found." -ErrorAction SilentlyContinue
        
            Write-Error $strings.HyperVModuleRequired
            
            return $null
        }

        return main
    
    } finally {
        cleanupScriptEnv
    }
}

}
## [END] Get-WACVMHyperVHostSettings ##
function Get-WACVMHyperVLiveMigrationSupported {
<#

.SYNOPSIS
Get this computer's Hyper-V live migration is supported or not

.DESCRIPTION
Get this computer's Hyper-V live migration is supported or not

.ROLE
Readers

#>

Set-StrictMode -Version 5.0

Import-Module Microsoft.PowerShell.Utility
Import-Module CimCmdlets

# Class is documented at https://docs.microsoft.com/en-us/windows/win32/hyperv_v2/msvm-virtualsystemmigrationsettingdata
# MigrationType = VirtualSystem (32768): Migrates the virtual system to the destination host.
$virtualSystem = 32768
$query = "Associators of {Msvm_VirtualSystemMigrationCapabilities.InstanceID=""Microsoft:MigrationCapabilities""} where resultclass = Msvm_VirtualSystemMigrationSettingData"
$instances = Get-CimInstance -Namespace root\virtualization\v2 -Query $query -ErrorAction SilentlyContinue
$state = 'NotSupported'
if ($null -ne $instances) {
    foreach ($instance in $instances) {
        if ($instance.MigrationType -eq $virtualSystem) {
            $state = 'Available'
        }
    }
}

@{ State = $state; Message =''; }
}
## [END] Get-WACVMHyperVLiveMigrationSupported ##
function Get-WACVMHyperVPhysicalDisks {
<#
.SYNOPSIS
Gets one or more disks visible to the operating system.

.DESCRIPTION
Returns physical disk objects like basic disks and partitioned drive partitions.

.ROLE
Readers
#>

$disks = Get-Disk

$disks = $disks | ForEach-Object {
  $disk = @{
    DiskNumber = $_.Number;
    DiskPath = $_.Path;
    DiskSize = $_.Size;
    IsDiskOffline = $_.IsOffline;
    IsDiskBoot = $_.IsBoot;
    IsDiskClustered = $_.IsClustered;
    IsDiskReadOnly = $_.IsReadOnly;
    DiskFriendlyName = $_.FriendlyName;
    DiskPartitionStyle = $_.PartitionStyle;
  }
  return $disk
}

$disks


}
## [END] Get-WACVMHyperVPhysicalDisks ##
function Get-WACVMHyperVPowerShellSupportInstalled {
<#

.SYNOPSIS
Checks if the server has the Hyper-V-Powershell feature is installed.

.DESCRIPTION
Checks if the server has the Hyper-V-Powershell feature is installed.  Returns true when installed.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0;
Import-Module Hyper-V -ErrorAction SilentlyContinue;
 
$cmdletInfo = get-command "get-vm" -ErrorAction SilentlyContinue

return ($cmdletInfo -and $cmdletInfo.Name -eq "get-vm");

}
## [END] Get-WACVMHyperVPowerShellSupportInstalled ##
function Get-WACVMHyperVRemoteDesktopSettings {
<#

.SYNOPSIS
    Name: Get-HyperVRemoteDesktopSettings
    Description: Gets remote desktop settings on target node.

.DESCRIPTION
Get the server events from this server.
The supported Operating Systems are Window Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0

function Get-fDenyTSConnectionsValue() {
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'

    $exists = Get-ItemProperty -Path $key -Name fDenyTSConnections -ErrorAction SilentlyContinue
    if (($null -ne $exists) -and ([bool]($exists.PSobject.Properties.name -match "fDenyTSConnections")))
    {
        $keyValue = $exists.fDenyTSConnections
        return $keyValue
    }
}

function Get-UserAuthentication() {
  $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'

  $exists = Get-ItemProperty -Path $key -Name UserAuthentication -ErrorAction SilentlyContinue
  if (($null -ne $exists) -and ([bool]($exists.PSobject.Properties.name -match "UserAuthentication")))
  {
      $keyValue = $exists.UserAuthentication
      return $keyValue
  }
}

function Get-PortNumber() {
  $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'

  $exists = Get-ItemProperty -Path $key -Name PortNumber -ErrorAction SilentlyContinue
  if (($null -ne $exists) -and ([bool]($exists.PSobject.Properties.name -match "PortNumber")))
  {
      $keyValue = $exists.PortNumber
      return $keyValue
  }
}

$UserAuthentication = Get-UserAuthentication
$fDenyTSConnections = Get-fDenyTSConnectionsValue
$PortNumber = Get-PortNumber

$result = New-Object -TypeName PSObject
$result | Add-Member -MemberType NoteProperty -Name "allowRemoteDesktop" $(if ($fDenyTSConnections -eq 0) { $true } else { $false })
$result | Add-Member -MemberType NoteProperty -Name "allowRemoteDesktopWithNLA" $(if ($UserAuthentication -eq 1) { $true } else { $false })
$result | Add-Member -MemberType NoteProperty -Name "portNumber" $PortNumber

$result

}
## [END] Get-WACVMHyperVRemoteDesktopSettings ##
function Get-WACVMHyperVRoleInstalled {
<#

.SYNOPSIS
Checks if the server has the Hyper-V role installed.

.DESCRIPTION
Checks if the server has the Hyper-V role installed.  Returns true when installed.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0;
 
$service = Microsoft.PowerShell.Management\Get-Service -Name "VMMS" -ErrorAction SilentlyContinue;

return ($service -and $service.Name -eq "VMMS");

}
## [END] Get-WACVMHyperVRoleInstalled ##
function Get-WACVMHyperVSETSupported {
<#

.SYNOPSIS
Checks if the server supports Hyper-V Switch Embedded Teaming (SET).

.DESCRIPTION
Checks if the server supports Hyper-V Switch Embedded Teaming (SET). Returns true when supported.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

BEGIN {
    Set-StrictMode -Version 5.0

    Import-Module CimCmdlets -ErrorAction SilentlyContinue
    Import-Module Hyper-V -ErrorAction SilentlyContinue

    Set-Variable -Name CimV2Namespace -Option ReadOnly -Value "root/cimv2" -Scope Script
    ##SkipCheck=true##
    Set-Variable -Name ProductTypeQuery -Option ReadOnly -Value "select ProductType from Win32_OperatingSystem" -Scope Script
    ##SkipCheck=false##
    Set-Variable -Name SetVMSwitchTeamCmdletName -Option ReadOnly -Value "Set-VMSwitchTeam" -Scope Script

    enum ProductType {
        WorkStation = 1
        DomainController = 2
        Server = 3
    }
}
PROCESS {
    $cmdletInfo = Get-Command $SetVMSwitchTeamCmdletName -ErrorAction SilentlyContinue
    $hyperVToolsPresent = ($cmdletInfo -and $cmdletInfo.Name -eq $SetVMSwitchTeamCmdletName)

    $cs = Get-CimInstance -Namespace $CimV2Namespace -Query $ProductTypeQuery
    $isServerSku = $cs.ProductType -ne [ProductType]::WorkStation
    
    return ($hyperVToolsPresent -and $isServerSku) 
}
END {
    Remove-Variable -Name CimV2Namespace -Scope Script -Force
    Remove-Variable -Name ProductTypeQuery -Scope Script -Force
    Remove-Variable -Name SetVMSwitchTeamCmdletName -Scope Script -Force
}

}
## [END] Get-WACVMHyperVSETSupported ##
function Get-WACVMHyperVStorageMigrationSupported {
<#

.SYNOPSIS
Get this computer's Hyper-V storage migration is supported or not

.DESCRIPTION
Get this computer's Hyper-V storage migration is supported or not

.ROLE
Readers

#>

Set-StrictMode -Version 5.0

$migrationSettingsDatas=Microsoft.PowerShell.Management\Get-WmiObject -Namespace root\virtualization\v2 -Query "associators of {Msvm_VirtualSystemMigrationCapabilities.InstanceID=""Microsoft:MigrationCapabilities""} where resultclass = Msvm_VirtualSystemMigrationSettingData"

$storage = $false;

foreach ($migrationSettingsData in $migrationSettingsDatas) {
    if ($migrationSettingsData.MigrationType -eq 32769) {
        $storage = $true;
    }
}

if ($storage) {
    @{ State = 'Available'; Message ='' }
} else {
    @{ State = 'NotSupported'; Message ='' }
}
}
## [END] Get-WACVMHyperVStorageMigrationSupported ##
function Get-WACVMIsSLBConfigured {
<#

.SYNOPSIS
Gets whether SLB is configured

.DESCRIPTION
Gets whether SLB is configured

.ROLE
Readers

.PARAMETER uri
The uri used to connect to the SDN Network controller
#>

param (
	[Parameter(Mandatory = $true)]
	[String]
  $uri
)
Import-Module NetworkController
Set-StrictMode -Version 5.0

try {
  Get-NetworkControllerLoadBalancerConfiguration -ConnectionUri $uri
  $true
} catch {
  $false
}

}
## [END] Get-WACVMIsSLBConfigured ##
function Get-WACVMLiveIOData {
<#

.SYNOPSIS
Gets the live I/O performance data for the volumes of a cluster.

.DESCRIPTION
Gets the live I/O performance data for the volumes of a cluster.

.ROLE
Readers

#>

# disabling this until there is a way to get output from get-storagehealthreport in strict mode
# Set-Strict -Version 5.0
Import-Module CimCmdlets;

###############################################################################
# Constants
###############################################################################
Set-Variable TimeRangeCurrentValue -Option Constant -Value 5 -ErrorAction SilentlyContinue
Set-Variable MsConversion -Option Constant -Value 1000 -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Reset old data and set the first one.

.DESCRIPTION
Reset last 60 second values and set the first one with current value

.PARAMETER dataValues
The hashtable format of current value of each performance measurement.

#>
function ResetData {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]
        $dataValues
    )

    $Global:IopsData = [System.Collections.ArrayList]@()
    $Global:ThroughputData = [System.Collections.ArrayList]@()
    $Global:LatencyData = [System.Collections.ArrayList]@()
    for ($i = 0; $i -lt 59; $i++) {
        $Global:IopsData.Insert(0, 0)
        $Global:ThroughputData.Insert(0, 0)
        $Global:LatencyData.Insert(0, 0)
    }

    $Global:IopsData.Insert(0, $dataValues.iops)
    $Global:ThroughputData.Insert(0, $dataValues.throughput)
    $Global:LatencyData.Insert(0, $dataValues.latency)

    $Global:Delta = 0
}

<#

.SYNOPSIS
Update data with current value.

.DESCRIPTION
Using current data to fill gap every second from current to last sampe data

.PARAMETER dataValues
The hashtable format of current value of each performance measurement.

#>
function UpdateData {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]
        $dataValues
    )

    $Global:Delta += ($Global:SampleTime - $Global:LastTime).TotalMilliseconds

    while ($Global:Delta -gt 1000) {
        $Global:Delta -= 1000

        [void]$Global:IopsData.Insert(0,$dataValues.iops)
        [void]$Global:LatencyData.Insert(0,$dataValues.latency)
        [void]$Global:ThroughputData.Insert(0,$dataValues.throughput)
    }

    $Global:IopsData = $Global:IopsData.GetRange(0, 60)
    $Global:LatencyData = $Global:LatencyData.GetRange(0, 60)
    $Global:ThroughputData = $Global:ThroughputData.GetRange(0, 60)
}

<#

.SYNOPSIS
Determines if Britannica (sddc management resources) are available on the cluster

.DESCRIPTION
Use the existance of the cim namespace root/sddc to determine if Britannica 
is supported or not.

#>
function isBritannicaEnabled() {
    return !!(Get-CimInstance -Namespace "root\SDDC\Management" -ClassName SDDC_Cluster -ErrorAction SilentlyContinue) 
}

<#

.SYNOPSIS
Are the cluster PowerShell Health report availabe on this server?

.DESCRIPTION
Are the cluster PowerShell Health report available on this server?

s#>
function isClusterHealthReportAvailable() {
    $report = $null
    if ((Get-Command Get-StorageSubSystem -ErrorAction SilentlyContinue) -and (Get-Command Get-StorageHealthReport -ErrorAction SilentlyContinue)) {
        $report = Get-StorageSubSystem -Model "Clustered Windows Storage" | Get-StorageHealthReport -ErrorAction Ignore
    }
    return !!$report
}

<#

.SYNOPSIS
Get current data from Britannica (sddc management resources)

.DESCRIPTION
Get iops, throughput and latency data value from Britannica 

#>
function getDataFromBritannica()
{
    $cluster = Get-CimInstance -Namespace "root\SDDC\Management" -ClassName SDDC_Cluster
    if (!$cluster) {
        return $null
    }

    $returnValues = @{}

    $iops = getMetrics $cluster "Volume.IOPS.Total"
    # In RS1 Britannica name space exists but GetMetrics return empty, in this case no need continue
    if (!$iops) {
        return $null
    }

    $returnValues.iops = $iops
    $returnValues.latency = getMetrics $cluster "Volume.Latency.Average" $MsConversion
    $returnValues.throughput = getMetrics $cluster "Volume.Throughput.Total"
    
    return $returnValues
} 

<#

.SYNOPSIS
Get data from Britannica metric (sddc management resources)

.DESCRIPTION
Get raw data through cim method "GetMetrics" with given seriesName and timeFrame 

.PARAMETER cluster
The PsObject of target cluster

.PARAMETER seriesName
The seriesName for query argument

.PARAMETER conversion
The conversion number for value adjustment. This parameter is optional, default is 1

#>
function getMetrics {
    param(
        [Parameter(Mandatory = $true)]
        [PsObject]
        $cluster,
        [Parameter(Mandatory = $true)]
        [string]
        $seriesName,
        [Parameter(Mandatory = $false)]
        [float]
        $conversion = 1 #default
    )

    if (!$cluster -or !$seriesName -or !$timeFrame) {
        return $null
    }

    $metric = $cluster | Invoke-CimMethod -MethodName "GetMetrics" -Arguments @{SeriesName = $seriesName; TimeFrame = [uint16]$TimeRangeCurrentValue}
    if ($metric.Metric -and $metric.Metric.Datapoints) {
        # remember current sample time stamp
        $Script:now = $metric.Metric.Datapoints[0].Timestamp
        return $metric.Metric.Datapoints[0].Value * $conversion
    } else {
        return $null
    }
}

<#

.SYNOPSIS
Get current data from cluster HealthReport

.DESCRIPTION
Get iops, throughput and latency data value from cluster HealthReport 

#>
function getDataFromHealthReport() {
    $returnValues = @{}
    $Script:now = get-date
    $storageHealthReport = Get-StorageSubSystem -Model "Clustered Windows Storage" | Get-StorageHealthReport
    if ($storageHealthReport -and $storageHealthReport[0].ItemValue -and $storageHealthReport[0].ItemValue.Records ) {
        $record = $storageHealthReport[0].ItemValue.Records
        $iopsResult = $record | Where {$_.Name -eq 'IOPSTotal'}
        $latencyResult = $record | Where {$_.Name -eq 'IOLatencyAverage'}
        $throughputResult = $record | Where {$_.Name -eq 'IOThroughputTotal'}
        
        # Value might be zero so $iopsResult.Value might be evaluated as $false
        if ($iopsResult -and ($null -ne $iopsResult.Value)) {
            $returnValues.iops = $iopsResult.Value
        }

        if ($latencyResult -and ($null -ne $latencyResult.Value)) {
            $returnValues.latency = $latencyResult.Value * $MsConversion
        }

        if ($throughputResult -and ($null -ne $throughputResult.Value)) {
            $returnValues.throughput = $throughputResult.Value
        }
    }

    return $returnValues
}

<#

.SYNOPSIS
Get live data

.DESCRIPTION
Get live data from the Britannica first if avaiable, then HealthReport, otherwise return null

#>
function getLiveData() {
    $data = $null
    if (isBritannicaEnabled) {
        $data = getDataFromBritannica
    }
    if (!$data -and (isClusterHealthReportAvailable)) {
        return getDataFromHealthReport
    }
    return $data
}

<#

.SYNOPSIS
Create sample data array list

.DESCRIPTION
Create sample data array list for last 60 seconds

.PARAMETER dataValues
The hashtable format of current value of each performance measurement.

#>
function createDataList {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]
        $dataValues
    )

    # get sampling time and remember last sample time.
    $globalExists = Get-Variable SampleTime -Scope Global -ErrorAction SilentlyContinue
    
    if (-not $globalExists) {
        $Global:SampleTime = $now
        $Global:LastTime = $Global:SampleTime

        ResetData $dataValues
    }
    else {
        $Global:LastTime = $Global:SampleTime
        $Global:SampleTime = $now

        if ($Global:SampleTime - $Global:LastTime -gt [System.TimeSpan]::FromSeconds(30)) {
            ResetData $dataValues
        }
        else {
            UpdateData $dataValues
        }
    }
}

###############################################################################
# Main
###############################################################################
$returnValues = getLiveData
if ($returnValues) {
    createDataList $returnValues

    $result = New-Object -TypeName PSObject
    $result | Add-Member -MemberType NoteProperty -Name "Iops" $Global:IopsData
    $result | Add-Member -MemberType NoteProperty -Name "Latency" $Global:LatencyData
    $result | Add-Member -MemberType NoteProperty -Name "Throughput" $Global:ThroughputData
    
    # return empty object will lead displaying empty chart
    return $result
} else { # return $null will delete the chart  
    return $null
}

}
## [END] Get-WACVMLiveIOData ##
function Get-WACVMLogicalNetworks {
<#

.SYNOPSIS
Gets the Logical Networks.

.DESCRIPTION
Gets the Logical Networks objects from the SDN Network Controller.

.ROLE
Readers

.PARAMETER uri
    The uri used to connect to the SDN Network controller
    
#>

param 
(
    [Parameter(Mandatory = $true)]
    [String]
    $uri
)

Set-StrictMode -Version 5.0;
Import-Module NetworkController;
Import-Module Microsoft.PowerShell.Management;

$Lnets = @(Get-NetworkControllerLogicalNetwork -ConnectionUri $uri)
$Lnets | ConvertTo-Json -depth 100 | ConvertFrom-Json
}
## [END] Get-WACVMLogicalNetworks ##
function Get-WACVMMemoryDownLevel {
<#

.SYNOPSIS
Gets a computer's memory usage perf counter data.

.DESCRIPTION
Gets a computer's memory usage perf counter data.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0
import-module CimCmdlets;

$memory = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory
$system = Get-CimInstance Win32_ComputerSystem

$result = New-Object -TypeName PSObject
$result | Add-Member -MemberType NoteProperty -Name "Total" $system.TotalPhysicalMemory
$result | Add-Member -MemberType NoteProperty -Name "InUse" ($system.TotalPhysicalMemory - $memory.AvailableBytes)
$result

}
## [END] Get-WACVMMemoryDownLevel ##
function Get-WACVMNICTypeMap {
<#

.SYNOPSIS
Gets a mapping of NIC adapter id to network type.

.DESCRIPTION
Gets a mapping of NIC adapter id to network type.

.ROLE
Readers

.PARAMETER vmId
    The ID of the VM for which you want to obtain the NIC types of.

.PARAMETER uri
    The URI of the SDN network controller.

#>
param (
  [Parameter(Mandatory = $true)]
  [String]
  $vmId
)

Import-Module Hyper-V -ErrorAction SilentlyContinue

function main(
  [string]$vmId
) {
  $vm = Get-RBACVM -Id $vmId -ErrorVariable err
  $vmNics = Get-VMNetworkAdapter -VM $vm -ErrorVariable +err

  if (!!$err) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
      -Message "[$ScriptName]: Couldn't get network adapters for the selected virtual machine. Error: $err" -ErrorAction SilentlyContinue

    Write-Error @($err)[0]
  }

  # 0 = None
  # 1 = Vlan
  # 2 = Vnet or Lnet
  $adapterNetworkTypeMap = @{ }
  foreach ($vmNic in $vmNics) {
    $currentFeature = Get-VMSwitchExtensionPortFeature -FeatureId "9940cd46-8b06-43bb-b9d5-93d50381fd56" -VMNetworkAdapter $vmNic -ErrorVariable +err

    if (!!$err) {
      Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Couldn't get port profile for the selected virtual machine network adapter. Error: $err" -ErrorAction SilentlyContinue

      Write-Error @($err)[0]
    }

    $adapterId = $vmNic.Id.Substring($vmNic.Id.IndexOf('\') + 1).ToLower()
    if ($null -eq $currentFeature) {
      # no port profile set = None
      $adapterNetworkTypeMap[$adapterId] = 0
    }
    elseif ($currentFeature.SettingData.ProfileData -eq 2) {
      # PortProfile = 2 means VLAN

      # See if it's a Default (None) new NIC case
      $vlanInfo = Get-VMNetworkAdapterVlan -VMNetworkAdapter $vmnic
      if ($vlanInfo.AccessVlanId -eq 0) {
        $adapterNetworkTypeMap[$adapterId] = 0
      }
      else {
        $adapterNetworkTypeMap[$adapterId] = 1
      }
    }
    elseif ($currentFeature.SettingData.ProfileData -eq 0) {
      # PortProfile = 0 means None
      $adapterNetworkTypeMap[$adapterId] = 0
    }
    elseif ($currentFeature.SettingData.ProfileData -eq 6) {
      # PortProfile = 6 means we're using LNET as VLAN with default network policies
      $adapterNetworkTypeMap[$adapterId] = 2
    }
    else {
      # If we have anything else, we want to check if there's a nic. Use 2 and determine whether it's Lnet or Vnet later
      $adapterNetworkTypeMap[$adapterId] = 2
    }
  }
  return $adapterNetworkTypeMap

}

###############################################################################
# Script execution starts here...
###############################################################################

Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
Set-Variable -Name LogSource -Option ReadOnly -Value "SMEGateway" -Scope Script
Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-NICTypeMap.ps1" -Scope Script

$value = main $vmId

Remove-Variable -Name LogName -Scope Script -Force
Remove-Variable -Name LogSource -Scope Script -Force
Remove-Variable -Name ScriptName -Scope Script -Force

return $value

}
## [END] Get-WACVMNICTypeMap ##
function Get-WACVMNetworkAdapters {
<#

.SYNOPSIS
Get the physical network adapters of the server.

.DESCRIPTION
Gets the physical network adapters of the server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0
Import-Module Microsoft.PowerShell.Management -ErrorAction SilentlyContinue
Import-Module NetAdapter -ErrorAction SilentlyContinue
Import-Module Hyper-V -ErrorAction SilentlyContinue

enum InterfaceOperationalStatus {
    Up = 1
    Down = 2
    Testing = 3
    Unknown = 4
    Dormant = 5
    NotPresent = 6
    LowerlayerDown = 7
}

<#

.SYNOPSIS
Setup script runtime environment.

.DESCRIPTION
Setup script runtime environment.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-NetworkAdapters" -Scope Script
    Set-Variable -Name VirtualAdapterInterfaceDescription -Option ReadOnly -Value "Hyper-V Virtual Ethernet Adapter" -Scope Script
    Set-Variable -Name NetAdapterInterfaceDescriptions -Option ReadOnly -Value "NetAdapterInterfaceDescriptions" -Scope Script
    Set-Variable -Name NetAdapterInterfaceDescription -Option ReadOnly -Value "NetAdapterInterfaceDescription" -Scope Script
}

<#

.SYNOPSIS
Cleanup script runtime environment.

.DESCRIPTION
Cleanup script runtime environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name VirtualAdapterInterfaceDescription -Scope Script -Force
    Remove-Variable -Name NetAdapterInterfaceDescriptions -Scope Script -Force
    Remove-Variable -Name NetAdapterInterfaceDescription -Scope Script -Force
}

<#

.SYNOPSIS
Main function of this script.

.DESCRIPTION
Main function of this script.

#>

function main() {
    $models = @()

    $module = Get-Module NetAdapter -ErrorAction SilentlyContinue -ErrorVariable +err
    if (-not($module)) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: The required PowerShell module (NetAdapter) was not found."  -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return $models;
    }

    $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue -ErrorVariable +err | Where-Object { $_.InterfaceDescription -notmatch $VirtualAdapterInterfaceDescription })
    if ($err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Couldn't get the network adapters of this server. Error: $err"  -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return $models;
    }

    $err = $null

    $virtualSwitchesArray = @(Get-VMSwitch -ErrorAction SilentlyContinue -ErrorVariable +err)
    if ($err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Couldn't get the virtual switches of this server. Error: $err"  -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return $models;
    }

    $virtualSwitchesHash = @{}

    $ipConfig = $null

    # Build a hash table of interface descriptions to virtual switches.
    foreach ($switch in $virtualSwitchesArray) {
        # If not a Switch Enabled Team (SET) switch use the NetAdapterInterfaceDescription property.
        # If it is a SET switch use the NetAdapterInterfaceDescriptions array property.
        if ($switch.PSObject.Properties.Match($NetAdapterInterfaceDescriptions).Count -eq 0) {
            if ($switch.$NetAdapterInterfaceDescription) {
                $virtualSwitchesHash += @{ $switch.$NetAdapterInterfaceDescription = $switch }
            }
        } else {
            foreach($interfaceDescription in $switch.$NetAdapterInterfaceDescriptions) {
                $virtualSwitchesHash += @{$interfaceDescription = $switch }
            }
        }
    }

    foreach ($adapter in $adapters) {
        $physicalAdapterNotPreset = $adapter.InterfaceOperationalStatus -eq [InterfaceOperationalStatus]::NotPresent

        if ($physicalAdapterNotPreset) {
            continue
        }

        $attachedToSwitch = !![bool]($virtualSwitchesHash[$adapter.InterfaceDescription])

        # resets error every time, to ensure that each error in the for loop can be logged separately.
        # to prevent the summed up error to be greater than max characters limitation from Microsoft.PowerShell.Management\Write-EventLog
        $err = $null;

        if (!$attachedToSwitch) {
            try {
                # find matched ip configuration by InterfaceIndex.
                $ipConfig = Get-NetIPConfiguration -ErrorAction SilentlyContinue -ErrorVariable +err | Where-Object { $_.InterfaceIndex -eq $adapter.InterfaceIndex }
            } catch
            {
                $err = $_.Exception.Message
            }

            if ($err) {
                Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                    -Message "[$ScriptName]: Couldn't get the IP configuration for $adapter.Name. Error: $err"  -ErrorAction SilentlyContinue
            }
        } else {
            $ipConfig = $null
        }

        $properties = @{
            'ifDesc' = $adapter.ifDesc;
            'LinkSpeed' = $adapter.LinkSpeed;
            'MediaConnectionState' = $adapter.MediaConnectionState;
            'Name' = $adapter.Name;
            'MacAddress' = $adapter.MacAddress;
            'IsAttachedToVirtualSwitch' = $attachedToSwitch;
        }

        if ($ipConfig) {
            $v4AddressProperties = @{}

            # It is possible to not always get a v4 address record...
            if ($ipConfig.IPv4Address) {
                $v4AddressProperties += @{
                'IPAddress' = $ipConfig.IPv4Address.IPAddress;
                'PrefixLength' = $ipConfig.IPv4Address.PrefixLength;
                }
            }

            $v4Address = New-Object psobject -Prop $v4AddressProperties

            $v6AddressProperties = @{}

            # It is possible to not always get a v6 address record...
            if ($ipConfig.IPv6Address) {
                $v6AddressProperties += @{
                'IPAddress' = $ipConfig.IPv6Address.IPAddress;
                'PrefixLength' = $ipConfig.IPv6Address.PrefixLength;
                }
            }

            $v6Address = New-Object psobject -Prop $v6AddressProperties;

            $properties += @{
                'IPv4Address' = $v4Address;
                'IPv6Address' = $v6Address;
            }
        } else {
            $properties += @{
                'IPv4Address' = '';
                'IPv6Address' = '';
            }
        }

        $model = New-Object psobject -Prop $properties
        $models += $model
    }

    return $models
}

###############################################################################
# Script execution starts here...
###############################################################################
setupScriptEnv

try {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    $module = Get-Module Hyper-V -ErrorAction SilentlyContinue -ErrorVariable +err
    if ($module) {
        return main
    }

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: The required PowerShell module (Hyper-V) was not found."  -ErrorAction SilentlyContinue

    Write-Error @($err)[0]

    return @()
} finally {
    cleanupScriptEnv
}

}
## [END] Get-WACVMNetworkAdapters ##
function Get-WACVMNetworkInterfaces {
<#

.SYNOPSIS
Gets the Network Interfaces.

.DESCRIPTION
Gets the Network Interface objects from the SDN Network Controller

.ROLE
Readers

.PARAMETER uri
    The uri used to connect to the SDN Network controller

#>

param (
		[Parameter(Mandatory = $true)]
		[String]
        $uri
)

Set-StrictMode -Version 5.0;
Import-Module NetworkController;

$nics = @(Get-NetworkControllerNetworkInterface -ConnectionUri $uri)
$nics | ConvertTo-Json -depth 100 | ConvertFrom-Json

}
## [END] Get-WACVMNetworkInterfaces ##
function Get-WACVMNetworkInterfacesForVMAdapters {
<#
.SYNOPSIS
Gets the Network Interfaces and Public IPs for a VM

.DESCRIPTION
Gets the Network Interface objects from the SDN Network Controller, mapped to the network adapter which they correspond to
And gets the Public IP objects associated with the Network Interface objects

.ROLE
Readers

.PARAMETER uri
    The uri used to connect to the SDN Network controller

.PARAMETER vmNics
    The VMNetworkAdapter objects for which to get SDN Network Interfaces

.PARAMETER map
    A hashtable of VMNetworkAdapter ID's to the port profile ID of that adapter
#>

param (
  [Parameter(Mandatory = $true)]
  [String]
  $uri,
  [Parameter(Mandatory = $true)]
  [object[]] # Array of VMNetworkAdapter objects. Powershell can't find the type, so keep generic for now
  $vmNics,
  [Parameter(Mandatory = $true)]
  [PSCustomObject] # Hashtable of VMNetworkAdapter ID's and port profile ID
  $map
)

Set-StrictMode -Version 5.0;
Import-Module NetworkController;
Import-Module Microsoft.PowerShell.Management;

<#

.SYNOPSIS
Setup script runtime environment.

.DESCRIPTION
Setup script runtime environment.

#>

function setupScriptEnv() {
  Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-NetworkInterfacesForVMAdapters.ps1" -Scope Script
  Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
  Set-Variable -Name LogSource -Option ReadOnly -Value "SMEGateway" -Scope Script
  Set-Variable -Name DefaultMac -Option ReadOnly -Value "000000000000" -Scope Script
  Set-Variable -Name ReturnJsonDepth -Option ReadOnly -Value 10 -Scope Script
}

<#

.SYNOPSIS
Cleanup script runtime environment.

.DESCRIPTION
Cleanup script runtime environment.

#>

function cleanupScriptEnv() {
  Remove-Variable -Name ScriptName -Scope Script -Force
  Remove-Variable -Name LogName -Scope Script -Force
  Remove-Variable -Name LogSource -Scope Script -Force
  Remove-Variable -Name DefaultMac -Scope Script -Force
  Remove-Variable -Name ReturnJsonDepth -Scope Script -Force
}

function resolvePnicToNcNic(
  [Microsoft.Windows.NetworkController.NetworkInterface[]]$ncNics,
  [object]$adapter,
  [object]$profileId
) {
  $adapterId = $adapter.Id.Substring($adapter.Id.IndexOf('\') + 1)
  $macAddress = $adapter.MacAddress

  $ncNics | ForEach-Object -Process {
    $nic = $_
    $returnFormatNic = $nic | ConvertTo-Json -Depth $ReturnJsonDepth | ConvertFrom-Json

    if ("{$($nic.InstanceId)}" -eq $profileId) {
      return $returnFormatNic
    }

    if ($macAddress -ne $DefaultMac -and $nic.Properties.psobject.properties.name -contains "PrivateMacAddress" -and $nic.Properties.PrivateMacAddress -eq $macAddress) {
      return $returnFormatNic
    }

    $tags = $nic.Tags
    if ($null -ne $tags -and $tags.psobject.properties.name -contains "adapterId" -and $nic.Tags.adapterId.ToLower() -eq $adapterId.ToLower()) {
      return $returnFormatNic
    }
  }
}

###############################################################################
# Script execution starts here
###############################################################################

$nicMap = @{}
$nics = $null
$pips = @()
setupScriptEnv

$nics = Get-NetworkControllerNetworkInterface -ConnectionUri $uri -ErrorVariable err

if (!!$err) {
  Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
    -Message "[$ScriptName]: Couldn't get SDN network interfaces. Error: $err" -ErrorAction SilentlyContinue

  Write-Error @($err)[0]
}

if ($null -ne $vmNics -and $vmNics.length -gt 0) {
  foreach ($vmNic in $vmNics) {
    $portProfileId = $map.($vmNic.Id)

    $adapterId = $vmNic.Id.Substring($vmNic.Id.IndexOf('\') + 1).ToLower()
    $nicMap[$adapterId] = resolvePnicToNcNic -adapter $vmNic -profileId $portProfileId -ncNics @($nics)

    $currentNic = $nicMap[$adapterId]
    if ($null -ne $currentNic) {
      $ipConfigs = $currentNic.properties.ipConfigurations
      if ($null -ne $ipConfigs) {
        foreach ($ipConfig in $ipConfigs) {
          $currentPip = $ipConfig.properties.publicIPAddress
          if ($null -ne $currentPip) {
            $ref = $currentPip.resourceRef -split '/'
            $id = $ref[$ref.length - 1]
            $pip = Get-NetworkControllerPublicIpAddress -ConnectionUri $uri -ResourceId $id | ConvertTo-Json | ConvertFrom-Json
            $pips += $pip
          }
        }
      }
    }
  }
}

cleanupScriptEnv
$nicMap
$pips

}
## [END] Get-WACVMNetworkInterfacesForVMAdapters ##
function Get-WACVMPortProfileMap {

<#

.SYNOPSIS
The main function.

.DESCRIPTION
Gets a mapping of physical NIC adapter ID to port profile ID.

.ROLE
Hyper-V-Administrators

.PARAMETER vmId
    The ID of the VM for which you want to obtain the NIC port profiles IDs of.

#>

param (
  [Parameter(Mandatory = $true)]
  [String]
  $vmId
)

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue

function getPortProfileMap(
  [Microsoft.HyperV.PowerShell.VMNetworkAdapter[]]$vmNics
) {
  $portProfileMap = @{}

  foreach ($vmNic in $vmNics) {
    $currentFeature = $null
    try {
      $currentFeature = Get-VMSwitchExtensionPortFeature -FeatureId $PortId -VMNetworkAdapter $vmNic
    }
    catch {
      # Port feature not found - this is fine, log if there's an error thrown at some other point for tracing
      Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Could not find VMSwitchExtension Port Feature with the ID for port profile data" -ErrorAction SilentlyContinue
    }
    if ($null -eq $currentFeature) {
      $portProfileMap[$vmNic.Id] = $null
    }
    else {
      $portProfileMap[$vmNic.Id] = $currentFeature.SettingData.ProfileId
    }
  }

  $portProfileMap
}

function main(
  [string]$vmId
) {
  $vm = Get-RBACVM -Id $vmId -ErrorVariable err
  $vmNics = Get-VMNetworkAdapter -VM $vm -ErrorVariable +err

  if (!!$err) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
      -Message "[$ScriptName]: Couldn't retrieve selected virtual machine network adapters. Error: $err" -ErrorAction SilentlyContinue

    Write-Error @($err)[0]
  }

  $ret = [PSCustomObject]@{
    vmNics = $vmNics
    map    = getPortProfileMap $vmNics
  }

  $ret
}

###############################################################################
# Script execution starts here...
###############################################################################

Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
Set-Variable -Name LogSource -Option ReadOnly -Value "SMEGateway" -Scope Script
Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-PortProfileMap.ps1" -Scope Script
Set-Variable -Name PortId -Option ReadOnly -Value "9940cd46-8b06-43bb-b9d5-93d50381fd56" -Scope Script

$value = main $vmId

Remove-Variable -Name LogName -Scope Script -Force
Remove-Variable -Name LogSource -Scope Script -Force
Remove-Variable -Name ScriptName -Scope Script -Force
Remove-Variable -Name PortId -Scope Script -Force

return $value

}
## [END] Get-WACVMPortProfileMap ##
function Get-WACVMRootVHDPath {
<#
.SYNOPSIS
Travels up a VHD's ancestry path and retrieves the oldest parent

.DESCRIPTION
Implementation for fetching the root path of the supplied vhdx or avhdx file path

.ROLE
Hyper-V-Administrators

.PARAMETER $path
    The child path
#>

param(
	[Parameter(Mandatory = $true)]
	[String]
	$path
)

Set-StrictMode -Version 5.0

Import-Module Hyper-V -ErrorAction SilentlyContinue
Import-Module FailoverClusters -ErrorAction SilentlyContinue
Import-Module Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.  Create read only (constant) variables
that add context to the said constants.

#>

function setupScriptEnv() {
	Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
	Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
	Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-RootVHDPath.ps1" -Scope Script
	Set-Variable -Name HyperVModuleName -Option ReadOnly -Value "Hyper-V" -Scope Script
}

<#

.SYNOPSIS
Cleanup the script environment.

.DESCRIPTION
Cleanup the script environment.

#>

function cleanupScriptEnv() {
	Remove-Variable -Name LogName -Scope Script -Force
	Remove-Variable -Name LogSource -Scope Script -Force
	Remove-Variable -Name ScriptName -Scope Script -Force
	Remove-Variable -Name HyperVModuleName -Scope Script -Force
}

<#
.SYNOPSIS
Travels up a VHD's ancestry path and retrieves the oldest parent

.DESCRIPTION
Implementation for fetching the root path of the supplied vhdx or avhdx file path
 #>
function Get-RootVHDPath(
		[Parameter(Mandatory = $true)]
		[String]
		$path
) {
	while($path)
	{
		$parent = $path
		$vhd = Get-VHD -Path $path -ErrorAction SilentlyContinue

		if ($vhd -and $vhd.ParentPath) {
			$path = $vhd.ParentPath
		} else {
			return $parent
    }
	}
}

<#

.SYNOPSIS
Main

.DESCRIPTION
Implementation of getting a virtual hard disks root path

.PARAMETER path
	The child path whose root vhd path is being sought
#>

function main(
	[Parameter(Mandatory = $true)]
	[String]
	$path
) {
	return Get-RootVHDPath $path
}



###############################################################################
# Script execution starts here
###############################################################################

if (-not ($env:pester)) {
	setupScriptEnv

	try {
		Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

		$hyperVModule = Get-Module -Name $HyperVModuleName -ErrorAction SilentlyContinue

		if (-not($hyperVModule)) {
			Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
				-Message "[$ScriptName]: The required PowerShell module (Hyper-V) was not found." -ErrorAction SilentlyContinue

			Write-Error $strings.HyperVModuleRequired

			return $null
		}

		return main $path
	}
	finally {
		cleanupScriptEnv
	}
}

}
## [END] Get-WACVMRootVHDPath ##
function Get-WACVMSecurityTags {
<#

.SYNOPSIS
Gets a Security tag from a given network controller.

.DESCRIPTION
Gets a security tag object from the SDN Network Controller.

.ROLE
Readers

.PARAMETER uri
The uri used to connect to the SDN Network controller
#>

param (
  [Parameter(Mandatory = $true)]
  [String]
  $uri
)
Import-Module NetworkController;
Set-StrictMode -Version 5.0;

Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
Set-Variable -Name LogSource -Option ReadOnly -Value "SMEGateway" -Scope Script
Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-SecurityTags.ps1" -Scope Script

$result = @()
$tags = @(Get-NetworkControllerSecurityTag -ConnectionUri $uri -PassInnerException -ErrorVariable err)

if (!!$err) {
  Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
    -Message "[$ScriptName]: Couldn't retrieve security tags. Error: $err" -ErrorAction SilentlyContinue

  Write-Error @($err)[0]
}

foreach ($tag in $tags) {
  $result += [PSCustomObject]@{
    ResourceId  = $tag.resourceId
    ResourceRef = $tag.resourceRef
    Type        = $tag.properties.type
  }
}

Remove-Variable -Name LogName -Scope Script -Force
Remove-Variable -Name LogSource -Scope Script -Force
Remove-Variable -Name ScriptName -Scope Script -Force

return $result

}
## [END] Get-WACVMSecurityTags ##
function Get-WACVMSelfSignedCertificateData {
<#

.SYNOPSIS
Install the Hyper-V-Powershell support feature.

.DESCRIPTION
Install Azure site recovery agent and register it. It requires two pre-defined variables ($keyContent and $node).
Copyright (c) Microsoft Corp 2023.

.ROLE
Administrators

#>
[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $CertificateName
)

# $Certificate = New-SelfSignedCertificate -Subject "CN=$CertificateName" -CertStoreLocation "Cert:\CurrentUser\My" -NotBefore (Get-Date) -NotAfter (Get-Date).AddDays(365) -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256
$Certificate = New-SelfSignedCertificate `
    -KeyFriendlyName $CertificateName `
    -Subject "CN=Windows Azure Tools" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -NotBefore (Get-Date) `
    -NotAfter (Get-Date).AddDays(365) `
    -KeyExportPolicy Exportable `
    -KeySpec Signature `
    -KeyLength 2048 `
    -KeyAlgorithm RSA `
    -HashAlgorithm SHA256 `
    -KeyUsage DigitalSignature, KeyEncipherment `
    -Provider "Microsoft Enhanced Cryptographic Provider v1.0"

$CertificateRawData = [System.Convert]::ToBase64String($Certificate.RawData)
$PfxCertificateBytes = $Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx)
$PfxCertificateData = [System.Convert]::ToBase64String($PfxCertificateBytes)

$Thumbprint = $Certificate.Thumbprint
Remove-Item -LiteralPath "Cert:\CurrentUser\My\$Thumbprint" -Confirm:$false

return @{
    RawCertificateData = $CertificateRawData
    PfxCertificateData = $PfxCertificateData
}

}
## [END] Get-WACVMSelfSignedCertificateData ##
function Get-WACVMServerEventDetailsEx {
<#

.SYNOPSIS
Get the server events using the root\microsoft\windows\servermanager namespace.

.DESCRIPTION
Get the server events from this server.
The supported Operating Systems are Window Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0;
Import-Module CimCmdlets;

$nameSpace = "root\microsoft\windows\servermanager";
$class = "MSFT_ServerManagerTasks";
$method = "GetServerEventDetailEx";

##SkipCheck=true##
$xmlFormat = `
"<QueryList> `
    <Query Id=""0"" Path=""MyHyperVAlerts""> `
        <Select Path=""{0}"">*</Select> `
        <Select Path=""{1}"">*</Select> `
        <Select Path=""{2}"">*</Select> `
    </Query> `
</QueryList>";
##SkipCheck=false##

$hypervVmmsAdminPath = 'Microsoft-Windows-Hyper-V-Compute-Admin';
$hypervComputeAdminPath = 'Microsoft-Windows-Hyper-V-VMMS-Admin';
$hypervWorkerAdminPath = 'Microsoft-Windows-Hyper-V-Worker-Admin';

$eventsQuery = $xmlFormat -f $hypervComputeAdminPath, $hypervVmmsAdminPath, $hypervWorkerAdminPath;

$args = @{
    'FilterXml' = $eventsQuery;
    'ReverseDirection' = $true;
    'Skip'= [UInt64]0;
    'Top' = [UInt64]10;
};

$results = Invoke-CimMethod -Namespace $nameSpace -ClassName $class -MethodName $method -Argument $args;

$return = @();
$machineName = [System.Net.DNS]::GetHostByName('').HostName;

foreach ($result in $results) {
    if ($result.PSObject.Properties.Match('ItemValue').Count) {
        foreach ($item in $result.ItemValue) {
            $event = New-Object psobject

            Add-Member -InputObject $event -MemberType NoteProperty -Name "description" -Value $item.description;
            Add-Member -InputObject $event -MemberType NoteProperty -Name "id" -Value $item.id;
            Add-Member -InputObject $event -MemberType NoteProperty -Name "level" -Value $item.level;
            Add-Member -InputObject $event -MemberType NoteProperty -Name "log" -Value $item.log;
            Add-Member -InputObject $event -MemberType NoteProperty -Name "source" -Value $item.source;
            Add-Member -InputObject $event -MemberType NoteProperty -Name "timestamp" -Value $item.timestamp;
            Add-Member -InputObject $event -MemberType NoteProperty -Name "__ServerName" -Value $machineName;

            $return += $event;
        }
    }
}

return $return;

}
## [END] Get-WACVMServerEventDetailsEx ##
function Get-WACVMServerMemorySummary {
<#

.SYNOPSIS
Get the server memory summary using the root\microsoft\windows\managementools namespace.

.DESCRIPTION
Get the server memory from this server.
The supported Operating Systems are Window Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0
import-module CimCmdlets;

$nameSpace = "root\microsoft\windows\managementtools";
$class = "MSFT_MTMemorySummary";

Get-CimInstance -Namespace $nameSpace -ClassName $class | Microsoft.PowerShell.Utility\Select-Object total, inUse;

}
## [END] Get-WACVMServerMemorySummary ##
function Get-WACVMUnusedPublicIPAddresses {
<#

.SYNOPSIS
Gets public ips from a given network controller. Returns only unused pubic ips.

.DESCRIPTION
Gets public ips from the SDN Network Controller.

.ROLE
Readers

.PARAMETER uri
The uri used to connect to the SDN Network controller
#>

param (
	[Parameter(Mandatory = $true)]
	[String]
  $uri
)
Import-Module NetworkController
Set-StrictMode -Version 5.0

# find all public ips referenced by gateways
$gwIpRefs = @()
# get all gateway pools
$gwPools = Get-NetworkControllerGatewayPool -Connection $uri
foreach ($gwPool in $gwPools) {
  # get puplic ips in gateway pool
  if ($null -ne $gwPool.Properties.IpConfiguration) {
    $gwPips = $gwPool.Properties.IpConfiguration.publicIPAddresses
  }
  if ($null -ne $gwPips -or $gwPips.count -ge 0) {
    foreach ($gwPip in $gwPips) {
      $gwIpRefs += $gwPip.ResourceRef
    }
  }
}

$availableIps = @()
# get all public ips not in gateways
$pips = Get-NetworkControllerPublicIpAddress -ConnectionUri $uri | Where-Object {$_.ResourceRef -notin $gwIpRefs}

foreach ($pip in $pips) {
  # check if public ip is already refenced by an ip config
  if ($null -eq $pip.Properties.IpConfiguration) {
    $availableIps += $pip
  }
}

$availableIps | ConvertTo-Json | ConvertFrom-Json

}
## [END] Get-WACVMUnusedPublicIPAddresses ##
function Get-WACVMVfpEnabledSwitches {
<#

.SYNOPSIS
Gets the VFP enabled switches.

.DESCRIPTION
Gets the VFP enabled switches (determined by checking the switch extension id) and returns the id and name of the switches.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0;
Import-Module Hyper-V;
Import-Module Microsoft.PowerShell.Utility;

# GUID represents VFP extension enabled. If enabled, it is a "SDN" switch.
Get-VMSwitch | Get-VMSwitchExtension | Where-Object {"E9B59CFA-2BE1-4B21-828F-B6FBDBDDC017", "F74F241B-440F-4433-BB28-00F89EAD20D8" -contains $_.Id.ToUpper() -and $_.Enabled} | Microsoft.PowerShell.Utility\Select-Object SwitchId, SwitchName
}
## [END] Get-WACVMVfpEnabledSwitches ##
function Get-WACVMVirtualMachine {
<#

.SYNOPSIS
Get the passed in virtual machine from this server.

.DESCRIPTION
Get the passed in virtual machine from this server.  And adjust the heartbeat status value from down level servers
to match uplevel (2016) servers.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER vmId
    The Id of the requested virtual machine.

#>

param (
  [Parameter(Mandatory = $true)]
  [String]
  $vmId
)

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Indicates the host type for the virtual machine.

.DESCRIPTION
Indicates the host type for the virtual machine.

#>

enum HostType {
  StandAlone = 0
  Cluster = 1
  Britannica = 2
}

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.  Create read only (constant) variables
that add context to the said constants.

#>

function setupScriptEnv() {
  ##SkipCheck=true##
  Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
  Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
  Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-VirtualMachine" -Scope Script
  Set-Variable -Name DisaggregatedStoragePropertyName -Option ReadOnly -Value "DisaggregatedStorage" -Scope Script
  Set-Variable -Name HeartBeatPropertyName -Option ReadOnly -Value "Heartbeat" -Scope Script
  Set-Variable -Name IdPropertyName -Option ReadOnly -Value "Id" -Scope Script
  Set-Variable -Name Windows10MajorVersion -Option ReadOnly -Value 10 -Scope Script
  Set-Variable -Name ConfigurationLocationPropertyName -Option ReadOnly -Value "ConfigurationLocation" -Scope Script
  Set-Variable -Name BritannicaNamespace -Option ReadOnly -Value "root\SDDC\Management" -Scope Script
  Set-Variable -Name BritannicaVirtualMachineClassName -Option ReadOnly -Value "SDDC_VirtualMachine" -Scope Script
  Set-Variable -Name MSClusterNamespace -Option ReadOnly -Value "root\MSCluster" -Scope Script
  Set-Variable -Name MSClusterResourceClassName -Option ReadOnly -Value "MSCluster_Resource" -Scope Script
  Set-Variable -Name ClusteredVirtualkMachineQueryName -Option ReadOnly -Value "Select PrivateProperties from MSCluster_Resource where Type='Virtual Machine' and PrivateProperties.VmId='{0}'" -Scope Script
  Set-Variable -Name HostTypePropertyName -Option ReadOnly -Value "HostType" -Scope Script
  Set-Variable -Name HostBuildServerNumberPropertyName -Option ReadOnly -Value "HostServerBuildNumber" -Scope Script
  ##SkipCheck=false##
}

<#

.SYNOPSIS
Cleanup the script environment.

.DESCRIPTION
Cleanup the script environment.

#>

function cleanupScriptEnv() {
  Remove-Variable -Name LogName -Scope Script -Force
  Remove-Variable -Name LogSource -Scope Script -Force
  Remove-Variable -Name ScriptName -Scope Script -Force
  Remove-Variable -Name DisaggregatedStoragePropertyName -Scope Script -Force
  Remove-Variable -Name HeartBeatPropertyName -Scope Script -Force
  Remove-Variable -Name IdPropertyName -Scope Script -Force
  Remove-Variable -Name Windows10MajorVersion -Scope Script -Force
  Remove-Variable -Name ConfigurationLocationPropertyName -Scope Script -Force
  Remove-Variable -Name BritannicaNamespace -Scope Script -Force
  Remove-Variable -Name BritannicaVirtualMachineClassName -Scope Script -Force
  Remove-Variable -Name MSClusterNamespace -Scope Script -Force
  Remove-Variable -Name MSClusterResourceClassName -Scope Script -Force
  Remove-Variable -Name ClusteredVirtualkMachineQueryName -Scope Script -Force
  Remove-Variable -Name HostTypePropertyName -Scope Script -Force
  Remove-Variable -Name HostBuildServerNumberPropertyName -Scope Script -Force
}

<#

.SYNOPSIS
Are any of the virtual hard disks on a remote file server (disaggregated storage)?

.DESCRIPTION
If any virtual hard disk is on disaggregated storage then return true.  The UX will
use this value to determine at run-time if CredSSP is needed to manage these disks.

#>

function isDisaggregatedStorageUsed($vm) {
  $configPath = $vm.$ConfigurationLocationPropertyName
  if ($configPath.StartsWith("\\")) {
    return $true
  }

  $hardDisks = $vm | Get-VMHardDiskDrive -ErrorAction SilentlyContinue -ErrorVariable err

  if (-not($err)) {
    foreach ($hardDisk in $hardDisks) {
      if ($hardDisk.Path.StartsWith("\\")) {
        return $true
      }
    }
  }
  else {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
      -Message "[$ScriptName]: There were errors getting the hard disks for virtual machine $vm.Name.  Errors: $err." -ErrorAction SilentlyContinue

    Write-Error @($err)[0]
  }

  return $false
}

<#

.SYNOPSIS
Update (convert) the heart beat enum value.

.DESCRIPTION
For server versions lower than Windows 10/ Server 2016 the heart beat enum values
are 1 less than the current enum values in the UX.

#>

function updateHeatBeatValue([int] $heatBeatValue, [bool] $isDownLevel) {
  $isDownlevel = [Environment]::OSVersion.Version.Major -lt $Windows10MajorVersion

  if ($isDownlevel) {
    $heartbeat + 1;
  }

  return $heartBeat
}

<#

.SYNOPSIS
Determines if Britannica (sddc management resources) virtualization is available on the cluster

.DESCRIPTION
Use the existance of the cim namespace root/sddc to determine if Britannica
is supported or not.

#>

function isBritannicaVirtualizationAvailable() {
  $class = Get-WmiObject -Namespace $BritannicaNamespace -ClassName $BritannicaVirtualMachineClassName -List -ErrorAction SilentlyContinue -ErrorVariable err

  if (-not($class)) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
      -Message "[$ScriptName]: Couldn't get the required CIM namespace $BritannicaNamespace. Error: $err" -ErrorAction SilentlyContinue
  }

  return $null -ne $class
}

<#

.SYNOPSIS
Determines if the passed n VM Id is a clustered VM or not.

.DESCRIPTION
Return true when the passed in VM is clustered.

#>

function isVmClustered([string] $vmId) {
  if (isMSClusterAvailable) {
    $queryString = $ClusteredVirtualkMachineQueryName -f $vmId
    $vmResource = Get-CimInstance -Namespace $MSClusterNamespace -Query $queryString -ErrorAction SilentlyContinue

    return $null -ne $vmResource
  }

  return $false
}

<#

.SYNOPSIS
Determines if the MSCluster CIM provider is available on this server.

.DESCRIPTION
Use the existance of the CIM namespace to determine if MSCluster is available.

#>

function isMSClusterAvailable() {
  $class = Get-WmiObject -Namespace $MSClusterNamespace -ClassName $MSClusterResourceClassName -List -ErrorAction SilentlyContinue -ErrorVariable err

  if (-not($class)) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
      -Message "[$ScriptName]: Couldn't get the required CIM namespace $MSClusterNamespace. Error: $err" -ErrorAction SilentlyContinue
  }

  return $null -ne $class
}

<#

.SYNOPSIS
Determines the type of vm host.

.DESCRIPTION
Determines the type of vm host.

#>

function getVmHostType() {
  if (isVmClustered $vmId) {
    $hostType = [HostType]::Cluster

    if (isBritannicaVirtualizationAvailable) {
      $hostType = [HostType]::Britannica
    }
  }
  else {
    $hostType = [HostType]::StandAlone
  }

  return $hostType
}

<#

.SYNOPSIS
Get the the build number for the OS installed on this server.

.DESCRIPTION
Get the the build number for the OS installed on this server.

#>

function getBuildNumber {
  return [System.Environment]::OSVersion.Version.Build
}

<#

.SYNOPSIS
The main function.

.DESCRIPTION
Get the virtual machines on this server and filter the properties down to just those
needed by the UX model.  The Id property is forced to lower case since Ids from other
sources (Britannica) are lower case.  The Hear Beat status enum may be adjusted for
down level servers and the meta property that indicates this VM uses disaggregated
storage is added.

#>

function main([string] $vmId) {
  $private:err = $null

  $vm = Get-RBACVM -Id $vmId -ErrorAction SilentlyContinue -ErrorVariable err | `
    Microsoft.PowerShell.Utility\Select-Object `
    Name, `
    CPUUsage, `
    MemoryAssigned, `
    MemoryDemand, `
    State, `
    Status, `
    CreationTime, `
    Uptime, `
    Version, `
    IsDeleted, `
    DynamicMemoryEnabled, `
    MemoryMaximum, `
    MemoryMinimum, `
    MemoryStartup, `
    ProcessorCount, `
    Generation, `
    ComputerName, `
    CheckpointFileLocation, `
    ConfigurationLocation, `
    SmartPagingFilePath, `
    OperationalStatus, `
    IsClustered, `
  @{Name = $HostTypePropertyName; Expression = { getVmHostType } }, `
  @{Name = $DisaggregatedStoragePropertyName; Expression = { isDisaggregatedStorageUsed $_ } }, `
  @{Name = $HeartBeatPropertyName; Expression = { updateHeatBeatValue $_.HeartBeatPropertyName } }, `
  @{Name = $IdPropertyName; Expression = { [System.Guid]::Parse($_.id.ToString().ToLower()) } }, # Ensure the ID GUID is lower case...
  @{Name = $HostBuildServerNumberPropertyName; Expression = { getBuildNumber } }

  if (!!$err) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
      -Message "[$ScriptName]: There were errors getting the virtual machine with Id $vmId.  Errors: $err." -ErrorAction SilentlyContinue

    Write-Error @($err)[0]

    return @{}
  }

  return $vm
}

###############################################################################
# Script execution starts here...
###############################################################################

if (-not ($env:pester)) {
  setupScriptEnv

  try {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    $module = Get-Module -Name Hyper-V -ErrorAction SilentlyContinue -ErrorVariable err
    if ($module) {
      return main $vmId
    }
    else {
      Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: The required PowerShell module (Hyper-V) was not found." -ErrorAction SilentlyContinue

      Write-Error $strings.HyperVModuleRequired

      return @()
    }
  }
  finally {
    cleanupScriptEnv
  }
}

return @{}

}
## [END] Get-WACVMVirtualMachine ##
function Get-WACVMVirtualMachineAlert {
<#

.SYNOPSIS
Get the latest alert for the provided virtual machine from Cluster Health Service.

.DESCRIPTION
Use the cluster health service to retrieve the last (latest) alert for the passed in virtual machine.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER vmId
    The Id of the requested virtual machine.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $vmId
)  

Set-StrictMode -Version 5.0
Import-Module CimCmdlets -ErrorAction SilentlyContinue
Import-Module FailoverClusters -ErrorAction SilentlyContinue
Import-Module Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

###############################################################################
# Constants
###############################################################################

Set-Variable -Name LogName -Option Constant -Value "Microsoft-ServerManagementExperience" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SMEScripts" -ErrorAction SilentlyContinue
Set-Variable -Name ScriptName -Option Constant -Value "Get-VirtualMachineAlerts.ps1" -ErrorAction SilentlyContinue

function main([string]$vmId) {
    $cluster = Get-Cluster
    $faults = @()

    if ($cluster) {
        if($cluster.S2DEnabled -gt 0) {

            # For VM alerts, field 'faultingObjectUniqueId' is not populated, so we need to depend on 'faultingObjectDescription'.
            # 'faultingObjectDescription' format: The virtual machine <vmId>
            $faults = Get-HealthFault | `
                Where-Object {$_.FaultingObjectType -eq "Microsoft.Health.EntityType.VM" -and `
                            $_.FaultingObjectDescription.ToLower().EndsWith($vmId)} | `
                Microsoft.PowerShell.Utility\Select-Object `
                PerceivedSeverity, `
                FaultingObjectDescription, `
                FaultingObjectLocation, `
                FaultingObjectType, `
                FaultingObjectUniqueId, `
                FaultTime, `
                FaultType, `
                Reason, `
                RecommendedActions -Last 1
        }
    }
}

$module = Get-Module -Name FailoverClusters -ErrorAction SilentlyContinue
if ($module) {
    return main $vmId
}

Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue
Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
    -Message "[$ScriptName]: The required PowerShell module (FailoverClusters) was not found." -ErrorAction SilentlyContinue

Write-Error $strings.FailoverClustersModuleRequired

return $null
}
## [END] Get-WACVMVirtualMachineAlert ##
function Get-WACVMVirtualMachineBootOrderSettings {
<#

.SYNOPSIS
Gets the boot order BIOS setting for the passed in virtual machine.

.DESCRIPTION
Gets the boot order BIOS setting for the passed in virtual machine from this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER vmId
    The Id of the requested virtual machine.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $vmId
)

Set-StrictMode -Version 5.0;
Import-Module Hyper-V;

$vm = Get-RBACVM -id $vmId
$isGen1 = $true;

# Prior to server 2012 R2 all virtual machines are Generation 1 and there is no Generation property of the virtual machine
# PowerShell object.
$isServer2012 = [Environment]::OSVersion.Version.Major -eq 6 -and [Environment]::OSVersion.Version.Minor -eq 2;

if (!$isServer2012) {
  $isGen1 = $vm.Generation -eq 1;
}

$result = @{}

if ($isGen1) {
  $result.gen1 = $vm | get-vmBios | Microsoft.PowerShell.Utility\Select-Object startupOrder
} else {
  $fw = $vm | get-vmFirmware
  $result.gen2 = @{}
  $result.gen2.bootOrderDevicesId = @()
  foreach ($bootEntry in $fw.BootOrder) {
    if ($bootEntry.Device) {
      $result.gen2.bootOrderDevicesId += $bootEntry.Device.Id
    } else {
      $result.gen2.bootOrderDevicesId += $bootEntry.FirmwarePath
    }
  }
}

$result

}
## [END] Get-WACVMVirtualMachineBootOrderSettings ##
function Get-WACVMVirtualMachineCheckpoint {
<#

.SYNOPSIS
Gets the passed in snapshot for the passed in virtual machine.  

.DESCRIPTION
Gets the passed in snapshot for the passed in virtual machine from this server.  
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER vmId
  	The Id of the requested virtual machine.

.PARAMETER snapShotId
  	The Id of the requested checkpoint (snapshot).

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $vmId,
    [Parameter(Mandatory = $true)]
    [String]
    $snapshotId
)

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.  Create read only (constant) variables
that add context to the said constants.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-VirtualMachineCheckpoint.ps1" -Scope Script
    Set-Variable -Name HyperVModuleName -Option ReadOnly -Value "Hyper-V" -Scope Script
}    

<#

.SYNOPSIS
Cleanup the script environment.

.DESCRIPTION
Cleanup the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name HyperVModuleName -Scope Script -Force
}

function main([string] $vmId, [string] $snapshotId) {

    $snapshot = Get-VMSnapShot -Id $snapshotId -ErrorAction SilentlyContinue -ErrorVarible err `
        | Microsoft.PowerShell.Utility\Select-Object parentcheckpointid, name, id, state, creationTime

    if (!!$err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Could not get the virtual machine snapshot with Id $snapshotId. Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return @{}
    }

    if (!!$snapshot)
    {
        # get the VM using the passed in Id
        $vm = Get-RBACVM -Id $vmId -ErrorAction SilentlyContinue -ErrorVariable err

        if (!!$err) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: Could not get the virtual machine with Id $vmId. Error: $err" -ErrorAction SilentlyContinue

            Write-Error @($err)[0]

            return @{}
        }
   
        # get the Id of the currently applied snapshot.  When the value is null then no snapshot is applied.
        # on down level servers this will some times fail when the VM does not have an applied snapshot
        $appliedSnapshot = Get-VMSnapShot -ParentOf $vm -ErrorAction Ignore | Microsoft.PowerShell.Utility\Select-Object id

        $isSnapshotApplied = ($appliedSnapShot -and $appliedSnapshot.Id -eq $snapshot.id)

        # The shape of this custom PS object must be the same in Get-VirtualMachineCheckpoints.ps1!
        $checkpoint = New-Object psobject -Property @{
            "CreationTime" = $snapshot.CreationTime;
            "Id" = $snapshot.Id;
            "Name" = $snapshot.Name;
            "ParentCheckpointId" = $snapshot.ParentCheckpointId;
            "State" = $snapshot.State;
            "IsCurrentlyApplied" = $isSnapshotApplied;
        }
    }

    return $checkpoint
}

###############################################################################
# Script execution starts here
###############################################################################

if (-not ($env:pester)) {
    setupScriptEnv

    try {
        Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

        $hyperVModule = Get-Module -Name $HyperVModuleName -ErrorAction SilentlyContinue -ErrorVariable err

        if (!!$err) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: The required PowerShell module (Hyper-V) was not found." -ErrorAction SilentlyContinue
        
            Write-Error @($err)[0]
            
            return @{}
        }

        return main $vmId $snapshotId
    } finally {
        cleanupScriptEnv
    }
}

}
## [END] Get-WACVMVirtualMachineCheckpoint ##
function Get-WACVMVirtualMachineCheckpoints {
<#

.SYNOPSIS
Get the checkpoints (snapshots) for the passed in virtual machine.  

.DESCRIPTION
Get the snapshots for the passed in virtual machine from this server.  
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER vmId
  	The Id of the requested virtual machine.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $vmId
)

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.  Create read only (constant) variables
that add context to the said constants.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-VirtualMachineCheckpoints.ps1" -Scope Script
    Set-Variable -Name HyperVModuleName -Option ReadOnly -Value "Hyper-V" -Scope Script
}    

<#

.SYNOPSIS
Cleanup the script environment.

.DESCRIPTION
Cleanup the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name HyperVModuleName -Scope Script -Force
}

function main([string] $vmId) {
    $checkpoints = @()

     $vm = Get-RBACVM -Id $vmId -ErrorAction SilentlyContinue -ErrorVariable err
    
     if (!!$err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Could not get the virtual machine with Id $vmId. Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return @()
    }

    $snapshots = $vm | Get-VMSnapShot -ErrorAction SilentlyContinue -ErrorVariable err | `
        Microsoft.PowerShell.Utility\Select-Object ParentCheckpointId, Name, Id, State, CreationTime

    if (!!$err) {
        $vmName = $vm.Name

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Could not get the snapshots for virtual machine  $vmName. Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return @()
    }
   
    if (@($snapshots).Count -gt 0)
    {
        # get the Id of the currently applied snapshot.  When the value is null then no snapshot is applied.
        # on down level servers this will some times fail when the VM does not have an applied snapshot
        $appliedSnapshot = Get-VMSnapshot -ParentOf $vm -ErrorAction Ignore | Microsoft.PowerShell.Utility\Select-Object id

        foreach($snapshot in $snapshots)
        {
            $isSnapshotApplied = ($appliedSnapShot -and $appliedSnapshot.Id -eq $snapshot.id)

            # The shape of this custom PS object must be the same in Get-VirtualMachineCheckpoint.ps1!
            $checkpoint = New-Object psobject -Property @{
                "CreationTime" = $snapshot.CreationTime;
                "Id" = $snapshot.Id;
                "Name" = $snapshot.Name;
                "ParentCheckpointId" = $snapshot.ParentCheckpointId;
                "State" = $snapshot.State;
                "IsCurrentlyApplied" = $isSnapshotApplied;
            }

            $checkpoints += $checkpoint
        }
    }

    return $checkpoints
}

###############################################################################
# Script execution starts here
###############################################################################

if (-not ($env:pester)) {
    setupScriptEnv

    try {
        Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

        Get-Module -Name $HyperVModuleName -ErrorAction SilentlyContinue -ErrorVariable err

        if (!!$err) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: The required PowerShell module (Hyper-V) was not found." -ErrorAction SilentlyContinue
        
            Write-Error @($err)[0]
            
            return @()
        }

        return main $vmId
    } finally {
        cleanupScriptEnv
    }
}

}
## [END] Get-WACVMVirtualMachineCheckpoints ##
function Get-WACVMVirtualMachineCheckpointsSettings {
<#

.SYNOPSIS
Get the checkpoints settings for the passed in virtual machine.

.DESCRIPTION
Get the checkpoints settings for the passed in virtual machine from this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER vmId
    The Id of the requested virtual machine.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $vmId
)  

Set-StrictMode -Version 5.0;
Import-Module Hyper-V;

Get-RBACVM -id $vmId | Microsoft.PowerShell.Utility\Select-Object vmname, vmid, IsDeleted, SnapshotFileLocation, CheckpointType, AutomaticCheckpointsEnabled

}
## [END] Get-WACVMVirtualMachineCheckpointsSettings ##
function Get-WACVMVirtualMachineComputerInfo {
<#

.SYNOPSIS
Get-ComputerInfo

.DESCRIPTION
Gets a host's OSDisplayVersion and OsOperatingSystemSKU information

.ROLE
Hyper-V-Administrators

#>


Set-StrictMode -Version 5.0;
Import-Module Hyper-V -ErrorAction SilentlyContinue;

<#

.SYNOPSIS
Setup script runtime environment.

.DESCRIPTION
Setup script runtime environment.

#>

function setupScriptEnv() {
  Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
  Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScript" -Scope Script
  Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-VirtualMachineComputerInfo.ps1" -Scope Script
}


<#

.SYNOPSIS
Cleanup script runtime environment.

.DESCRIPTION
Cleanup script runtime environment.

#>

function cleanupScriptEnv() {
  Remove-Variable -Name LogName -Scope Script -Force
  Remove-Variable -Name LogSource -Scope Script -Force
  Remove-Variable -Name ScriptName -Scope Script -Force
}

if (-not ($env:pester)) {
  setupScriptEnv

  try {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    $module = Get-Module -Name Hyper-V -ErrorAction SilentlyContinue -ErrorVariable +err

    if ($module) {
      return Get-ComputerInfo | Microsoft.PowerShell.Utility\Select-Object OSDisplayVersion, OsOperatingSystemSKU

    }

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: The required PowerShell module (Hyper-V) was not found." -ErrorAction SilentlyContinue

    Write-Error $strings.HyperVModuleRequired

    return @()
  }
  finally {
    cleanupScriptEnv
  }
}

}
## [END] Get-WACVMVirtualMachineComputerInfo ##
function Get-WACVMVirtualMachineDisksDefaultPath {
<#

.SYNOPSIS
Get the list of vhds in a folder.

.DESCRIPTION
Get the list of vhds in a folder.

.ROLE
Readers

.PARAMETER vhdDefaultPath
The Id of the requested virtual machine.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $vhdDefaultPath
)

$list = @{}
if (Test-Path $vhdDefaultPath ) {
    $list = Get-ChildItem -Path  $vhdDefaultPath  -ErrorAction SilentlyContinue;
    if (-not $list) {
        return $list;
    }
    $list = $list | Microsoft.PowerShell.Utility\Select-Object Name | Where-Object {$_.Name -like '*.vhd*'}
}

return $list

}
## [END] Get-WACVMVirtualMachineDisksDefaultPath ##
function Get-WACVMVirtualMachineDisksSettings {
<#

.SYNOPSIS
Get the hard disks for the passed in virtual machine.

.DESCRIPTION
Get the hard disks for the passed in virtual machine from this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER vmId
    The Id of the requested virtual machine.

#>

param (
  [Parameter(Mandatory = $true)]
  [String]
  $vmId
)

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue
Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

###############################################################################
# Constants
###############################################################################

function setupScriptEnv() {
  Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
  Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
  Set-Variable -Name ScriptName -Option ReadOnly -Value Get-VirtualMachineDisksSettings.ps1 -Scope Script
  Set-Variable -Name DiskSizePropertyName -Option ReadOnly -Value "Size" -Scope Script
  Set-Variable -Name DiskVhdFormatPropertyName -Option ReadOnly -Value "VhdFormat" -Scope Script
  Set-Variable -Name DiskVhdTypePropertyName -Option ReadOnly -Value "VhdType" -Scope Script
  Set-Variable -Name DiskVhdMinimumSizePropertyName -Option ReadOnly -Value "VhdMinimumSize" -Scope Script
}

function cleanupScriptEnv() {
  Remove-Variable -Name LogName -Scope Script -Force
  Remove-Variable -Name LogSource -Scope Script -Force
  Remove-Variable -Name ScriptName -Scope Script -Force
  Remove-Variable -Name DiskSizePropertyName -Scope Script -Force
  Remove-Variable -Name DiskVhdFormatPropertyName -Scope Script -Force
  Remove-Variable -Name DiskVhdTypePropertyName -Scope Script -Force
  Remove-Variable -Name DiskVhdMinimumSizePropertyName -Scope Script -Force
}

function getSize($path) {
  $vhd = Get-VHD -Path $path
  return $vhd.Size
}

function getVhdFormat($path) {
  $vhd = Get-VHD -Path $path
  return $vhd.VhdFormat
}

function getVhdType($path) {
  $vhd = Get-VHD -Path $path
  return $vhd.VhdType
}

function getVhdMinimumSize($path) {
  $vhd = Get-VHD -Path $path
  return $vhd.MinimumSize
}

function main([string]$vmId) {
  $defaultPath = ""
  $vm = Get-RBACVM -id $vmId
  $disks = @($vm | Get-VMHardDiskDrive | Microsoft.PowerShell.Utility\Select-Object vmname, vmid, IsDeleted, name, id, controllerType, controllerLocation, controllerNumber, path, @{l = $DiskVhdFormatPropertyName; e = { getVhdFormat $_.path } }, @{l = $DiskSizePropertyName; e = { getSize $_.path } }, @{l = $DiskVhdTypePropertyName; e = { getVhdType $_.path } }, @{l = $DiskVhdMinimumSizePropertyName; e = { getVhdMinimumSize $_.path } })
  $dvds = @($vm | Get-VMDvdDrive | Microsoft.PowerShell.Utility\Select-Object vmname, vmid, IsDeleted, name, id, controllerType, controllerLocation, controllerNumber, path)

  foreach ($disk in $disks) {
    $path = $disk.path.substring(0, $disk.path.lastIndexOf('\') + 1)
    Write-Host $path

    if ($path -and (Test-Path $path)) {
      $defaultPath = $path;
      break;
    }
  }

  if (-not $defaultPath -and $vm.Path -and (Test-Path $vm.Path)) {
    $defaultPath = $vm.Path + '\Virtual Hard Disks';

    if (-not (Test-Path $defaultPath)) {
      $defaultPath = $vm.Path;
    }
  }

  if (-not $defaultPath -or -not (Test-Path $defaultPath)) {
    $defaultPath = (Get-VMHost).VirtualHardDiskPath
  }

  $result = @{}

  $result.defaultPath = $defaultPath
  $result.disks = $disks
  $result.dvds = $dvds

  return $result
}

###############################################################################
# Script execution starts here...
###############################################################################

if (-not ($env:pester)) {
  setupScriptEnv

  try {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    $hyperVModule = Get-Module -Name Hyper-V -ErrorAction SilentlyContinue

    if (-not($hyperVModule)) {
      Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: The required PowerShell module (Hyper-V) was not found." -ErrorAction SilentlyContinue

      Write-Error $strings.HyperVModuleRequired

      return $null
    }

    return main $vmId

  }
  finally {
    cleanupScriptEnv
  }
}

}
## [END] Get-WACVMVirtualMachineDisksSettings ##
function Get-WACVMVirtualMachineHostNode {
<#

.SYNOPSIS
Get the current host server (node) of the passed in virtual machine from the cluster.

.DESCRIPTION
Gets a computer's Hyper-V Host General settings.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER vmId
  	The Id of the requested virtual machine.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $vmId
)  

Set-StrictMode -Version 5.0;
Import-Module CimCmdlets;

##SkipCheck=true##
$queryString = "select name, ownernode from mscluster_resource where type='virtual machine' and privateproperties.vmid='{0}'" -f $vmId;
##SkipCheck=false##

$results = Get-CimInstance -Namespace "Root\MSCluster" -Query $queryString

$results | Microsoft.PowerShell.Utility\Select-Object name, ownernode;
}
## [END] Get-WACVMVirtualMachineHostNode ##
function Get-WACVMVirtualMachineIdCompatibility {
<#

.SYNOPSIS
Validate ID compatibility.

.DESCRIPTION
Validate whether the ID of virtual machine to be imported is compatible with the host or not.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER vmcxPath
The path containing the virtual machine configuration files

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $vmcxPath
)

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue


<#

.SYNOPSIS
Setup script runtime environment.

.DESCRIPTION
Setup script runtime environment.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScript" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-VirtualMachineIdCompatibility.ps1" -Scope Script
}

<#

.SYNOPSIS
Cleanup script runtime environment.

.DESCRIPTION
Cleanup script runtime environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
}


<#

.SYNOPSIS
The main function.

.DESCRIPTION
Validate whether the ID of virtual machine to be imported is compatible with the host or not

.PARAMETER vmcxPath
The path containing the virtual machine configuration files

#>

function main([string]$vmcxPath) {
  $err = $null
  $report = Compare-VM -Path $vmcxPath -ErrorAction SilentlyContinue -ErrorVariable +err

  if ($err) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Couldn't generate the compatibility report. Error: $err"  -ErrorAction SilentlyContinue
  }

  if($report) {
      return $true
  } else {
      return $false
  }
}


###############################################################################
# Script execution starts here
###############################################################################
setupScriptEnv

try {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    $module = Get-Module -Name Hyper-V -ErrorAction SilentlyContinue -ErrorVariable +err
    if ($module) {
        return main $vmcxPath
    }

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: The required PowerShell module (Hyper-V) was not found."  -ErrorAction SilentlyContinue

    Write-Error @($err)[0]

    return @()
} finally {
    cleanupScriptEnv
}

}
## [END] Get-WACVMVirtualMachineIdCompatibility ##
function Get-WACVMVirtualMachineIntegrationServiceComponents {
<#

.SYNOPSIS
Get the integration components for the passed in virtual machine.

.DESCRIPTION
Gets the integration components for the passed in virtual machine on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER vmId
    The Id of the requested virtual machine.

#>

 param (
    [Parameter(Mandatory = $true)]
    [String]
    $vmId
)  

Set-StrictMode -Version 5.0;
Import-Module Hyper-V;

Get-RBACVM -id $vmId | `
    Get-VMIntegrationService | `
    Microsoft.PowerShell.Utility\Select-Object vmname, vmid, IsDeleted, Name, Enabled, PrimaryStatusDescription, SecondaryStatusDescription

}
## [END] Get-WACVMVirtualMachineIntegrationServiceComponents ##
function Get-WACVMVirtualMachineKvpProperties {
<#

.SYNOPSIS
Get the Key Value Exchange properties for the passed in virtual machine.

.DESCRIPTION
Get the Key Value Exchange properties for the passed in virtual machine from this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER vmId
  	The Id of the requested virtual machine.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $vmId
)

Set-StrictMode -Version 5.0

import-module CimCmdlets -ErrorAction SilentlyContinue
Import-Module Hyper-V -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.  Create read only (constant) variables
that add context to the said constants.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScript" -Scope Script
	Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-VirtualMachineKvpProperties.ps1" -Scope Script
	Set-Variable -Name VirtualizationNamespace -Option ReadOnly -Value "root\virtualization\v2" -Scope Script
	Set-Variable -Name MsvmComputerSystemClassName -Option ReadOnly -Value "Msvm_ComputerSystem" -Scope Script
	Set-Variable -Name OSNamePropertyName -Option ReadOnly -Value "OSName" -Scope Script
	Set-Variable -Name LastSuccessfulCheckpointPropertyName -Option ReadOnly -Value "LastSuccessfulCheckpoint" -Scope Script
	Set-Variable -Name OSVersionPropertyName -Option ReadOnly -Value "OSVersion" -Scope Script
	Set-Variable -Name DataPropertyName -Option ReadOnly -Value "Data" -Scope Script
	Set-Variable -Name FullyQualifiedDomainNamePropertyName -Option ReadOnly -Value "FullyQualifiedDomainName" -Scope Script
	Set-Variable -Name IntegrationServicesVersionPropertyName -Option ReadOnly -Value "IntegrationServicesVersion" -Scope Script
	Set-Variable -Name NamePropertyName -Option ReadOnly -Value "Name" -Scope Script
	Set-Variable -Name MsvmSystemDeviceClassName -Option ReadOnly -Value "Msvm_SystemDevice" -Scope Script
	Set-Variable -Name MsvmKvpExchangeComponentClassName -Option ReadOnly -Value "Msvm_KvpExchangeComponent" -Scope Script
	Set-Variable -Name IdPropertyName -Option ReadOnly -Value "Id" -Scope Script
	Set-Variable -Name IsClusteredPropertyName -Option ReadOnly -Value "IsClustered" -Scope Script
	Set-Variable -Name HostOnlyItemsPropertyName -Option ReadOnly -Value "HostOnlyItems" -Scope Script
	Set-Variable -Name GuestIntrinsicExchangeItemsPropertyName -Option ReadOnly -Value "GuestIntrinsicExchangeItems" -Scope Script
  Set-Variable -Name CreationTimePropertyName -Option ReadOnly -Value "CreationTime" -Scope Script
  Set-Variable -Name ProductTypeName -Option ReadOnly -Value "ProductType" -Scope Script
}

<#

.SYNOPSIS
Cleanup the script environment.

.DESCRIPTION
Cleanup the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name VirtualizationNamespace -Scope Script -Force
    Remove-Variable -Name MsvmComputerSystemClassName -Scope Script -Force
    Remove-Variable -Name OSNamePropertyName -Scope Script -Force
	Remove-Variable -Name LastSuccessfulCheckpointPropertyName -Scope Script -Force
	Remove-Variable -Name OSVersionPropertyName -Scope Script -Force
	Remove-Variable -Name DataPropertyName -Scope Script -Force
	Remove-Variable -Name FullyQualifiedDomainNamePropertyName -Scope Script -Force
	Remove-Variable -Name IntegrationServicesVersionPropertyName -Scope Script -Force
	Remove-Variable -Name NamePropertyName -Scope Script -Force
	Remove-Variable -Name MsvmSystemDeviceClassName -Scope Script -Force
	Remove-Variable -Name MsvmKvpExchangeComponentClassName -Scope Script -Force
	Remove-Variable -Name IdPropertyName -Scope Script -Force
	Remove-Variable -Name IsClusteredPropertyName -Scope Script -Force
	Remove-Variable -Name HostOnlyItemsPropertyName -Scope Script -Force
	Remove-Variable -Name GuestIntrinsicExchangeItemsPropertyName -Scope Script -Force
  Remove-Variable -Name CreationTimePropertyName -Scope Script -Force
  Remove-Variable -Name ProductTypeName -Scope Script -Force
}

<#

.SYNOPSIS
Get the creation time of the last successful checkpoint.

.DESCRIPTION
Get the creation time of the last successful checkpoint, or return an empty string if
the data is not available.

#>

function getLastSuccessfulCheckpointCreationTime($vm) {
	$err = $null

	$checkpoints = @($vm | Get-VMSnapshot -ErrorAction SilentlyContinue -ErrorVariable +err | Microsoft.PowerShell.Utility\Sort-Object $CreationTimePropertyName)
	if ($err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Warning `
			-Message "[$ScriptName]: Couldn't get the checkpoints of virtual machine with Id $vmId. Script will continue without this data. Error: $err" -ErrorAction SilentlyContinue

		$checkpoints = @()
	}

	if ($checkpoints.Count -gt 0) {
		return $checkpoints[$checkpoints.Count - 1].$CreationTimePropertyName
	}

	return ""
}

<#

.SYNOPSIS
Get the KVP data from the CIM namespace.

.DESCRIPTION
Get the KVP data from the CIM namespace.

#>

function getKvpData([string] $vmId) {
	$err = $null

	# get the CIM VM instance
	$cimVm = Get-CimInstance -namespace $VirtualizationNamespace -ClassName $MsvmComputerSystemClassName -filter "$NamePropertyName = '$($vmId)'" -ErrorAction SilentlyContinue -ErrorVariable +err
	if ($err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
			-Message "[$ScriptName]: Couldn't get the CIM instance of virtual machine with Id $vmId.  Error: $err" -ErrorAction SilentlyContinue

		return $null
	}

	# get the associated KVP exchange component
	$Kvp = Get-CimAssociatedInstance -InputObject $cimVm -Association $MsvmSystemDeviceClassName -ResultClassName $MsvmKvpExchangeComponentClassName -ErrorAction SilentlyContinue -ErrorVariable +err
	if ($err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
			-Message "[$ScriptName]: Couldn't get the KVP data of virtual machine with Id $vmId.  Error: $err" -ErrorAction SilentlyContinue

		return $null
	}

	return $kvp
}

<#

.SYNOPSIS
Get the passed in property from the KVP GuestIntrinsicExchangeItems data.

.DESCRIPTION
Get the passed in property from the KVP GuestIntrinsicExchangeItems data.

#>

function getKvpGuestIntrinsicProperty($kvp, [string] $propertyName) {
	try {
		return (([xml]($Kvp.$GuestIntrinsicExchangeItemsPropertyName | `
			Microsoft.PowerShell.Core\Where-Object {$_ -match $propertyName})).instance.property | `
			Microsoft.PowerShell.Core\Where-Object {$_.Name -eq $DataPropertyName}).Value
	} catch [System.Management.Automation.PropertyNotFoundException] {
		return ""
	}
}

<#

.SYNOPSIS
Get the passed in property from the KVP HostOnlyItems data.

.DESCRIPTION
Get the passed in property from the KVP HostOnlyItems data.

#>

function getKvpGuestHostOnlyProperty($kvp, [string] $propertyName) {
	try {
		return (([xml]($Kvp.$HostOnlyItemsPropertyName | `
			Microsoft.PowerShell.Core\Where-Object {$_ -match $propertyName})).instance.property | `
			Microsoft.PowerShell.Core\Where-Object {$_.Name -eq $DataPropertyName}).Value
	} catch [System.Management.Automation.PropertyNotFoundException] {
		return ""
	}
}

<#

.SYNOPSIS
Main

.DESCRIPTION
An explicit main function to fetch the settings.

#>

function main([string] $vmId) {
	$err = $null

	$vm = Get-RBACVM -id $vmId -ErrorAction SilentlyContinue -ErrorVariable +err
	if ($err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        	-Message "[$ScriptName]: Couldn't get the virtual machine with Id $vmId. Error: $err" -ErrorAction SilentlyContinue

		return @{}
	}

	$Kvp = getKvpData $vmId
	if (-not ($kvp)) {
		return @{}
	}

	# define a new object that will hold the properties that will be returned to the caller.
	$vmProperties = New-Object psobject -Property @{
		$IdPropertyName = $vmId;
		$IsClusteredPropertyName =  $vm.isClustered;
		$LastSuccessfulCheckpointPropertyName = (getLastSuccessfulCheckpointCreationTime $vm);
		$OSNamePropertyName = (getKvpGuestIntrinsicProperty $kvp $OSNamePropertyName);
    $OSVersionPropertyName = (getKvpGuestIntrinsicProperty $kvp $OSVersionPropertyName);
		$FullyQualifiedDomainNamePropertyName = (getKvpGuestIntrinsicProperty $kvp $FullyQualifiedDomainNamePropertyName);
    $IntegrationServicesVersionPropertyName = (getKvpGuestIntrinsicProperty $kvp $IntegrationServicesVersionPropertyName);
    $ProductTypeName = (getKvpGuestIntrinsicProperty $kvp $ProductTypeName);
	}

	return $vmProperties
}

###############################################################################
# Script execution starts here.
###############################################################################

if (-not($env:pester)) {
    setupScriptEnv

    try {
        Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

        # Hyper-V PowerShell module and the VM name must be available for this script to run.
        $module = Get-Module Hyper-V -ErrorAction SilentlyContinue
        if ($module) {
            return main $vmId
        }

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        	-Message "[$ScriptName]: The required PowerShell module (HyperV) was not found. Virtual Machine $vmName was not added to the cluster." -ErrorAction SilentlyContinue

        return @{}
    } finally {
        cleanupScriptEnv
    }
}

}
## [END] Get-WACVMVirtualMachineKvpProperties ##
function Get-WACVMVirtualMachineMemorySettings {
<#

.SYNOPSIS
Get the memory settings for the passed in virtual machine.

.DESCRIPTION
Gets the memory settings for the passed in virtual machine from this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER vmId
    The Id of the requested virtual machine.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $vmId
)  

Set-StrictMode -Version 5.0;
Import-Module Hyper-V;

Get-RBACVM -id $vmId | get-vmmemory | Microsoft.PowerShell.Utility\Select-Object vmname, vmid, DynamicMemoryEnabled, Maximum, IsDeleted, Minimum, Startup, Priority, Buffer

}
## [END] Get-WACVMVirtualMachineMemorySettings ##
function Get-WACVMVirtualMachineNameAndIdCompatibility {
<#

.SYNOPSIS
Check if rename is required for import.

.DESCRIPTION
Validate whether the virtual machine name already exists on the host and return if rename is required.
Check for the presence of the virtual machine ID in the host and return if a new ID needs to be generated.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016, Windows Server 2019.

.ROLE
Hyper-V-Administrators

.PARAMETER vmName
The virtual machine name of the machine being imported

.PARAMETER configPath
The path containing the virtual machine configuration files

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $vmName,
    [Parameter(Mandatory = $true)]
    [String]
    $configPath
)

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue


<#

.SYNOPSIS
Setup script runtime environment.

.DESCRIPTION
Setup script runtime environment.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScript" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-VirtualMachineNameAndIdCompatibility.ps1" -Scope Script
}

<#

.SYNOPSIS
Cleanup script runtime environment.

.DESCRIPTION
Cleanup script runtime environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
}


<#

.SYNOPSIS
The main function.

.DESCRIPTION
Validate whether the virtual machine name already exists on the host and return if rename is required.

.PARAMETER vmName
The virtual machine name of the machine being imported

.PARAMETER configPath
The path containing the virtual machine configuration files

#>

function main([string]$vmName, [string]$configPath) {
  $err = $null
  $vm = Get-RBACVM -Name $vmName -ErrorAction SilentlyContinue -ErrorVariable +err

  if ($err) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Couldn't get the virtual machines. Error: $err"  -ErrorAction SilentlyContinue

  }

  $err = $null
  $vmIdCompatible = Compare-VM -Path $configPath -ErrorAction SilentlyContinue -ErrorVariable +err

  if ($err) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Couldn't generate the compatibility report. Error: $err"  -ErrorAction SilentlyContinue

  }

  return @{
      'renameRequired' = if ($vm) { $true } else { $false };
      'vmIdCompatible' = if($vmIdCompatible) { $true } else { $false };
  }
}


###############################################################################
# Script execution starts here
###############################################################################
setupScriptEnv

try {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    $module = Get-Module -Name Hyper-V -ErrorAction SilentlyContinue -ErrorVariable +err
    if ($module) {
        return main $vmName $configPath
    }

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: The required PowerShell module (Hyper-V) was not found."  -ErrorAction SilentlyContinue

    Write-Error @($err)[0]

    return @{}
} finally {
    cleanupScriptEnv
}

}
## [END] Get-WACVMVirtualMachineNameAndIdCompatibility ##
function Get-WACVMVirtualMachineNetworkSettings {
<#

.SYNOPSIS
Get the network settings for the passed in virtual machine

.DESCRIPTION
Get the network settings for the passed in virtual machine from this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER vmId
    The Id of the requested virtual machine.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $vmId
)

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue

enum SdnNetworkType {
    None = 0
    Vlan = 1
    Vnet = 2
    Lnet = 3
}

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-VirtualMachineNetworkSettings.ps1" -Scope Script
    Set-Variable -Name MinimumBandwidthAbsolute -Option ReadOnly -Value "MinimumBandwidthAbsolute" -Scope Script
    Set-Variable -Name BandwidthSetting -Option ReadOnly -Value "BandwidthSetting" -Scope Script
    Set-Variable -Name MaximumBandwidth -Option ReadOnly -Value "MaximumBandwidth" -Scope Script
    Set-Variable -Name IsolationMode -Option ReadOnly -Value "IsolationMode" -Scope Script
    Set-Variable -Name VlanMode -Option ReadOnly -Value "VlanMode" -Scope Script
    Set-Variable -Name AccessVlanId -Option ReadOnly -Value "AccessVlanId" -Scope Script
    Set-Variable -Name SdnOptions -Option ReadOnly -Value "SdnOptions" -Scope Script
}

<#

.SYNOPSIS
Clean up the script environment.

.DESCRIPTION
Clean up the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name MinimumBandwidthAbsolute -Scope Script -Force
    Remove-Variable -Name BandwidthSetting -Scope Script -Force
    Remove-Variable -Name MaximumBandwidth -Scope Script -Force
    Remove-Variable -Name IsolationMode -Scope Script -Force
    Remove-Variable -Name VlanMode -Scope Script -Force
    Remove-Variable -Name AccessVlanId -Scope Script -Force
    Remove-Variable -Name SdnOptions -Scope Script -Force
}

<#

.SYNOPSIS
Get the SDN Options for a given virtual network adapter.

.DESCRIPTION
Find the SDN options for the virtual network adapter, or return
an empty set when SDN is not being used.

#>

function getSdnOptions($adapter) {
    $sdnOptions = New-Object PSObject -Property @{
        virtualNetwork = $null;
        virtualSubnet = $null;
        sdnNetworkType = [SdnNetworkType]::None;
        ipAddress = $null;
        virtualIpConfigurations = @();
        shouldSetNetworkInterfaceIsPrimary = $false;
        securityTags = $null;
        logicalNetwork = $null;
        logicalSubnet = $null;
    }

    return $sdnOptions
}

<#

.SYNOPSIS
The main function.

.DESCRIPTION
The main function.

#>

function main() {
    return Get-RBACVM -id $vmId | Get-VMNetworkAdapter | Microsoft.PowerShell.Utility\Select-Object `
    name, `
    id, `
    vmname, `
    vmid, `
    SwitchName, `
    SwitchId, `
    IPAddresses, `
    MacAddress, `
    DynamicMacAddressEnabled, `
    MacAddressSpoofing, `
    Status, `
    isLegacy, `
    isDeleted, `
    connected, `
    @{Label=$MinimumBandwidthAbsolute;Expression={if ($_.$BandwidthSetting) {$_.$BandwidthSetting.$MinimumBandwidthAbsolute} else {0}}}, `
    @{Label=$MaximumBandwidth;Expression={if ($_.$BandwidthSetting) {$_.$BandwidthSetting.$MaximumBandwidth} else {0}}}, `
    @{Label=$IsolationMode;Expression={$_.IsolationSetting.$IsolationMode}}, `
    @{Label=$VlanMode;Expression={$_.VlanSetting.OperationMode}}, `
    @{Label=$AccessVlanId;Expression={$_.VlanSetting.$AccessVlanId}}, `
    @{Label=$SdnOptions;Expression={getSdnOptions $_}}
}

###############################################################################
# Script execution starts here.
###############################################################################

setupScriptEnv

try {
  Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

  $retVals =@()

  $module = Get-Module Hyper-V -ErrorAction SilentlyContinue
  if ($module) {
      $retVals = main
  } else {
      Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
      -Message "[$ScriptName]: Cannot continue because required Hyper-V PowerShell module was not found." -ErrorAction SilentlyContinue
  }
}
finally {
  cleanupScriptEnv
}

return $retVals

}
## [END] Get-WACVMVirtualMachineNetworkSettings ##
function Get-WACVMVirtualMachinePerformanceHistoricalData {
<#

.SYNOPSIS
Get the historical performance data for the passed in virtual machine.

.DESCRIPTION
Get the historical performance data for the passed in virtual machine from the cluster health service.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER vmId
    The Id of the requested virtual machine.

#>

param(
    [Parameter(Mandatory = $true)]
    [String]
    $vmId
)

Set-StrictMode -Version 5.0
Import-Module CimCmdlets -ErrorAction SilentlyContinue
Import-Module FailoverClusters -ErrorAction SilentlyContinue
Import-Module Microsoft.PowerShell.Management -ErrorAction SilentlyContinue
Import-Module Hyper-V -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

###############################################################################
# Constants
###############################################################################
Set-Variable TimeRangeHourValue -Option Constant -Value 0 -ErrorAction SilentlyContinue
Set-Variable TimeRangeDayValue -Option Constant -Value 1 -ErrorAction SilentlyContinue
Set-Variable TimeRangeWeekValue -Option Constant -Value 2 -ErrorAction SilentlyContinue
Set-Variable TimeRangeMonthValue -Option Constant -Value 3 -ErrorAction SilentlyContinue
Set-Variable TimeRangeYearValue -Option Constant -Value 4 -ErrorAction SilentlyContinue
Set-Variable MsConversion -Option Constant -Value 1000 -ErrorAction SilentlyContinue
Set-Variable BitToByteConversion -Option Constant -Value 0.125 -ErrorAction SilentlyContinue
Set-Variable -Name LogName -Option Constant -Value "Microsoft-ServerManagementExperience" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SMEScripts" -ErrorAction SilentlyContinue
Set-Variable -Name ScriptName -Option Constant -Value "Get-VirtualMachinePerformanceHistoricalData.ps1" -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Determines if Britannica (sddc management resources) are available on the server

.DESCRIPTION
Use the existance of the cim namespace root/sddc to determine if Britannica
is supported or not.

#>
function isBritannicaEnabled() {
    return !!(Get-CimInstance -Namespace "root\SDDC\Management" -ClassName SDDC_VirtualMachine -ErrorAction SilentlyContinue)
}

<#

.SYNOPSIS
Determines if the current cluster supports Failover Clusters Time Series Database.

.DESCRIPTION
Use the existance of the path value of cmdlet Get-StorageHealthSetting to determine if TSDB
is supported or not.

#>
function isTsdbEnabled() {
    $path = $null
    if ((Get-Command Get-StorageSubSystem -ErrorAction SilentlyContinue) -and (Get-Command Get-StorageHealthSetting -ErrorAction SilentlyContinue)) {
        $path = Get-StorageSubSystem clus* | Get-StorageHealthSetting -Name "System.PerformanceHistory.Path" -ErrorAction SilentlyContinue
    }
    return !!$path
}

<#

.SYNOPSIS
Get historical data from Britannica (sddc management resources)

.DESCRIPTION
Get raw historical hourly, daily, weekly, monthly, yearly data from Britannica

#>
function getDataFromBritannica()
{
    $vm = Get-CimInstance -Namespace "root\SDDC\Management" -ClassName SDDC_VirtualMachine | Where-Object {$_.Id -ieq $vmId}
    if (!$vm) {
        return $null
    }

    $returnValues = @{}

    $returnValues.hourlyCpuRaw = getMetrics $vm "VM.Cpu.Usage" $TimeRangeHourValue
    $returnValues.dailyCpuRaw = getMetrics $vm "VM.Cpu.Usage" $TimeRangeDayValue
    $returnValues.weeklyCpuRaw = getMetrics $vm "VM.Cpu.Usage" $TimeRangeWeekValue
    $returnValues.monthlyCpuRaw = getMetrics $vm "VM.Cpu.Usage" $TimeRangeMonthValue
    $returnValues.yearlyCpuRaw = getMetrics $vm "VM.Cpu.Usage" $TimeRangeYearValue

    $returnValues.hourlyMemoryRaw = getMetrics $vm "VM.Memory.Assigned" $TimeRangeHourValue
    $returnValues.dailyMemoryRaw = getMetrics $vm "VM.Memory.Assigned" $TimeRangeDayValue
    $returnValues.weeklyMemoryRaw = getMetrics $vm "VM.Memory.Assigned" $TimeRangeWeekValue
    $returnValues.monthlyMemoryRaw = getMetrics $vm "VM.Memory.Assigned" $TimeRangeMonthValue
    $returnValues.yearlyMemoryRaw = getMetrics $vm "VM.Memory.Assigned" $TimeRangeYearValue

    $returnValues.hourlyNetworkRaw = getMetrics $vm "VMNetworkAdapter.Bandwidth.Total" $TimeRangeHourValue
    $returnValues.dailyNetworkRaw = getMetrics $vm "VMNetworkAdapter.Bandwidth.Total" $TimeRangeDayValue
    $returnValues.weeklyNetworkRaw = getMetrics $vm "VMNetworkAdapter.Bandwidth.Total" $TimeRangeWeekValue
    $returnValues.monthlyNetworkRaw = getMetrics $vm "VMNetworkAdapter.Bandwidth.Total" $TimeRangeMonthValue
    $returnValues.yearlyNetworkRaw = getMetrics $vm "VMNetworkAdapter.Bandwidth.Total" $TimeRangeYearValue

    $returnValues.hourlyIopsRaw = getMetrics $vm "VHD.IOPS.Total" $TimeRangeHourValue
    $returnValues.dailyIopsRaw = getMetrics $vm "VHD.IOPS.Total" $TimeRangeDayValue
    $returnValues.weeklyIopsRaw = getMetrics $vm "VHD.IOPS.Total" $TimeRangeWeekValue
    $returnValues.monthlyIopsRaw = getMetrics $vm "VHD.IOPS.Total" $TimeRangeMonthValue
    $returnValues.yearlyIopsRaw = getMetrics $vm "VHD.IOPS.Total" $TimeRangeYearValue

    $returnValues.hourlyLatencyRaw = getMetrics $vm "VHD.Latency.Average" $TimeRangeHourValue
    $returnValues.dailyLatencyRaw = getMetrics $vm "VHD.Latency.Average" $TimeRangeDayValue
    $returnValues.weeklyLatencyRaw = getMetrics $vm "VHD.Latency.Average" $TimeRangeWeekValue
    $returnValues.monthlyLatencyRaw = getMetrics $vm "VHD.Latency.Average" $TimeRangeMonthValue
    $returnValues.yearlyLatencyRaw = getMetrics $vm "VHD.Latency.Average" $TimeRangeYearValue

    $returnValues.hourlyThroughputRaw = getMetrics $vm "VHD.Throughput.Total" $TimeRangeHourValue
    $returnValues.dailyThroughputRaw = getMetrics $vm "VHD.Throughput.Total" $TimeRangeDayValue
    $returnValues.weeklyThroughputRaw = getMetrics $vm "VHD.Throughput.Total" $TimeRangeWeekValue
    $returnValues.monthlyThroughputRaw = getMetrics $vm "VHD.Throughput.Total" $TimeRangeMonthValue
    $returnValues.yearlyThroughputRaw = getMetrics $vm "VHD.Throughput.Total" $TimeRangeYearValue

    return $returnValues
}

<#

.SYNOPSIS
Get historical metrics data from Britannica (sddc management resources)

.DESCRIPTION
Get raw data through cim method "GetMetrics" with given seriesName and timeFrame

.PARAMETER vm
The PsObject of target virtual machine

.PARAMETER seriesName
The string of seriesName for query argument

.PARAMETER timeFrame
The number of timeFrame for query argument

#>
function getMetrics {
    param(
        [Parameter(Mandatory = $true)]
        [PsObject]
        $vm,
        [Parameter(Mandatory = $true)]
        [string]
        $seriesName,
        [Parameter(Mandatory = $true)]
        [uint16]
        $timeFrame
    )

    # don't use !$timeFrame since it can be evaluated as $true when $timeFrame is zero
    if (!$vm -or !$seriesName -or ($null -eq $timeFrame)) {
        return $null
    }

    $metric = $vm | Invoke-CimMethod -MethodName "GetMetrics" -Arguments @{ SeriesName = $seriesName; TimeFrame = [uint16]$timeFrame}
    if ($metric -and $metric.Metric -and $metric.Metric.Datapoints) {
        return $metric.Metric.Datapoints
    } else {
        return $null
    }
}

<#

.SYNOPSIS
Get historical data from failover cluster TSDB (time series database)

.DESCRIPTION
Get raw historical hourly, daily, weekly, monthly, yearly data from failover cluster TSDB

#>
function getDataFromTsdb()
{
    $vm = Get-RBACVM -id $vmId
    if ($vm -eq $null) {
        return $null
    }

    $returnValues = @{}

    $returnValues.hourlyCpuRaw = getPerfHistory $vm "VM.Cpu.Usage" "LastHour"
    $returnValues.dailyCpuRaw = getPerfHistory $vm "VM.Cpu.Usage" "LastDay"
    $returnValues.weeklyCpuRaw = getPerfHistory $vm "VM.Cpu.Usage" "LastWeek"
    $returnValues.monthlyCpuRaw = getPerfHistory $vm "VM.Cpu.Usage" "LastMonth"
    $returnValues.yearlyCpuRaw = getPerfHistory $vm "VM.Cpu.Usage" "LastYear"

    $returnValues.hourlyMemoryRaw = getPerfHistory $vm "VM.Memory.Assigned" "LastHour"
    $returnValues.dailyMemoryRaw = getPerfHistory $vm "VM.Memory.Assigned" "LastDay"
    $returnValues.weeklyMemoryRaw = getPerfHistory $vm "VM.Memory.Assigned" "LastWeek"
    $returnValues.monthlyMemoryRaw = getPerfHistory $vm "VM.Memory.Assigned" "LastMonth"
    $returnValues.yearlyMemoryRaw = getPerfHistory $vm "VM.Memory.Assigned" "LastYear"

    $returnValues.hourlyNetworkRaw = getPerfHistory $vm "VMNetworkAdapter.Bandwidth.Total" "LastHour"
    $returnValues.dailyNetworkRaw = getPerfHistory $vm "VMNetworkAdapter.Bandwidth.Total" "LastDay"
    $returnValues.weeklyNetworkRaw = getPerfHistory $vm "VMNetworkAdapter.Bandwidth.Total" "LastWeek"
    $returnValues.monthlyNetworkRaw = getPerfHistory $vm "VMNetworkAdapter.Bandwidth.Total" "LastMonth"
    $returnValues.yearlyNetworkRaw = getPerfHistory $vm "VMNetworkAdapter.Bandwidth.Total" "LastYear"

    $returnValues.hourlyIopsRaw = getPerfHistory $vm "VHD.IOPS.Total" "LastHour"
    $returnValues.dailyIopsRaw = getPerfHistory $vm "VHD.IOPS.Total" "LastDay"
    $returnValues.weeklyIopsRaw = getPerfHistory $vm "VHD.IOPS.Total" "LastWeek"
    $returnValues.monthlyIopsRaw = getPerfHistory $vm "VHD.IOPS.Total" "LastMonth"
    $returnValues.yearlyIopsRaw = getPerfHistory $vm "VHD.IOPS.Total" "LastYear"

    $returnValues.hourlyLatencyRaw = getPerfHistory $vm "VHD.Latency.Average" "LastHour"
    $returnValues.dailyLatencyRaw = getPerfHistory $vm "VHD.Latency.Average" "LastDay"
    $returnValues.weeklyLatencyRaw = getPerfHistory $vm "VHD.Latency.Average" "LastWeek"
    $returnValues.monthlyLatencyRaw = getPerfHistory $vm "VHD.Latency.Average" "LastMonth"
    $returnValues.yearlyLatencyRaw = getPerfHistory $vm "VHD.Latency.Average" "LastYear"

    $returnValues.hourlyThroughputRaw = getPerfHistory $vm "VHD.Throughput.Total" "LastHour"
    $returnValues.dailyThroughputRaw = getPerfHistory $vm "VHD.Throughput.Total" "LastDay"
    $returnValues.weeklyThroughputRaw = getPerfHistory $vm "VHD.Throughput.Total" "LastWeek"
    $returnValues.monthlyThroughputRaw = getPerfHistory $vm "VHD.Throughput.Total" "LastMonth"
    $returnValues.yearlyThroughputRaw = getPerfHistory $vm "VHD.Throughput.Total" "LastYear"

    return $returnValues
}

<#

.SYNOPSIS
Get performance historical data from failover cluster TSDB (time series database)

.DESCRIPTION
Get raw data through Get-ClusterPerformanceHistory with given seriesName and timeFrame

.PARAMETER vm
The PsObject of target virtual machine

.PARAMETER seriesName
The string of seriesName for query argument

.PARAMETER timeFrame
The string of timeFrame for query argument

#>
function getPerfHistory {
    param(
        [Parameter(Mandatory = $true)]
        [PsObject]
        $vm,
        [Parameter(Mandatory = $true)]
        [string]
        $seriesName,
        [Parameter(Mandatory = $true)]
        [string]
        $timeFrame
    )

    if (!$vm -or !$seriesName -or (!$timeFrame)) {
        return $null
    }

    return $vm | Get-ClusterPerformanceHistory -VMSeriesName $seriesName -TimeFrame $timeFrame
}

<#

.SYNOPSIS
Create all graph data from Britannica raw data

.DESCRIPTION
Create all graph data from Britannica raw data

#>
function createAllGraphDataFromBritannica() {
    $rawData = getDataFromBritannica
    if ($null -eq $rawData){
        return $null
    }

    $returnValues = @{}

    $returnValues.hourlyCpu = createGraphDataFromBritannica $rawData.hourlyCpuRaw
    $returnValues.dailyCpu = createGraphDataFromBritannica $rawData.dailyCpuRaw
    $returnValues.weeklyCpu = createGraphDataFromBritannica $rawData.weeklyCpuRaw
    $returnValues.monthlyCpu = createGraphDataFromBritannica $rawData.monthlyCpuRaw
    $returnValues.yearlyCpu = createGraphDataFromBritannica $rawData.yearlyCpuRaw

    $returnValues.hourlyMemory = createGraphDataFromBritannica $rawData.hourlyMemoryRaw
    $returnValues.dailyMemory = createGraphDataFromBritannica $rawData.dailyMemoryRaw
    $returnValues.weeklyMemory = createGraphDataFromBritannica $rawData.weeklyMemoryRaw
    $returnValues.monthlyMemory = createGraphDataFromBritannica $rawData.monthlyMemoryRaw
    $returnValues.yearlyMemory = createGraphDataFromBritannica $rawData.yearlyMemoryRaw

    $returnValues.hourlyNetwork = createGraphDataFromBritannica $rawData.hourlyNetworkRaw $BitToByteConversion
    $returnValues.dailyNetwork = createGraphDataFromBritannica $rawData.dailyNetworkRaw $BitToByteConversion
    $returnValues.weeklyNetwork = createGraphDataFromBritannica $rawData.weeklyNetworkRaw $BitToByteConversion
    $returnValues.monthlyNetwork = createGraphDataFromBritannica $rawData.monthlyNetworkRaw $BitToByteConversion
    $returnValues.yearlyNetwork = createGraphDataFromBritannica $rawData.yearlyNetworkRaw $BitToByteConversion

    $returnValues.hourlyIops = createGraphDataFromBritannica $rawData.hourlyIopsRaw
    $returnValues.dailyIops = createGraphDataFromBritannica $rawData.dailyIopsRaw
    $returnValues.weeklyIops = createGraphDataFromBritannica $rawData.weeklyIopsRaw
    $returnValues.monthlyIops = createGraphDataFromBritannica $rawData.monthlyIopsRaw
    $returnValues.yearlyIops = createGraphDataFromBritannica $rawData.yearlyIopsRaw

    $returnValues.hourlyLatency = createGraphDataFromBritannica $rawData.hourlyLatencyRaw $MsConversion
    $returnValues.dailyLatency = createGraphDataFromBritannica $rawData.dailyLatencyRaw $MsConversion
    $returnValues.weeklyLatency = createGraphDataFromBritannica $rawData.weeklyLatencyRaw $MsConversion
    $returnValues.monthlyLatency = createGraphDataFromBritannica $rawData.monthlyLatencyRaw $MsConversion
    $returnValues.yearlyLatency = createGraphDataFromBritannica $rawData.yearlyLatencyRaw $MsConversion

    $returnValues.hourlyThroughput = createGraphDataFromBritannica $rawData.hourlyThroughputRaw
    $returnValues.dailyThroughput = createGraphDataFromBritannica $rawData.dailyThroughputRaw
    $returnValues.weeklyThroughput = createGraphDataFromBritannica $rawData.weeklyThroughputRaw
    $returnValues.monthlyThroughput = createGraphDataFromBritannica $rawData.monthlyThroughputRaw
    $returnValues.yearlyThroughput = createGraphDataFromBritannica $rawData.yearlyThroughputRaw

    return $returnValues
}

<#

.SYNOPSIS
Create all graph data from TSDB raw data

.DESCRIPTION
Create all graph data from TSDB raw data

#>
function createAllGraphDataFromTsdb() {
    $rawData = getDataFromTsdb
    if ($null -eq $rawData){
        return $null
    }

    $returnValues = @{}

    $returnValues.hourlyCpu = createGraphDataFromTsdb $rawData.hourlyCpuRaw
    $returnValues.dailyCpu = createGraphDataFromTsdb $rawData.dailyCpuRaw
    $returnValues.weeklyCpu = createGraphDataFromTsdb $rawData.weeklyCpuRaw
    $returnValues.monthlyCpu = createGraphDataFromTsdb $rawData.monthlyCpuRaw
    $returnValues.yearlyCpu = createGraphDataFromTsdb $rawData.yearlyCpuRaw

    $returnValues.hourlyMemory = createGraphDataFromTsdb $rawData.hourlyMemoryRaw
    $returnValues.dailyMemory = createGraphDataFromTsdb $rawData.dailyMemoryRaw
    $returnValues.weeklyMemory = createGraphDataFromTsdb $rawData.weeklyMemoryRaw
    $returnValues.monthlyMemory = createGraphDataFromTsdb $rawData.monthlyMemoryRaw
    $returnValues.yearlyMemory = createGraphDataFromTsdb $rawData.yearlyMemoryRaw

    $returnValues.hourlyNetwork = createGraphDataFromTsdb $rawData.hourlyNetworkRaw $BitToByteConversion
    $returnValues.dailyNetwork = createGraphDataFromTsdb $rawData.dailyNetworkRaw $BitToByteConversion
    $returnValues.weeklyNetwork = createGraphDataFromTsdb $rawData.weeklyNetworkRaw $BitToByteConversion
    $returnValues.monthlyNetwork = createGraphDataFromTsdb $rawData.monthlyNetworkRaw $BitToByteConversion
    $returnValues.yearlyNetwork = createGraphDataFromTsdb $rawData.yearlyNetworkRaw $BitToByteConversion

    $returnValues.hourlyIops = createGraphDataFromTsdb $rawData.hourlyIopsRaw
    $returnValues.dailyIops = createGraphDataFromTsdb $rawData.dailyIopsRaw
    $returnValues.weeklyIops = createGraphDataFromTsdb $rawData.weeklyIopsRaw
    $returnValues.monthlyIops = createGraphDataFromTsdb $rawData.monthlyIopsRaw
    $returnValues.yearlyIops = createGraphDataFromTsdb $rawData.yearlyIopsRaw

    $returnValues.hourlyLatency = createGraphDataFromTsdb $rawData.hourlyLatencyRaw $MsConversion
    $returnValues.dailyLatency = createGraphDataFromTsdb $rawData.dailyLatencyRaw $MsConversion
    $returnValues.weeklyLatency = createGraphDataFromTsdb $rawData.weeklyLatencyRaw $MsConversion
    $returnValues.monthlyLatency = createGraphDataFromTsdb $rawData.monthlyLatencyRaw $MsConversion
    $returnValues.yearlyLatency = createGraphDataFromTsdb $rawData.yearlyLatencyRaw $MsConversion

    $returnValues.hourlyThroughput = createGraphDataFromTsdb $rawData.hourlyThroughputRaw
    $returnValues.dailyThroughput = createGraphDataFromTsdb $rawData.dailyThroughputRaw
    $returnValues.weeklyThroughput = createGraphDataFromTsdb $rawData.weeklyThroughputRaw
    $returnValues.monthlyThroughput = createGraphDataFromTsdb $rawData.monthlyThroughputRaw
    $returnValues.yearlyThroughput = createGraphDataFromTsdb $rawData.yearlyThroughputRaw

    return $returnValues
}

<#

.SYNOPSIS
Create graph data from Britannica raw data

.DESCRIPTION
Create graph data from Britannica raw data

.PARAMETER rawData
The array of dataValues, if might be null when the raw data is not avaiable

.PARAMETER conversion
The conversion number for value adjustment. This parameter is optional, default is 1

#>
function createGraphDataFromBritannica {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [array]
        $rawData,
        [Parameter(Mandatory = $false)]
        [float]
        $conversion = 1 #default
    )

    $graphData = New-Object System.Collections.ArrayList
    if ($rawData) {
        $graphData = $rawData | Microsoft.PowerShell.Utility\Select-Object @{N='Value'; E={[math]::Round($_.Value * $conversion,2)}}, TimeStamp
    }

    return $graphData
}

<#

.SYNOPSIS
Create graph data from TSDB raw data

.DESCRIPTION
Create graph data from TSDB raw data

.PARAMETER rawData
The array of dataValues, if might be null when the raw data is not avaiable

.PARAMETER conversion
The conversion number for value adjustment. This parameter is optional, default is 1

#>
function createGraphDataFromTsdb {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [array]
        $rawData,
        [Parameter(Mandatory = $false)]
        [float]
        $conversion = 1 #default
    )

    $graphData = New-Object System.Collections.ArrayList
    if ($rawData) {
        $graphData = $rawData | Microsoft.PowerShell.Utility\Select-Object @{N='Value'; E={[math]::Round($_.Value * $conversion,2)}}, @{N='TimeStamp'; E={$_.Time}}
    }

    return $graphData
}

<#

.SYNOPSIS
Get historical data

.DESCRIPTION
Get historical data from the Britannica first if avaiable, then Tsdb, otherwise return null
return $null means neither Britannica nor Tsdb is enabled

.PARAMETER vmId
The VM Id to use.

#>
function getHistoricalData([string]$vmId) {
    $isClusteredProp = Get-RBACVM -Id $vmId | Microsoft.PowerShell.Utility\Select-Object IsClustered

    if ($isClusteredProp.IsClustered -and (isBritannicaEnabled)) {
        return createAllGraphDataFromBritannica
    } elseif ($isClusteredProp.IsClustered -and (isTsdbEnabled)) {
        return createAllGraphDataFromTsdb
    }

    return $null
}

function main([string]$vmId) {
    $returnValues = getHistoricalData $vmId
    if ($returnValues) {

        $result = New-Object PSObject

        $result | Add-Member -MemberType NoteProperty -Name 'hourlyCpu' -Value $returnValues.hourlyCpu
        $result | Add-Member -MemberType NoteProperty -Name 'dailyCpu' -Value $returnValues.dailyCpu
        $result | Add-Member -MemberType NoteProperty -Name 'weeklyCpu' -Value $returnValues.weeklyCpu
        $result | Add-Member -MemberType NoteProperty -Name 'monthlyCpu' -Value $returnValues.monthlyCpu
        $result | Add-Member -MemberType NoteProperty -Name 'yearlyCpu' -Value $returnValues.yearlyCpu

        $result | Add-Member -MemberType NoteProperty -Name 'hourlyMemory' -Value $returnValues.hourlyMemory
        $result | Add-Member -MemberType NoteProperty -Name 'dailyMemory' -Value $returnValues.dailyMemory
        $result | Add-Member -MemberType NoteProperty -Name 'weeklyMemory' -Value $returnValues.weeklyMemory
        $result | Add-Member -MemberType NoteProperty -Name 'monthlyMemory' -Value $returnValues.monthlyMemory
        $result | Add-Member -MemberType NoteProperty -Name 'yearlyMemory' -Value $returnValues.yearlyMemory

        $result | Add-Member -MemberType NoteProperty -Name 'hourlyNetwork' -Value $returnValues.hourlyNetwork
        $result | Add-Member -MemberType NoteProperty -Name 'dailyNetwork' -Value $returnValues.dailyNetwork
        $result | Add-Member -MemberType NoteProperty -Name 'weeklyNetwork' -Value $returnValues.weeklyNetwork
        $result | Add-Member -MemberType NoteProperty -Name 'monthlyNetwork' -Value $returnValues.monthlyNetwork
        $result | Add-Member -MemberType NoteProperty -Name 'yearlyNetwork' -Value $returnValues.yearlyNetwork

        $result | Add-Member -MemberType NoteProperty -Name 'hourlyIops' -Value $returnValues.hourlyIops
        $result | Add-Member -MemberType NoteProperty -Name 'dailyIops' -Value $returnValues.dailyIops
        $result | Add-Member -MemberType NoteProperty -Name 'weeklyIops' -Value $returnValues.weeklyIops
        $result | Add-Member -MemberType NoteProperty -Name 'monthlyIops' -Value $returnValues.monthlyIops
        $result | Add-Member -MemberType NoteProperty -Name 'yearlyIops' -Value $returnValues.yearlyIops

        $result | Add-Member -MemberType NoteProperty -Name 'hourlyLatency' -Value $returnValues.hourlyLatency
        $result | Add-Member -MemberType NoteProperty -Name 'dailyLatency' -Value $returnValues.dailyLatency
        $result | Add-Member -MemberType NoteProperty -Name 'weeklyLatency' -Value $returnValues.weeklyLatency
        $result | Add-Member -MemberType NoteProperty -Name 'monthlyLatency' -Value $returnValues.monthlyLatency
        $result | Add-Member -MemberType NoteProperty -Name 'yearlyLatency' -Value $returnValues.yearlyLatency

        $result | Add-Member -MemberType NoteProperty -Name 'hourlyThroughput' -Value $returnValues.hourlyThroughput
        $result | Add-Member -MemberType NoteProperty -Name 'dailyThroughput' -Value $returnValues.dailyThroughput
        $result | Add-Member -MemberType NoteProperty -Name 'weeklyThroughput' -Value $returnValues.weeklyThroughput
        $result | Add-Member -MemberType NoteProperty -Name 'monthlyThroughput' -Value $returnValues.monthlyThroughput
        $result | Add-Member -MemberType NoteProperty -Name 'yearlyThroughput' -Value $returnValues.yearlyThroughput

        # return empty object will lead displaying empty chart
        return $result
    }

    # return $null will delete the chart
    return $null
}

$module = Get-Module -Name FailoverClusters -ErrorAction SilentlyContinue
if ($module) {
    return main $vmId
} else {
  # may not be cluster connection or node, return $null will delete the historical chart
  return $null
}

}
## [END] Get-WACVMVirtualMachinePerformanceHistoricalData ##
function Get-WACVMVirtualMachinePerformanceLiveData {
<#

.SYNOPSIS
Get the live performance data for the passed in virtual machine

.DESCRIPTION
Get the live performace data for the passed in virtual machine from this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER vmId
    The Id of the requested virtual machine.

#>

param(
    [Parameter(Mandatory = $true)]
    [String]
    $vmId
)

Set-StrictMode -Version 5.0
Import-Module CimCmdlets -ErrorAction SilentlyContinue
Import-Module Hyper-V -ErrorAction SilentlyContinue

###############################################################################
# Constants
###############################################################################
Set-Variable TimeRangeCurrentValue -Option Constant -Value 5 -ErrorAction SilentlyContinue
Set-Variable MsConversion -Option Constant -Value 1000 -ErrorAction SilentlyContinue
Set-Variable BitToByteConversion -Option Constant -Value 0.125 -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Reset old Iops data and set the first one.

.DESCRIPTION
Reset last 60 second values and set the first one with current value

#>

<#

.SYNOPSIS
Reset old data and set the first one.

.DESCRIPTION
Reset last 60 second values and set the first one with current value

.PARAMETER dataValues
The hashtable format of current value of each performance measurement.

#>
function ResetData {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]
        $dataValues
    )

    $Global:CpuData = [System.Collections.ArrayList]@()
    $Global:MemoryData = [System.Collections.ArrayList]@()
    $Global:NetworkData = [System.Collections.ArrayList]@()
    $Global:IopsData = [System.Collections.ArrayList]@()
    $Global:LatencyData = [System.Collections.ArrayList]@()
    $Global:ThroughputData = [System.Collections.ArrayList]@()

    for ($i = 0; $i -lt 59; $i++) {
        $Global:CpuData.Insert(0, 0)
        $Global:MemoryData.Insert(0, 0)
        $Global:NetworkData.Insert(0, 0)
        $Global:IopsData.Insert(0, 0)
        $Global:LatencyData.Insert(0, 0)
        $Global:ThroughputData.Insert(0, 0)
    }

    [void]$Global:CpuData.Add($dataValues.cpuUsage)
    [void]$Global:MemoryData.Add($dataValues.memoryAssigned)
    [void]$Global:NetworkData.Add($dataValues.adapterBytesPerSec)
    [void]$Global:IopsData.Add($dataValues.iops)
    if ($dataValues.latency) {
      [void]$Global:LatencyData.Insert(0, $dataValues.latency)
    } else {
      $Global:LatencyData = $null
    }
    [void]$Global:ThroughputData.Add($dataValues.throughput)

    $Global:Delta = 0
}

<#

.SYNOPSIS
Update data with current value.

.DESCRIPTION
Using current data to fill gap every second from current to last sampe data

.PARAMETER dataValues
The hashtable format of current value of each performance measurement.

#>
function UpdateData {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]
        $dataValues
    )

    $Global:Delta += ($Global:SampleTime - $Global:LastTime).TotalMilliseconds

    while ($Global:Delta -gt 1000) {
        $Global:Delta -= 1000

        [void]$Global:CpuData.Add($dataValues.cpuUsage)
        [void]$Global:MemoryData.Add($dataValues.memoryAssigned)
        [void]$Global:NetworkData.Add($dataValues.adapterBytesPerSec)
        [void]$Global:IopsData.Add($dataValues.iops)
        if ($Global:LatencyData -and $dataValues.latency) {
          [void]$Global:LatencyData.Add($dataValues.latency)
        }
        [void]$Global:ThroughputData.Add($dataValues.throughput)
    }

    $Global:CpuData = $Global:CpuData.GetRange($Global:CpuData.Count - 60, 60)
    $Global:MemoryData = $Global:MemoryData.GetRange($Global:MemoryData.Count - 60, 60)
    $Global:NetworkData = $Global:NetworkData.GetRange($Global:NetworkData.Count - 60, 60)
    $Global:IopsData = $Global:IopsData.GetRange($Global:IopsData.Count - 60, 60)
    if ($dataValues.latency) {
      $Global:LatencyData = $Global:LatencyData.GetRange($Global:LatencyData.Count - 60, 60)
    } else {
      $Global:LatencyData = $null
    }
    $Global:ThroughputData = $Global:ThroughputData.GetRange($Global:ThroughputData.Count - 60, 60)
}

<#

.SYNOPSIS
Determines if Britannica (sddc management resources) are available on the cluster

.DESCRIPTION
Use the existance of the cim namespace root/sddc to determine if Britannica
is supported or not.

#>
function isBritannicaEnabled() {
    return !!(Get-CimInstance -Namespace "root\SDDC\Management" -ClassName SDDC_VirtualMachine -ErrorAction SilentlyContinue)
}

<#

.SYNOPSIS
Determines if the current cluster supports Failover Clusters Time Series Database.

.DESCRIPTION
Use the existance of the path value of cmdlet Get-StorageHealthSetting to determine if TSDB
is supported or not.

#>
function isTsdbEnabled() {
    $path = $null

    if ((Get-Command Get-StorageSubSystem -ErrorAction SilentlyContinue) -and (Get-Command Get-StorageHealthSetting -ErrorAction SilentlyContinue)) {
        $path = Get-StorageSubSystem clus* | Get-StorageHealthSetting -Name "System.PerformanceHistory.Path" -ErrorAction SilentlyContinue
    }

    return !!$path
}

<#

.SYNOPSIS
Get current data from Britannica (sddc management resources)

.DESCRIPTION
Get iops and throughput data value from Britannica

#>
function getDataFromBritannica()
{
    $vm = Get-CimInstance -Namespace "root\SDDC\Management" -ClassName SDDC_VirtualMachine | `
        Where-Object {$_.Id -ieq $vmId}
    if (!$vm) {
        return $null
    }

    $returnValues = @{}

    $returnValues.cpuUsage = getMetrics $vm "VM.Cpu.Usage"
    $returnValues.memoryAssigned = getMetrics $vm "VM.Memory.Assigned"
    $returnValues.adapterBytesPerSec = getMetrics $vm "VMNetworkAdapter.Bandwidth.Total" $BitToByteConversion
    $returnValues.iops = getMetrics $vm "VHD.IOPS.Total"
    $returnValues.latency = getMetrics $vm "VHD.Latency.Average" $MsConversion
    $returnValues.throughput = getMetrics $vm "VHD.Throughput.Total"

    return $returnValues
}

<#

.SYNOPSIS
Get data from Britannica metric (sddc management resources)

.DESCRIPTION
Get raw data through cim method "GetMetrics" with given seriesName and timeFrame

.PARAMETER vm
The PsObject of target virtual machine

.PARAMETER seriesName
The seriesName for query argument

.PARAMETER conversion
The conversion number for value adjustment. This parameter is optional, default is 1

#>
function getMetrics {
    param(
        [Parameter(Mandatory = $true)]
        [PsObject]
        $vm,
        [Parameter(Mandatory = $true)]
        [string]
        $seriesName,
        [Parameter(Mandatory = $false)]
        [float]
        $conversion = 1 #default
    )

    if (!$vm -or !$seriesName) {
        return $null
    }

    $metric = $vm | Invoke-CimMethod -MethodName "GetMetrics" -Arguments @{ SeriesName = $seriesName; TimeFrame = [uint16]$TimeRangeCurrentValue}
    if ($metric.Metric -and $metric.Metric.Datapoints) {
        # remember current sample time stamp
        $Script:now = $metric.Metric.Datapoints[0].Timestamp
        return [math]::Round($metric.Metric.Datapoints[0].Value * $conversion, 2)
    }
    else {
        $Script:now = $null
        return $null
    }
}

<#

.SYNOPSIS
Get historical data from failover cluster TSDB (time series database)

.DESCRIPTION
Get raw historical hourly, daily, weekly, monthly, yearly data from failover cluster TSDB

#>
function getDataFromTsdb() {
    $vm = Get-RBACVM -id $vmId
    if (!$vm) {
        return $null
    }

    $returnValues = @{}

    $returnValues.cpu = getPerfHistory $vm "VM.Cpu.Usage"
    $returnValues.memory = getPerfHistory $vm "VM.Memory.Assigned"
    $returnValues.network = getPerfHistory $vm "VMNetworkAdapter.Bandwidth.Total" $BitToByteConversion
    $returnValues.iops = getPerfHistory $vm "VHD.IOPS.Total"
    $returnValues.latency = getPerfHistory $vm "VHD.Latency.Average" $MsConversion
    $returnValues.hourlyThroughputRaw = getPerfHistory $vm "VHD.Throughput.Total"
    return $returnValues
}

<#

.SYNOPSIS
Get performance historical data from failover cluster TSDB (time series database)

.DESCRIPTION
Get raw data through Get-ClusterPerformanceHistory with given seriesName

.PARAMETER vm
The PsObject of target virtual machine

.PARAMETER seriesName
The seriesName for query argument

.PARAMETER conversion
The conversion number for value adjustment. This parameter is optional, default is 1

#>
function getPerfHistory {
    param(
        [Parameter(Mandatory = $true)]
        [PsObject]
        $vm,
        [Parameter(Mandatory = $true)]
        [string]
        $seriesName,
        [Parameter(Mandatory = $false)]
        [float]
        $conversion = 1 #default
    )

    if (!$vm -or !$seriesName ) {
        return $null
    }

    $data = $vm | Get-ClusterPerformanceHistory -VMSeriesName $seriesName
    if ($data) {
        # remember current sample time stamp
        $Script:now = $data.Time
        return [math]::Round($data.Value * $conversion, 2)
    }
    else {
        $Script:now = $null
        return $null
    }
}

<#

.SYNOPSIS
Get current data for general

.DESCRIPTION
Get data value for general (no vhd latency data)

#>
function getDataFromGeneral() {
    $returnValues = @{}
    $Script:now = Get-Date
    $vm = Get-RBACVM -id $vmId

    if ($vm) {
        #CPU
        $returnValues.cpuUsage = $vm.CPUUsage

        #Memory
        $returnValues.memoryAssigned = $vm.MemoryAssigned

        #Virtual Network Adapter
        $networkAdapters = $vm.NetworkAdapters

        $adapterBytesPerSec = 0
        foreach ($networkAdapter in $networkAdapters) {
            $adapterId = $networkAdapter.AdapterId
            if ($null -eq $adapterId) {
                $idSplit = $networkAdapter.id.Split('\')
                $adapterId = $idSplit[$idSplit.Count - 1]
            }

            $hyperVVirtualNetworkAdapter = Get-CimInstance -ClassName Win32_PerfFormattedData_NvspNicStats_HyperVVirtualNetworkAdapter | Where-Object { $_.Name -and $_.Name.Contains($adapterId) }
            if ($hyperVVirtualNetworkAdapter) {
                $adapterBytesPerSec += $hyperVVirtualNetworkAdapter.BytesPerSec
            }
        }

        $returnValues.adapterBytesPerSec = [math]::Round($adapterBytesPerSec, 2)

        #Virtual Storage Device
        $vhd = Get-VHD -VMId $vm.VMId -ErrorVariable +vhdError -ErrorAction SilentlyContinue
        if ($vhd) {
            $vhdPaths = $vhd.Path

            $iopsTotal = 0
            $throughputTotal = 0

            foreach ($vhdPath in $vhdPaths) {
                $vhdPathNormalized = $vhdPath -replace "\\", "-"
                $virtualStorageDevice = Get-CimInstance -ClassName Win32_PerfFormattedData_Counters_HyperVVirtualStorageDevice | Where-Object { $_.Name -eq $vhdPathNormalized }

                if ($virtualStorageDevice) {
                    $iopsTotal += $virtualStorageDevice.ReadOperationsPerSec + $virtualStorageDevice.WriteOperationsPerSec
                    $throughputTotal += $virtualStorageDevice.ReadBytesPerSec + $virtualStorageDevice.WriteBytesPerSec
                }
            }

            $returnValues.iops = $iopsTotal
            $returnValues.latency = $null
            $returnValues.throughput = [math]::Round($throughputTotal, 2)
        }
        else {
            $returnValues.iops = 0
            $returnValues.latency = $null
            $returnValues.throughput = 0
        }

        if ($vhdError) {
            $err = @($vhdError)[0]
            if ($err.exception.ErrorIdentifier -eq "ObjectNotFound") {
                # one of VHDs could be physical drive, make it as progress message.
                Write-Progress -Activity "VHDObjectNotFound" -Status $err.Exception.Message
            }
            else {
                Write-Error $err
            }
        }
    }

    return $returnValues
}

<#

.SYNOPSIS
Get live data

.DESCRIPTION
Get live data from the Britannica first if avaiable, then HealthReport, otherwise return null

.PARAMETER vmId
The Id of the virtual machine.

#>
function getLiveData([string]$vmId) {
    $isClusteredProp = Get-RBACVM -Id $vmId | Microsoft.PowerShell.Utility\Select-Object IsClustered

    if ($isClusteredProp.IsClustered -and (isBritannicaEnabled)) {
        return getDataFromBritannica
    }
    elseif ($isClusteredProp.IsClustered -and (isTsdbEnabled)) {
        return getDataFromTsdb
    }
    else {
        return getDataFromGeneral
    }
}

<#

.SYNOPSIS
Create sample data array list

.DESCRIPTION
Create sample data array list for last 60 seconds

.PARAMETER dataValues
The hashtable format of current value of each performance measurement.

#>
function createDataList {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]
        $dataValues
    )

    # get sampling time and remember last sample time.
    $globalExists = Get-Variable SampleTime -Scope Global -ErrorAction SilentlyContinue

    if (-not $globalExists) {
        $Global:SampleTime = [System.DateTime]::Now
        $Global:LastTime = $Global:SampleTime

        ResetData $dataValues
    }
    else {
        $Global:LastTime = $Global:SampleTime
        $Global:SampleTime = [System.DateTime]::Now
        $elapsedTime = $Global:SampleTime - $Global:LastTime

        if ($elapsedTime -gt [System.TimeSpan]::FromSeconds(30)) {
            ResetData $dataValues
        }
        else {
            UpdateData $dataValues
        }
    }
}

<#

.SYNOPSIS
The main function

.DESCRIPTION
Get the chart data

.PARAMETER vmId
The Id of the VM...

#>

function main([string]$vmId) {
    $returnValues = getLiveData $vmId
    if ($returnValues) {
        createDataList $returnValues

        $result = New-Object PSObject
        $result | Add-Member -MemberType NoteProperty -Name 'Cpu' $Global:CpuData
        $result | Add-Member -MemberType NoteProperty -Name 'Memory' $Global:MemoryData
        $result | Add-Member -MemberType NoteProperty -Name 'Network' $Global:NetworkData
        $result | Add-Member -MemberType NoteProperty -Name 'Iops' $Global:IopsData
        $result | Add-Member -MemberType NoteProperty -Name "Latency" $Global:LatencyData
        $result | Add-Member -MemberType NoteProperty -Name 'Throughput' $Global:ThroughputData

        # return empty object will lead displaying empty chart
        return $result
    }

    # return $null will delete the chart
    return $null
}

###############################################################################
# Script execution starts here
###############################################################################

return main $vmId

}
## [END] Get-WACVMVirtualMachinePerformanceLiveData ##
function Get-WACVMVirtualMachineProcessorSettings {
<#

.SYNOPSIS
Get the processor (virtual CPU) settings for the passed in virtual machine.

.DESCRIPTION
Get the processor (virtual CPU) settings for the passed in virtual machine from this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER vmId
    The Id of the requested virtual machine.

#>

param (
    [Parameter(Mandatory = $true)]
    [string]
    $vmId
)

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue

<#

.SYNOPSIS
WindowsServerVersion

.DESCRIPTION
This enum is used for various Windows Server versions.

#>
enum WindowsServerVersion
{
    Unknown
    Server2008R2
    Server2012
    Server2012R2
    Server2016
    Server2019
}

<#

.SYNOPSIS
HypervisorSchedulerType

.DESCRIPTION
The Hypervisor scheduler type that is in effect on this host server.

#>

enum HypervisorSchedulerType {
    Unknown = 0
    ClassicSmtDisabled = 1
    Classic = 2
    Core = 3
    Root = 4
}

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.  Create read only (constant) variables
that add context to the said constants.

#>

function setupScriptEnv() {
    Set-Variable -Name ExposeVirtualizationExtensionsPropertyName -Option ReadOnly -Value "ExposeVirtualizationExtensions" -Scope Script
    Set-Variable -Name HwThreadCountPerCorePropertyName -Option ReadOnly -Value "HwThreadCountPerCore" -Scope Script
    Set-Variable -Name HypervisorEventChannelName -Option ReadOnly -Value "Microsoft-Windows-Hyper-V-Hypervisor" -Scope Script
    Set-Variable -Name Server2008R2BuildNumber -Option ReadOnly -Value 7600 -Scope Script
    Set-Variable -Name Server2012BuildNumber -Option ReadOnly -Value 9200 -Scope Script
    Set-Variable -Name Server2012R2BuildNumber -Option ReadOnly -Value 9600 -Scope Script
    Set-Variable -Name Server2016BuildNumber -Option ReadOnly -Value 14393 -Scope Script
    Set-Variable -Name Server2019BuildNumber -Option ReadOnly -Value 17763 -Scope Script
    Set-Variable -Name ClassicSmtDisabled -Option ReadOnly -Value "0x1" -Scope Script
    Set-Variable -Name Classic -Option ReadOnly -Value "0x2" -Scope Script
    Set-Variable -Name Core -Option ReadOnly -Value "0x3" -Scope Script
    Set-Variable -Name Root -Option ReadOnly -Value "0x4" -Scope Script
    Set-Variable -Name SmtEnabledPropertyName -Option ReadOnly -Value "smtEnabled" -Scope Script
    Set-Variable -Name DisableSmt -Option ReadOnly -Value 1 -Scope Script
    Set-Variable -Name EnableSmt -Option ReadOnly -Value 2 -Scope Script
    Set-Variable -Name InheritFromHost -Option ReadOnly -Value 0 -Scope Script
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-VirtualMachineProcessorSettings.ps1" -Scope Script
}

<#

.SYNOPSIS
Cleanup the script environment.

.DESCRIPTION
Cleanup the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name ExposeVirtualizationExtensionsPropertyName -Scope Script -Force
    Remove-Variable -Name HwThreadCountPerCorePropertyName -Scope Script -Force
    Remove-Variable -Name HypervisorEventChannelName -Scope Script -Force
    Remove-Variable -Name Server2008R2BuildNumber -Scope Script -Force
    Remove-Variable -Name Server2012BuildNumber -Scope Script -Force
    Remove-Variable -Name Server2012R2BuildNumber -Scope Script -Force
    Remove-Variable -Name Server2016BuildNumber -Scope Script -Force
    Remove-Variable -Name Server2019BuildNumber -Scope Script -Force
    Remove-Variable -Name ClassicSmtDisabled -Scope Script -Force
    Remove-Variable -Name Classic -Scope Script -Force
    Remove-Variable -Name Core -Scope Script -Force
    Remove-Variable -Name Root -Scope Script -Force
    Remove-Variable -Name SmtEnabledPropertyName -Scope Script -Force
    Remove-Variable -Name DisableSmt -Scope Script -Force
    Remove-Variable -Name EnableSmt -Scope Script -Force
    Remove-Variable -Name InheritFromHost -Scope Script -Force
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
}

<#

.SYNOPSIS
Get the Hypervisor scheduler type for this server.

.DESCRIPTION
Convert the event string value into an enum that is the current Hypervisor scheduler type.

The message looks like this:

 "Hypervisor scheduler type is 0x1."

 Since the hex value is all we care about this localized message should not be a problem...

#>

function getSchedulerType {
    $event = Get-WinEvent -FilterHashTable @{ProviderName = $HypervisorEventChannelName; ID = 2} -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object -First 1 Message

    # $event.message may not exist on downlevel servers
    if ($null -ne $event -AND $null -ne $event.message) {

        if ($event.message -match $ClassicSmtDisabled) {
            return [HypervisorSchedulerType]::ClassicSmtDisabled
        }

        if ($event.message -match $Classic) {
            return [HypervisorSchedulerType]::Classic
        }

        if ($event.message -match $Core) {
            return [HypervisorSchedulerType]::Core
        }

        if ($event.message -match $Root) {
            return [HypervisorSchedulerType]::Root
        }
    }

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Could not determine the HyperVisor scheduler type." -ErrorAction SilentlyContinue

    return [HypervisorSchedulerType]::Unknown
}

<#

.SYNOPSIS
Get the the build number for the OS installed on this server.

.DESCRIPTION
Get the the build number for the OS installed on this server.

#>

function getBuildNumber {
    return [System.Environment]::OSVersion.Version.Build
}

<#

.SYNOPSIS
Get the Windows Server version for the OS installed on this server.

.DESCRIPTION
Get the Windows Server version for the OS installed on this server.

#>

function getServerVersion {
    $build = getBuildNumber

    if ($build -eq $Server2008R2BuildNumber) {
        return [WindowsServerVersion]::Server2008R2
    }

    if ($build -eq $Server2012BuildNumber) {
        return [WindowsServerVersion]::Server2012
    }

    if ($build -eq $Server2012R2BuildNumber) {
        return [WindowsServerVersion]::Server2012R2
    }

    if ($build -eq $Server2016BuildNumber) {
        return [WindowsServerVersion]::Server2016
    }

    if ($build -ge $Server2019BuildNumber) {
        return [WindowsServerVersion]::Server2019
    }

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Unknown build number $build." -ErrorAction SilentlyContinue

    return [WindowsServerVersion]::Unknown
}

<#

.SYNOPSIS
Determine if this Windows Server 2016 server has been patched.

.DESCRIPTION
Returns true if the patch for CVE-2018-3646 has been installed on this Windows 2016 server.

#>

function isServer2016Patched {
    $event = Get-WinEvent -FilterHashTable @{ProviderName = $HypervisorEventChannelName; ID = 156}  -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object -First 1

    return !!$event
}

<#

.SYNOPSIS
Calculate the value of SmtEnabled meta-property.

.DESCRIPTION
Determine the correct value of SmtEnabled from the OsVersion and the HwThreadCountPerCore property.

#>

function getSmtEnabled([int] $hwThreadCountPerCore) {
    $schedulerType = getSchedulerType

    # If we cannot get, or do not have, a scheduler type then set the smtEnabled to false.
    if ($schedulerType -eq [HypervisorSchedulerType]::Unknown) {
        return $false
    }

    $serverVersion = getServerVersion
    $smtEnabled = $false                #default to false -- do not change!

    if ($serverVersion -eq [WindowsServerVersion]::Server2016) {

        # If the 2016 server has been patched then we can enable SMT on the VM if the HwThreadCountPerCore property is set.
        if (isServer2016Patched) {
            # When the scheduler type is Core.

            if ($schedulerType -eq [HypervisorSchedulerType]::Core) {
                $smtEnabled = ($hwThreadCountPerCore -eq $EnableSmt)
            }
        }

        return $smtEnabled
    }

    if ($serverVersion -ge [WindowsServerVersion]::Server2019) {

        # When the scheduler type is Core.
        if ($schedulerType -eq [HypervisorSchedulerType]::Core) {
            $smtEnabled = ($hwThreadCountPerCore -eq $InheritFromHost) -or ($hwThreadCountPerCore -eq $EnableSmt)
        }

        return $smtEnabled
    }

    # Unknown, or unexpected, server version -- force the result to false.
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Couldn't calculate if SMT is enabled because of an unknown server version $serverVersion." -ErrorAction SilentlyContinue

    return $false
}

<#

.SYNOPSIS
Get the processor settings for the passed in VM.

.DESCRIPTION
Get the processor settings for the passed in VM.

#>

function getSettings($vm) {
    return $vm | Get-VMProcessor | Microsoft.PowerShell.Utility\Select-Object `
        VMName, `
        VMId, `
        Count, `
        CompatibilityForMigrationEnabled, `
        CompatibilityForMigrationMode, `
        CompatibilityForOlderOperatingSystemsEnabled, `
        Reserve, `
        Maximum, `
        RelativeWeight, `
        $HwThreadCountPerCorePropertyName, `
        MaximumCountPerNumaNode, `
        MaximumCountPerNumaSocket, `
        IsDeleted, `
        @{Name=$ExposeVirtualizationExtensionsPropertyName; Expression={if ($_.PSObject.Properties.Match($ExposeVirtualizationExtensionsPropertyName).Count -gt 0) {$_.$ExposeVirtualizationExtensionsPropertyName} else {$null}}}
}

<#

.SYNOPSIS
Main

.DESCRIPTION
An explicit main function to fetch the settings.

#>

function main([string] $vmId) {
    $vm = Get-RBACVM -id $vmId

    $settings = getSettings $vm

    $smtEnabled = getSmtEnabled $settings.$HwThreadCountPerCorePropertyName
    Add-Member -InputObject $settings -MemberType NoteProperty -Name $SmtEnabledPropertyName -Value $smtEnabled

    return $settings
}

###############################################################################
# Script execution starts here!
###############################################################################
if (-not ($env:pester)) {
    setupScriptEnv

    try {
        Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

        $module = Get-Module -Name Hyper-V -ErrorAction SilentlyContinue
        if ($module) {
            return main $vmId
        }

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: The required PowerShell module (Hyper-V) was not found." -ErrorAction SilentlyContinue

        return @{}
    } finally {
        cleanupScriptEnv
    }
}

}
## [END] Get-WACVMVirtualMachineProcessorSettings ##
function Get-WACVMVirtualMachineSecuritySettings {
<#

.SYNOPSIS
Gets the Virtual Machine Security Settings

.ROLE
Readers

.PARAMETER vmId
    The Id of the requested virtual machine.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $vmId
)

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue

<#

.SYNOPSIS
A general enumeration for functions that switch on and off.

.DESCRIPTION
Maps to  Microsoft.HyperV.PowerShell.OnOffState

#>

enum OnOffState
{
    On
    Off
}

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-VirtualMachineSecuritySettings" -Scope Script
    Set-Variable -Name GenerationPropertyName -Option ReadOnly -Value "Generation" -Scope Script
    Set-Variable -Name Generation2 -Option ReadOnly -Value 2 -Scope Script
    Set-Variable -Name SecureBootPropertyName -Option ReadOnly -Value "SecureBoot" -Scope Script
    Set-Variable -Name TemplateIdPropertyName -Option ReadOnly -Value "TemplateId" -Scope Script
    Set-Variable -Name IdPropertyName -Option ReadOnly -Value "Id" -Scope Script
    Set-Variable -Name SecureBootTemplateIdPropertyName -Option ReadOnly -Value "SecureBootTemplateId" -Scope Script
    Set-Variable -Name TrustedPlatformPropertyName -Option ReadOnly -Value "TrustedPlatform" -Scope Script
    Set-Variable -Name EncryptMigrationPropertyName -Option ReadOnly -Value "EncryptMigration" -Scope Script
    Set-Variable -Name ShieldedPropertyName -Option ReadOnly -Value "Shielded" -Scope Script
    Set-Variable -Name GetVMSecurityCmdletName -Option ReadOnly -Value "Get-VMSecurity" -Scope Script
} 

<#

.SYNOPSIS
Clean up the script environment.

.DESCRIPTION
Clean up the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name GenerationPropertyName -Scope Script -Force
    Remove-Variable -Name Generation2 -Scope Script -Force
    Remove-Variable -Name SecureBootPropertyName -Scope Script -Force
    Remove-Variable -Name TemplateIdPropertyName -Scope Script -Force
    Remove-Variable -Name IdPropertyName -Scope Script -Force
    Remove-Variable -Name SecureBootTemplateIdPropertyName -Scope Script -Force
    Remove-Variable -Name TrustedPlatformPropertyName -Scope Script -Force
    Remove-Variable -Name EncryptMigrationPropertyName -Scope Script -Force
    Remove-Variable -Name ShieldedPropertyName -Scope Script -Force
    Remove-Variable -Name GetVMSecurityCmdletName -Scope Script -Force
}

<#

.SYNOPSIS
Gets the firmware configuration of a virtual machine

.DESCRIPTION
Get values for:
- id (VMId)
- Secure boot status
- The ID of the secure boot template

#>
function getVMFirmware($vm) {
    $result = @{}
    $result.$IdPropertyName = $null
    $result.$SecureBootPropertyName = $null
    $result.$TemplateIdPropertyName = $null

    $fw = $vm | Get-VMFirmware -ErrorAction SilentlyContinue -ErrorVariable +err
    if ($fw) {
        $result.$IdPropertyName = $fw.VMId
        $result.$SecureBootPropertyName = $fw.$SecureBootPropertyName -eq [OnOffState]::On

        if (Get-Member -InputObject $fw -Name $SecureBootTemplateIdPropertyName -Membertype Properties) {
            $result.templateId = $fw.$SecureBootTemplateIdPropertyName
        } else {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
            -Message "[$ScriptName]: Virtual machine firmware settings for virtual machine $vm.Name did not contain $SecureBootTemplateIdPropertyName property." -ErrorAction SilentlyContinue
        }
    } else {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Could not get the virtual machine firmware settings for virtual machine $vm.Name. Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]
    }

    return $result
}

<#

.SYNOPSIS
Gets security information about a virtual machine.

.DESCRIPTION
Get status of:
- TPM (Trusted Platform Module)
- Encryption of virtual machine state and migration traffic
- Shield

#>
function getVMSecurity($vm) {
    $result = @{}

    $result.$TrustedPlatformPropertyName = $null
    $result.$EncryptMigrationPropertyName = $null
    $result.$ShieldedPropertyName = $null

    if (Get-Command $GetVMSecurityCmdletName -ErrorAction SilentlyContinue){
        $vms = $vm | Get-VMSecurity -ErrorAction SilentlyContinue -ErrorVariable +err

        if ($vms) {
            $result.$TrustedPlatformPropertyName = $vms.TpmEnabled
            $result.$EncryptMigrationPropertyName = $vms.EncryptStateAndVmMigrationTraffic
            $result.$ShieldedPropertyName = $vms.Shielded
        } else {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Could not get the virtual machine security settings for virtual machine $vm.Name. Error: $err" -ErrorAction SilentlyContinue

            Write-Error @($err)[0]
        }
    } else {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Required Hyper-V PowerShell cmdlet $GetVMSecurityCmdletName was not found." -ErrorAction SilentlyContinue
    }

    return $result
}

<#

.SYNOPSIS
Gets security settings of a virtual machine.

.DESCRIPTION
Gets security settings of a virtual machine.

#>

function getSecuritySettings($vm) {
    $result = New-Object PSObject

    if (Get-Member -InputObject $vm -Name $GenerationPropertyName -Membertype Properties) {
        if ($vm.Generation -ge $Generation2){
            $fw = getVMFirmware $vm
            $vms = getVMSecurity $vm

            $result | Add-Member -MemberType NoteProperty -Name $IdPropertyName -Value $fw.$IdPropertyName
            $result | Add-Member -MemberType NoteProperty -Name $SecureBootPropertyName -Value $fw.$SecureBootPropertyName
            $result | Add-Member -MemberType NoteProperty -Name $TemplateIdPropertyName -Value $fw.$TemplateIdPropertyName
            $result | Add-Member -MemberType NoteProperty -Name $TrustedPlatformPropertyName -Value $vms.$TrustedPlatformPropertyName
            $result | Add-Member -MemberType NoteProperty -Name $EncryptMigrationPropertyName -Value $vms.$EncryptMigrationPropertyName
            $result | Add-Member -MemberType NoteProperty -Name $ShieldedPropertyName -Value $vms.$ShieldedPropertyName
        }
    }

    return $result
}

<#

.SYNOPSIS
Main function.

.DESCRIPTION
Main function.

#>

function main([string] $vmId) {
    $vm = Get-RBACVM -Id $vmId -ErrorAction SilentlyContinue -ErrorVariable +err
    if ($vm) {
        return getSecuritySettings $vm
    }

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
    -Message "[$ScriptName]: Could not find VM with Id $vmId. Error: $err" -ErrorAction SilentlyContinue

    Write-Error @($err)[0]

    return @{}
}

###############################################################################
# Script execution starts here...
###############################################################################

$retValue = @{}

setupScriptEnv

try {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    $module = Get-Module -Name Hyper-V -ErrorAction SilentlyContinue -ErrorVariable +err
    if ($module) {
        $retValue = main $vmId
    } else {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Cannot continue because required Hyper-V PowerShell module was not found." -ErrorAction SilentlyContinue

        Write-Error @($err)[0]
    }
} finally {
    cleanupScriptEnv
}

return $retValue
}
## [END] Get-WACVMVirtualMachineSecuritySettings ##
function Get-WACVMVirtualMachineServer {
<#

.SYNOPSIS
Get informaiton about this hosting server.

.DESCRIPTION
Get information about this hosting server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0;
Import-Module CimCmdlets;

$result = New-Object psobject

$hardware = Get-CimInstance -ClassName Win32_ComputerSystem | Microsoft.PowerShell.Utility\Select-Object Name, Model, Manufacturer
$result | Add-Member -MemberType NoteProperty -Name Name -Value $hardware.Name
$result | Add-Member -MemberType NoteProperty -Name Model -Value $hardware.Model
$result | Add-Member -MemberType NoteProperty -Name Manufacturer -Value $hardware.Manufacturer

$serialNumber = Get-CimInstance -ClassName Win32_SystemEnclosure | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty SerialNumber
$result | Add-Member -MemberType NoteProperty -Name SerialNumber -Value $serialNumber

$osMemory = Get-CimInstance -ClassName Win32_OperatingSystem | Microsoft.PowerShell.Utility\Select-Object FreePhysicalMemory, TotalVisibleMemorySize
$result | Add-Member -MemberType NoteProperty -Name Memory `
    -Value $([Math]::Round(100*($osMemory.TotalVisibleMemorySize-$osMemory.FreePhysicalMemory)/$osMemory.TotalVisibleMemorySize, 2))

$cpuUsages = (Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Processor | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty PercentProcessorTime) | `
    Microsoft.PowerShell.Utility\Measure-Object -Sum
$result | Add-Member -MemberType NoteProperty -Name Compute -Value $([Math]::Round(100*($cpuUsages.Sum/($cpuUsages.Count*100)), 2))

Write-Output $result

}
## [END] Get-WACVMVirtualMachineServer ##
function Get-WACVMVirtualMachineSettings {
<#

.SYNOPSIS
Get the general settings for the passed in virtual machine.

.DESCRIPTION
Get the general settings for the passed in virtual machine from this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER vmId
    The Id of the requested virtual machine.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $vmId
)

Set-StrictMode -Version 5.0;
Import-Module Hyper-V;

Get-RBACVM -id $vmId | `
    Microsoft.PowerShell.Utility\Select-Object `
    name, `
    id, `
    SmartPagingFilePath, `
    SmartPagingFileInUse, `
    AutomaticStartAction, `
    AutomaticStartDelay, `
    AutomaticStopAction, `
    AutomaticCriticalErrorAction, `
    AutomaticCriticalErrorActionTimeout, `
    ConfigurationLocation, `
    IsDeleted, `
    Notes, `
    Generation, `
    State

}
## [END] Get-WACVMVirtualMachineSettings ##
function Get-WACVMVirtualMachineVhds {
<#

.SYNOPSIS
Gets the virtual hard disks (VHD) for the passed in virtual machine.

.DESCRIPTION
Gets the virtual hard disks (VHD) for the passed in virtual machine from this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER vmId
    The Id of the requested virtual machine.

#>

param (
    [Parameter(Mandatory = $true)]
    [String] $vmId
)

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue
Import-Module Microsoft.PowerShell.Management -ErrorAction SilentlyContinue
Import-Module CimCmdlets -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.  Create read only (constant) variables
that add context to the said constants.

#>

function setupScriptEnv() {
##SkipCheck=true##
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-VirtualMachineVhds" -Scope Script
    Set-Variable -Name PathPropertyName -Option ReadOnly -Value "Path" -Scope Script
	Set-Variable -Name NamePropertyName -Option ReadOnly -Value "Name" -Scope Script
    Set-Variable -Name BritannicaNamespace -Option ReadOnly -Value "root\SDDC\Management" -Scope Script
    Set-Variable -Name BritannicaVirtualMachineClassName -Option ReadOnly -Value "SDDC_VirtualMachine" -Scope Script
	Set-Variable -Name FileSizePropertyName -Option ReadOnly -Value "FileSize" -Scope Script
	Set-Variable -Name SizeUsedPropertyName -Option ReadOnly -Value "SizeUsed" -Scope Script
	Set-Variable -Name StorageVolumeIdPropertyName -Option ReadOnly -Value "StorageVolumeId" -Scope Script
	Set-Variable -Name FileSharePropertyName -Option ReadOnly -Value "FileShare" -Scope Script
	Set-Variable -Name VhdsFromBritannicaVirtualMachineQueryName -Option ReadOnly -Value "select vhds from sddc_virtualmachine where id='{0}'" -Scope Script
	Set-Variable -Name ClusteredVirtualkMachineQueryName -Option ReadOnly -Value "Select PrivateProperties from MSCluster_Resource where Type='Virtual Machine' and PrivateProperties.VmId='{0}'" -Scope Script
    Set-Variable -Name MSClusterNamespace -Option ReadOnly -Value "root\MSCluster" -Scope Script
    Set-Variable -Name MSClusterResourceClassName -Option ReadOnly -Value "MSCluster_Resource" -Scope Script
    Set-Variable -Name ReservedRegex -Option ReadOnly -Value '[^<>:""\\/\?\*|]' -Scope Script
    Set-Variable -Name UNCPathRegex -Option ReadOnly -Value '^\\\\(?<server>R+?)\\*?\\(?<share>R+?)(?<dirs>(\\R*?)*)$' -Scope Script
    Set-Variable -Name RegexReplacementChar -Option ReadOnly -Value "R" -Scope Script
##SkipCheck=false##
}

<#

.SYNOPSIS
Cleanup the script environment.

.DESCRIPTION
Cleanup the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name PathPropertyName -Scope Script -Force
	Remove-Variable -Name NamePropertyName -Scope Script -Force
    Remove-Variable -Name BritannicaNamespace -Scope Script -Force
    Remove-Variable -Name BritannicaVirtualMachineClassName -Scope Script -Force
	Remove-Variable -Name FileSizePropertyName -Scope Script -Force
	Remove-Variable -Name SizeUsedPropertyName -Scope Script -Force
	Remove-Variable -Name StorageVolumeIdPropertyName -Scope Script -Force
	Remove-Variable -Name FileSharePropertyName -Scope Script -Force
	Remove-Variable -Name VhdsFromBritannicaVirtualMachineQueryName -Scope Script -Force
	Remove-Variable -Name ClusteredVirtualkMachineQueryName -Scope Script -Force
	Remove-Variable -Name MSClusterNamespace -Scope Script -Force
	Remove-Variable -Name MSClusterResourceClassName -Scope Script -Force
	Remove-Variable -Name ReservedRegex -Scope Script -Force
	Remove-Variable -Name UNCPathRegex -Scope Script -Force
	Remove-Variable -Name RegexReplacementChar -Scope Script -Force
}

<#

.SYNOPSIS
Determines if the passed n VM Id is a clustered VM or not.

.DESCRIPTION
Return true when the passed in VM is clustered.

#>

function isVmClustered([string] $vmId) {
    if (isMSClusterAvailable) {
        $queryString = $ClusteredVirtualkMachineQueryName -f $vmId
        $vmResource = Get-CimInstance -Namespace $MSClusterNamespace -Query $queryString -ErrorAction SilentlyContinue

        return $null -ne $vmResource
    }

    return $false
}

<#

.SYNOPSIS
Determines if Britannica (sddc management resources) virtualization is available on the cluster

.DESCRIPTION
Use the existance of the cim namespace root/sddc to determine if Britannica
is supported or not.

#>

function isBritannicaVirtualizationAvailable() {
    $class = Get-WmiObject -Namespace $BritannicaNamespace -ClassName $BritannicaVirtualMachineClassName -List -ErrorAction SilentlyContinue -ErrorVariable err

    if (-not($class)) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Couldn't get the required CIM namespace $BritannicaNamespace. Error: $err" -ErrorAction SilentlyContinue
    }

    return !!$class
}

<#

.SYNOPSIS
Determines if the MSCluster CIM provider is available on this server.

.DESCRIPTION
Use the existance of the CIM namespace to determine if MSCluster is available.

#>

function isMSClusterAvailable() {
    $class = Get-WmiObject -Namespace $MSClusterNamespace -ClassName $MSClusterResourceClassName -List -ErrorAction SilentlyContinue -ErrorVariable err

    if (-not($class)) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Couldn't get the required CIM namespace $MSClusterNamespace. Error: $err" -ErrorAction SilentlyContinue
    }

    return !!$class
}

<#

.SYNOPSIS
Get the VHDs of the passed in VM.

.DESCRIPTION
Use Britannica when getting the VHDs from a clustered VM.

#>

function getVhdsBritannica([string] $vmId) {
    $queryString = $VhdsFromBritannicaVirtualMachineQueryName -f $vmId
    $vm = Get-CimInstance -Namespace $BritannicaNamespace -Query $queryString -ErrorAction SilentlyContinue -ErrorVariable err

    if (!!$err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Couldn't get the virtual machine instance from Britannica. Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]
    }

    if ($vm) {
        return $vm.vhds | Microsoft.PowerShell.Utility\Select-Object `
            @{Name = $NamePropertyName; Expression ={[System.IO.Path]::GetFileName($_.FilePath)}}, `
            @{Name = $PathPropertyName; Expression ={$_.FilePath}}, `
            VhdType, `
            VhdFormat, `
            @{Name = $FileSizePropertyName; Expression ={$_.SizeUsed}}, `
            Size, `
            @{Name = $SizeUsedPropertyName; Expression ={[math]::Round(100*$_.SizeUsed/$_.Size,2)}}, `
            @{Name = $StorageVolumeIdPropertyName; Expression ={$_.VolumeId}}, `
            @{Name = $FileSharePropertyName; Expression = { getFileShare $_.FilePath}}, `
            TotalIops, `
            TotalThroughput
        }

    return $null
}

<#

.SYNOPSIS
Get the VHDs of the passed in VM.

.DESCRIPTION
Get the VHDs using Hyper-V and then ask the cluster via a physical disk resource control code for
the volume Id of the path.

#>

function getVhdsCluster([string] $vmId) {
    $vhds = getVhds $vmId

    #TODO: Use a control code to add the storage volume id from the cluster for each path used by the VHDs.
    return $vhds
}

<#

.SYNOPSIS
Get the VHDs of the passed in VM.

.DESCRIPTION
Use the standard Hyper-V PS cmdlets when getting the VHDs on stand alone servers.

#>

function getVhds([string] $vmId) {
    $vhds = Get-Vhd -id $vmId -ErrorAction SilentlyContinue -ErrorVariable +vhdError | Microsoft.PowerShell.Utility\Select-Object `
        @{Name = $NamePropertyName; Expression = {[System.IO.Path]::GetFileName($_.Path)}}, `
        $PathPropertyName, `
        VhdType, `
        VhdFormat, `
        $FileSizePropertyName, `
        Size, `
        @{Name = $SizeUsedPropertyName; Expression = {[math]::Round(100*$_.Filesize/$_.Size,2)}}, `
        @{Name = $StorageVolumeIdPropertyName; Expression = {$null}}, `   # TODO:  Figure out how to get the volume Id of local storage.
        @{Name = $FileSharePropertyName; Expression = { getFileShare $_.Path}}

    if (!!$vhdError) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: There was an error getting the VHDs for virtual machine with Id $vmId. Error: $err" -ErrorAction SilentlyContinue

        if ($vhdError) {
            $err = @($vhdError)[0]
            if ($err.exception.ErrorIdentifier -eq "ObjectNotFound") {
                # one of VHDs could be physical drive, make it as progress message.
                Write-Progress -Activity "VHDObjectNotFound" -Status $err.Exception.Message
            } else {
                Write-Error $err
            }
        }
    }

    if ($vhds) {
        return $vhds
    }

    return @()
}

<#

.SYNOPSIS
Get the file share (\\server\sharename) from the passed in path.

.DESCRIPTION
If the passed in path is a UNC path, extract the file share path and return it, otherwise
return $null.

#>

function getFileShare([string] $path) {
    $regex = $UNCPathRegex.Replace($RegexReplacementChar, $ReservedRegex)

    if ($path -match $regex) {
        $fileShare = Join-Path -Path $matches.server -ChildPath $matches.share

        return "\\" + $fileShare
    }

    return $null
}

<#

.SYNOPSIS
Main function of this script.

.DESCRIPTION
The main function.

#>

function main([string] $vmId) {
    if (isVmClustered $vmId) {
        if (isBritannicaVirtualizationAvailable) {
            return getVhdsBritannica $vmId
        }

        return getVhdsCluster $vmId
    }

    return getVhds $vmId
}

###############################################################################
# Script execution starts here.
###############################################################################
if (-not ($env:pester)) {
    setupScriptEnv

    try {
        Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

        $module = Get-Module -Name Hyper-V -ErrorAction SilentlyContinue -ErrorVariable err
        if (!!$module) {
            return main $vmId
        } else {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: The required PowerShell module (Hyper-V) was not found." -ErrorAction SilentlyContinue

            Write-Error $strings.HyperVModuleRequired

            return @()
        }
    } finally {
        cleanupScriptEnv
    }
}

}
## [END] Get-WACVMVirtualMachineVhds ##
function Get-WACVMVirtualMachinesEvents {
<#

.SYNOPSIS
Get events for virtual machines hosted on this server.

.DESCRIPTION
Get event from the following logs on this server:
    'Microsoft-Windows-Hyper-V-Compute-Admin'
    'Microsoft-Windows-Hyper-V-VMMS-Admin'
    'Microsoft-Windows-Hyper-V-Worker-Admin'
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0;

Microsoft.PowerShell.Diagnostics\get-winevent -FilterHashtable @{ LogName= `
    'Microsoft-Windows-Hyper-V-Compute-Admin',`
    'Microsoft-Windows-Hyper-V-VMMS-Admin', `
    'Microsoft-Windows-Hyper-V-Worker-Admin'; `
    level= 1,2,3; `
    StartTime=((Get-Date).AddDays(-10))} `
    -MaxEvents 10 -ErrorAction SilentlyContinue | `
        Microsoft.PowerShell.Utility\Select-Object Id, TimeCreated, LogName, Level, Message, MachineName, ProviderName

}
## [END] Get-WACVMVirtualMachinesEvents ##
function Get-WACVMVirtualMachinesFromBritannica {
<#

.SYNOPSIS
Get the virtual machines of this cluster from Britannica.

.DESCRIPTION
Get the virtual machines of this cluster from Britannica if it avaiable. Otherwise return null.
The supported Operating Systems are Windows Server 2016.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0
Import-Module CimCmdlets -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.  Create read only (constant) variables
that add context to the said constants.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-VirtualMachinesFromBritannica" -Scope Script
    Set-Variable -Name DisaggregatedStoragePropertyName -Option ReadOnly -Value "DisaggregatedStorage" -Scope Script
    Set-Variable -Name SDDCNamespace -Option ReadOnly -Value "root\SDDC\Management" -Scope Script
    Set-Variable -Name IdPropertyName -Option ReadOnly -Value "Id" -Scope Script
    Set-Variable -Name CPUUsagePropertyName -Option ReadOnly -Value "CPUUsage" -Scope Script
    Set-Variable -Name MemoryAssignedPropertyName -Option ReadOnly -Value "MemoryAssigned" -Scope Script
    Set-Variable -Name MemoryDemandPropertyName -Option ReadOnly -Value "MemoryDemand" -Scope Script
    Set-Variable -Name ComputerNamePropertyName -Option ReadOnly -Value "ComputerName" -Scope Script
    Set-Variable -Name BytesToMegaBytes -Option ReadOnly -Value 1048576 -Scope Script
    Set-Variable -Name VirtualMachineClassName -Option ReadOnly -Value "SDDC_VirtualMachine" -Scope Script
    Set-Variable -Name ConfigurationLocationPropertyName -Option ReadOnly -Value "ConfigurationLocation" -Scope Script
    Set-Variable -Name Server2019RS5InsiderBuildNumber -Option ReadOnly -Value 17723 -Scope Script
    Set-Variable -Name HostBuildServerNumberPropertyName -Option ReadOnly -Value "HostServerBuildNumber" -Scope Script
    Set-Variable -Name IPAddressPropertyName -Option ReadOnly -Value "IPAddress" -Scope Script
    Set-Variable -Name VirtualDiskCountPropertyName -Option ReadOnly -Value "VirtualDiskCount" -Scope Script
    Set-Variable -Name NICCardCountPropertyName -Option ReadOnly -Value "NetworkInterfaceCardCount" -Scope Script
}

<#

.SYNOPSIS
Cleanup the script environment.

.DESCRIPTION
Cleanup the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name DisaggregatedStoragePropertyName -Scope Script -Force
    Remove-Variable -Name SDDCNamespace -Scope Script -Force
    Remove-Variable -Name IdPropertyName -Scope Script -Force
    Remove-Variable -Name CPUUsagePropertyName -Scope Script -Force
    Remove-Variable -Name MemoryAssignedPropertyName -Scope Script -Force
    Remove-Variable -Name MemoryDemandPropertyName -Scope Script -Force
    Remove-Variable -Name ComputerNamePropertyName -Scope Script -Force
    Remove-Variable -Name BytesToMegaBytes -Scope Script -Force
    Remove-Variable -Name VirtualMachineClassName -Scope Script -Force
    Remove-Variable -Name ConfigurationLocationPropertyName -Scope Script -Force
    Remove-Variable -Name Server2019RS5InsiderBuildNumber -Scope Script -Force
    Remove-Variable -Name HostBuildServerNumberPropertyName -Scope Script -Force
    Remove-Variable -Name IPAddressPropertyName -Scope Script -Force
    Remove-Variable -Name VirtualDiskCountPropertyName -Scope Script -Force
    Remove-Variable -Name NICCardCountPropertyName -Scope Script -Force
}

<#

.SYNOPSIS
Are any of the virtual hard disks on a remote file server (disaggregated storage)?

.DESCRIPTION
If any virtual hard disk is on disaggregated storage then return true.  The UX will
use this value to determine at run-time if CredSSP is needed to manage these disks.

#>

function isDisaggregatedStorageUsed($vhds) {
    # TODO -- Britannica model does not include the ConfigurationLocation property.  So we will
    # always assume that if there is a disk on a share that most likley the ConfigurationLocation
    # on a share too.
    foreach($vhd in $vhds) {
        if ($vhd.FilePath.StartsWith("\\")) {
            return $true
        }
    }

    return $false
}

<#

.SYNOPSIS
Get the memory convertion rate based on build number

.DESCRIPTION
If build number less than RS5, the memory number is in bytes, convertion rate is 1.
Otherwise, the memory number is in mega bytes, need convert to bytes

#>

function getMemoryConvertionRate() {
    $build = [System.Environment]::OSVersion.Version.Build

    if ($build -lt $Server2019RS5InsiderBuildNumber) {
      return 1
    } else {
      return $BytesToMegaBytes
    }
}

<#

.SYNOPSIS
Get the the build number for the OS installed on this server.

.DESCRIPTION
Get the the build number for the OS installed on this server.

#>

function getBuildNumber {
    return [System.Environment]::OSVersion.Version.Build
}

<#

.SYNOPSIS
Gets the IP4 Address of the VM.

.DESCRIPTION
Gets the IP4 Address of the VM

#>

function getIPAddress($vm) {
    if ($vm.vNics.Length -gt 0) {
        return $vm.vNics[0].IPAddresses[0]
    }
}


<#

.SYNOPSIS
Gets the number of disks attached to the VM

.DESCRIPTION
Gets the number of disks attached to the VM

#>

function getVirtualDiskCount($vm) {
    $disks = Get-VMDvdDrive -VM $vm

    if ($disks) {
        return @($disks).Length
    }
}

<#

.SYNOPSIS
Get the the build number for the OS installed on this server.

.DESCRIPTION
Get the the build number for the OS installed on this server.

#>

<#

.SYNOPSIS
Get cluster virtual machines from Britannica (sddc management resources)

.DESCRIPTION
Get virtual machines data for the whole cluster from Britannica

Memory number are in MB(mega bytes), need convert to bytes

#>
function main()
{
    $memoryConvertionRate = getMemoryConvertionRate
    $vms = Get-CimInstance -Namespace $SDDCNamespace -ClassName $VirtualMachineClassName | `
        Microsoft.PowerShell.Utility\Select-Object `
        name, `
        @{Name = $IdPropertyName; Expression = {$_.$IdPropertyName.ToLower()}}, `
        @{Name = $CPUUsagePropertyName;Expression = {[math]::Round($_.$CPUUsagePropertyName)}}, `
        @{Name = $MemoryAssignedPropertyName; Expression = {$_.$MemoryAssignedPropertyName * $memoryConvertionRate}}, `
        @{Name = $MemoryDemandPropertyName; Expression = {$_.$MemoryDemandPropertyName * $memoryConvertionRate}}, `
        State, `
        Status, `
        CreationTime, `
        Uptime, `
        Heartbeat, `
        Version, `
        IsDeleted, `
        DynamicMemoryEnabled, `
        MemoryMaximum, `
        MemoryMinimum, `
        MemoryStartup, `
        ProcessorCount, `
        Generation, `
        @{Name = $ComputerNamePropertyName; Expression = {$_.Host}}, `
        @{Name = $DisaggregatedStoragePropertyName; Expression = {isDisaggregatedStorageUsed $_.vhds}}, `
        @{Name = $HostBuildServerNumberPropertyName; Expression = {getBuildNumber}}, `
        IsClustered, `
        @{Name = $IPAddressPropertyName; Expression = { getIPAddress $_ }}, `
        @{Name = $VirtualDiskCountPropertyName; Expression = { getVirtualDiskCount $_ } }, `
        @{Name = $NICCardCountPropertyName; Expression = { $_.vNics.Length }}, `
        OperationalStatus, `
        VirtualMachineType, `
        ReplicationHealth, `
        ReplicationMode, `
        ReplicationState, `
        SizeOfSystemFiles

    return $vms
}

###############################################################################
# Script execution starts here...
###############################################################################

if (-not($env:pester)) {
    setupScriptEnv

    try {
        Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

        $module = Get-Module -Name CimCmdlets -ErrorAction SilentlyContinue -ErrorVariable err

        if (!!$err) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: The required PowerShell module (CimCmdlets) was not found." -ErrorAction SilentlyContinue

            Write-Error $strings.CimCmdletsModuleRequired

            return @()
        }

        return main
       
    } finally {
        cleanupScriptEnv
    }
}

}
## [END] Get-WACVMVirtualMachinesFromBritannica ##
function Get-WACVMVirtualMachinesKvpHostOnlyProperty {
<#

.SYNOPSIS
Get the Key Value Exchange HostOnlyProperty property from the the virtual machines on this server.

.DESCRIPTION
Get the Key Value Exchange property for the virtual machines on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER propertyName
	The name of the host only property to get.

#>

param (
    [Parameter(Mandatory = $true)]
    [String] $propertyName
)

Set-StrictMode -Version 5.0

Import-Module CimCmdlets -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.  Create read only (constant) variables
that add context to the said constants.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScript" -Scope Script
	Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-VirtualMachineKvpHostOnlyProperty.ps1" -Scope Script
	Set-Variable -Name VirtualizationNamespace -Option ReadOnly -Value "root\virtualization\v2" -Scope Script
	Set-Variable -Name MsvmComputerSystemClassName -Option ReadOnly -Value "Msvm_ComputerSystem" -Scope Script
	Set-Variable -Name MsvmSystemDeviceClassName -Option ReadOnly -Value "Msvm_SystemDevice" -Scope Script
	Set-Variable -Name MsvmKvpExchangeComponentClassName -Option ReadOnly -Value "Msvm_KvpExchangeComponent" -Scope Script
	Set-Variable -Name DataPropertyName -Option ReadOnly -Value "Data" -Scope Script
	Set-Variable -Name MsvmElementSettingDataClassName -Option ReadOnly -Value "Msvm_ElementSettingData" -Scope Script
	Set-Variable -Name MsvmKvpExchangeComponentSettingDataClassName -Option ReadOnly -Value "Msvm_KvpExchangeComponentSettingData" -Scope Script
	Set-Variable -Name NamePropertyName -Option ReadOnly -Value "Name" -Scope Script
    Set-Variable -Name HostOnlyItemsPropertyName -Option ReadOnly -Value "HostOnlyItems" -Scope Script
    Set-Variable -Name MsvmVirtualSystemSettingDataComponentClassName -Option ReadOnly -Value "Msvm_VirtualSystemSettingDataComponent" -Scope Script
    Set-Variable -Name MsvmVirtualSystemSettingDataClassName -Option ReadOnly -Value "Msvm_VirtualSystemSettingData" -Scope Script
    Set-Variable -Name MsvmSettingsDefineStateClassName -Option ReadOnly -Value "Msvm_SettingsDefineState" -Scope Script
    Set-Variable -Name VmIdPropertyName -Option ReadOnly -Value "VmId" -Scope Script
}

<#

.SYNOPSIS
Cleanup the script environment.

.DESCRIPTION
Cleanup the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name VirtualizationNamespace -Scope Script -Force
    Remove-Variable -Name MsvmComputerSystemClassName -Scope Script -Force
	Remove-Variable -Name MsvmSystemDeviceClassName -Scope Script -Force
	Remove-Variable -Name MsvmKvpExchangeComponentClassName -Scope Script -Force
	Remove-Variable -Name DataPropertyName -Scope Script -Force
	Remove-Variable -Name MsvmElementSettingDataClassName -Scope Script -Force
	Remove-Variable -Name MsvmKvpExchangeComponentSettingDataClassName -Scope Script -Force
	Remove-Variable -Name NamePropertyName -Scope Script -Force
	Remove-Variable -Name HostOnlyItemsPropertyName -Scope Script -Force
	Remove-Variable -Name MsvmVirtualSystemSettingDataComponentClassName -Scope Script -Force
	Remove-Variable -Name MsvmVirtualSystemSettingDataClassName -Scope Script -Force
	Remove-Variable -Name MsvmSettingsDefineStateClassName -Scope Script -Force
	Remove-Variable -Name VmIdPropertyName -Scope Script -Force
}

<#

.SYNOPSIS
Get the guest CIM instance of the passed in value pair exchange.

.DESCRIPTION
Get the guest CIM instance of the passed in value pair exchange.

#>

function getGuestKvp($settingsData) {
	$err = $null

	$guestKvp = Get-CimAssociatedInstance -InputObject $settingsData -Association $MsvmVirtualSystemSettingDataComponentClassName -ResultClassName $MsvmKvpExchangeComponentSettingDataClassName `
		-ErrorAction SilentlyContinue -ErrorVariable +err
	if ($err) {
		Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
			-Message "[$ScriptName]: Couldn't get the guest KVP instance. Error: $err" -ErrorAction SilentlyContinue

		Write-Error @($err)[0]

		return $null
	}

	return $guestKvp
}

<#

.SYNOPSIS
Get the CIM instance of the passed in virtual machine's settings data.

.DESCRIPTION
Get the CIM instance of the passed in virtual machine's settings data.

#>

function getSettingsData($vm) {
	$err = $null

	$settingsData = Get-CimAssociatedInstance -InputObject $vm -Association $MsvmSettingsDefineStateClassName -ResultClassName $MsvmVirtualSystemSettingDataClassName `
		-ErrorAction SilentlyContinue -ErrorVariable +err

	if ($err) {
		$vmName = $vm.ElementName

		Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
			-Message "[$ScriptName]: Couldn't get the settings data component for virtual machine $vmName. Error: $err" -ErrorAction SilentlyContinue

		Write-Error @($err)[0]

		return $null
	}

	return $settingsData
}

<#

.SYNOPSIS
Get the CIM instances of the virtual machines on this server.

.DESCRIPTION
Get the CIM instances of the virtual machines on this server.

#>

function getVms() {
	$err = $null

	$vms = Get-CimInstance -namespace $VirtualizationNamespace -ClassName $MsvmComputerSystemClassName -ErrorAction SilentlyContinue -ErrorVariable +err

	if ($err) {
		Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
			-Message "[$ScriptName]: Couldn't get the CIM instance for virtual machine Id $vmId. Error: $err" -ErrorAction SilentlyContinue

		Write-Error @($err)[0]

		return $null
	}

	return $vms
}

<#

.SYNOPSIS
Get the value of the passed in property from the guest key value pair exchange hostOnlyItems.

.DESCRIPTION
Get the value of the passed in property from the guest key value pair exchange hostOnlyItems.

#>

function getHostOnlyProperty($vm, $guestKvp, [string] $propertyName) {
	try {
		return (([xml]($guestKvp.$HostOnlyItemsPropertyName | `
			Microsoft.PowerShell.Core\Where-Object {$_ -match $propertyName})).instance.property | `
			Microsoft.PowerShell.Core\Where-Object {$_.Name -eq $DataPropertyName}).Value
	} catch {
        # This log is too chatty...  Commenting out until a better way to determine a failure versus no data is found.
		# $vmName = $vm.ElementName

        # Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        # 	-Message "[$ScriptName]: Couldn't get the host only property $propertyName from the virtual machine $vmName. Error: $_.Exception" -ErrorAction SilentlyContinue

        return $null
    }
}

function getVmPropertyData($vm) {
    if (-not ($vm)) {
        return $null
    }

    $settingsData = getSettingsData $vm
	if (-not ($settingsData)) {
        return $null
    }

	$guestKvp = getGuestKvp $settingsData
	if (-not ($guestKvp)) {
        return $null
	}

	return getHostOnlyProperty $vm $guestKvp $propertyName
}

<#

.SYNOPSIS
Main

.DESCRIPTION
An explicit main function to fetch the settings.

#>

function main([string] $propertyName) {
    $vms = getVms
    if (-not ($vms)) {
        return @()
    }

    $results = @()

    foreach ($vm in $vms) {
        $data = getVmPropertyData $vm

        if ($data) {
            $result = New-Object PSObject -Property @{
                $VmIdPropertyName = ($vm.$NamePropertyName).ToLower();
                $propertyName = $data;
            }

            $results += $result
        }
    }

    return $results
}

###############################################################################
# Script execution starts here.
###############################################################################

if (-not($env:pester)) {
    setupScriptEnv

    try {
		$err = $null

        Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

        $namespace = Get-CimInstance -Namespace $VirtualizationNamespace -Class __Namespace -ErrorAction SilentlyContinue -ErrorVariable +err
        if (-not ($err)) {
            return main $propertyName
        }

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        	-Message "[$ScriptName]: The required CIM namepace ($VirtualizationNamespace) was not found." -ErrorAction SilentlyContinue

        return @()
    } finally {
        cleanupScriptEnv
    }
}

}
## [END] Get-WACVMVirtualMachinesKvpHostOnlyProperty ##
function Get-WACVMVirtualMachinesProperties {
<#

.SYNOPSIS
Get the virtual machines.

.DESCRIPTION
Get the virtual machines on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

param (
    [Parameter(Mandatory = $true)]
    [int]
    $fetchType
)

Set-StrictMode -Version 5.0

Import-Module Hyper-V -ErrorAction SilentlyContinue
Import-Module CimCmdlets -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Indicates the host type for the virtual machine.

.DESCRIPTION
Indicates the host type for the virtual machine.

#>

enum HostType {
  StandAlone = 0
  Cluster = 1
  Britannica = 2
}

enum FetchType {
  Full = 0
  Partial = 1
}

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.  Create read only (constant) variables
that add context to the said constants.

#>

function setupScriptEnv() {
  ##SkipCheck=true##
  Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
  Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
  Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-VirtualMachines" -Scope Script
  Set-Variable -Name DisaggregatedStoragePropertyName -Option ReadOnly -Value "DisaggregatedStorage" -Scope Script
  Set-Variable -Name HeartBeatPropertyName -Option ReadOnly -Value "Heartbeat" -Scope Script
  Set-Variable -Name IdPropertyName -Option ReadOnly -Value "Id" -Scope Script
  Set-Variable -Name Windows10MajorVersion -Option ReadOnly -Value 10 -Scope Script
  Set-Variable -Name ConfigurationLocationPropertyName -Option ReadOnly -Value "ConfigurationLocation" -Scope Script
  Set-Variable -Name PathPropertyName -Option ReadOnly -Value "Path" -Scope Script
  Set-Variable -Name BritannicaNamespace -Option ReadOnly -Value "root\SDDC\Management" -Scope Script
  Set-Variable -Name BritannicaVirtualMachineClassName -Option ReadOnly -Value "SDDC_VirtualMachine" -Scope Script
  Set-Variable -Name MSClusterNamespace -Option ReadOnly -Value "root\MSCluster" -Scope Script
  Set-Variable -Name MSClusterResourceClassName -Option ReadOnly -Value "MSCluster_Resource" -Scope Script
  Set-Variable -Name ClusteredVirtualkMachineQueryName -Option ReadOnly -Value "Select PrivateProperties from MSCluster_Resource where Type='Virtual Machine' and PrivateProperties.VmId='{0}'" -Scope Script
  Set-Variable -Name HostTypePropertyName -Option ReadOnly -Value "HostType" -Scope Script
  Set-Variable -Name HostBuildServerNumberPropertyName -Option ReadOnly -Value "HostServerBuildNumber" -Scope Script
  Set-Variable -Name IPAddressPropertyName -Option ReadOnly -Value "IPAddress" -Scope Script
  Set-Variable -Name VirtualDiskCountPropertyName -Option ReadOnly -Value "VirtualDiskCount" -Scope Script
  Set-Variable -Name NICCardCountPropertyName -Option ReadOnly -Value "NetworkInterfaceCardCount" -Scope Script
  ##SkipCheck=false##
}

<#

.SYNOPSIS
Cleanup the script environment.

.DESCRIPTION
Cleanup the script environment.

#>

function cleanupScriptEnv() {
  Remove-Variable -Name LogName -Scope Script -Force
  Remove-Variable -Name LogSource -Scope Script -Force
  Remove-Variable -Name ScriptName -Scope Script -Force
  Remove-Variable -Name DisaggregatedStoragePropertyName -Scope Script -Force
  Remove-Variable -Name HeartBeatPropertyName -Scope Script -Force
  Remove-Variable -Name IdPropertyName -Scope Script -Force
  Remove-Variable -Name Windows10MajorVersion -Scope Script -Force
  Remove-Variable -Name ConfigurationLocationPropertyName -Scope Script -Force
  Remove-Variable -Name PathPropertyName -Scope Script -Force
  Remove-Variable -Name BritannicaNamespace -Scope Script -Force
  Remove-Variable -Name BritannicaVirtualMachineClassName -Scope Script -Force
  Remove-Variable -Name MSClusterNamespace -Scope Script -Force
  Remove-Variable -Name MSClusterResourceClassName -Scope Script -Force
  Remove-Variable -Name ClusteredVirtualkMachineQueryName -Scope Script -Force
  Remove-Variable -Name HostTypePropertyName -Scope Script -Force
  Remove-Variable -Name HostBuildServerNumberPropertyName -Scope Script -Force
  Remove-Variable -Name IPAddressPropertyName -Scope Script -Force
  Remove-Variable -Name VirtualDiskCountPropertyName -Scope Script -Force
  Remove-Variable -Name NICCardCountPropertyName -Scope Script -Force
}

<#

.SYNOPSIS
Are any of the virtual hard disks on a remote file server (disaggregated storage)?

.DESCRIPTION
If any virtual hard disk is on disaggregated storage then return true.  The UX will
use this value to determine at run-time if CredSSP is needed to manage these disks.

#>

function isDisaggregatedStorageUsed($vm) {
  $err = $null

  $configPath = $vm.$ConfigurationLocationPropertyName
  if ($configPath.StartsWith("\\")) {
    return $true
  }

  $hardDisks = $vm | Get-VMHardDiskDrive -ErrorAction SilentlyContinue -ErrorVariable err

  if (-not($err)) {
    foreach ($hardDisk in $hardDisks) {
      if ($hardDisk.$PathPropertyName.StartsWith("\\")) {
        return $true
      }
    }
  }
  else {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
      -Message "[$ScriptName]: There were errors getting the hard disks for virtual machine $vm.Name.  Errors: $err." -ErrorAction SilentlyContinue

    Write-Error @($err)[0]
  }

  return $false
}

<#

.SYNOPSIS
Update (convert) the heart beat enum value.

.DESCRIPTION
For server versions lower than Windows 10/ Server 2016 the heart beat enum values
are 1 less than the current enum values in the UX.

#>

function updateHeatBeatValue([int] $heartBeatValue, [bool] $isDownLevel) {
  if ($isDownlevel) {
    $heartbeatValue + 1;
  }

  return $heartBeatValue
}

<#

.SYNOPSIS
Determines if Britannica (sddc management resources) virtualization is available on the cluster

.DESCRIPTION
Use the existance of the cim namespace root/sddc to determine if Britannica
is supported or not.

#>

function isBritannicaVirtualizationAvailable() {
  $class = Get-WmiObject -Namespace $BritannicaNamespace -ClassName $BritannicaVirtualMachineClassName -List -ErrorAction SilentlyContinue -ErrorVariable err

  if (-not($class)) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
      -Message "[$ScriptName]: Couldn't get the required CIM namespace $BritannicaNamespace. Error: $err" -ErrorAction SilentlyContinue
  }

  return $null -ne $class
}

<#

.SYNOPSIS
Determines if the passed n VM Id is a clustered VM or not.

.DESCRIPTION
Return true when the passed in VM is clustered.

#>

function isVmClustered([string] $vmId) {
  if (isMSClusterAvailable) {
    $queryString = $ClusteredVirtualkMachineQueryName -f $vmId
    $vmResource = Get-CimInstance -Namespace $MSClusterNamespace -Query $queryString -ErrorAction SilentlyContinue

    return $null -ne $vmResource
  }

  return $false
}

<#

.SYNOPSIS
Determines if the MSCluster CIM provider is available on this server.

.DESCRIPTION
Use the existance of the CIM namespace to determine if MSCluster is available.

#>

function isMSClusterAvailable() {
  $class = Get-WmiObject -Namespace $MSClusterNamespace -ClassName $MSClusterResourceClassName -List -ErrorAction SilentlyContinue -ErrorVariable err

  if (-not($class)) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
      -Message "[$ScriptName]: Couldn't get the required CIM namespace $MSClusterNamespace. Error: $err" -ErrorAction SilentlyContinue
  }

  return $null -ne $class
}

<#

.SYNOPSIS
Determines the type of vm host.

.DESCRIPTION
Determines the type of vm host.

#>

function getVmHostType() {
  if (isVmClustered $vmId) {
    $hostType = [HostType]::Cluster

    if (isBritannicaVirtualizationAvailable) {
      $hostType = [HostType]::Britannica
    }
  }
  else {
    $hostType = [HostType]::StandAlone
  }

  return $hostType
}

<#

.SYNOPSIS
Gets the IP4 Address of the VM.

.DESCRIPTION
Gets the IP4 Address of the VM

#>

function getIPAddress($vmId) {
  $adapters = Get-RBACVM -Id $vmId | Get-VMNetworkAdapter
  try {
    $firstIP4Address = $adapters[0].IPAddresses[0]
    return $firstIP4Address
  }
  catch { return $null }

}

<#

.SYNOPSIS
Gets the number of disks attached to the VM

.DESCRIPTION
Gets the number of disks attached to the VM

#>

function getVirtualDiskCount($vmId) {
  $disks = Get-RBACVM -Id $vmId | Get-VMDvdDrive

  return @($disks).Length
}

<#

.SYNOPSIS
Gets the number of NICs attached to the VM

.DESCRIPTION
Gets the number of NICs attached to the VM

#>

function getNetworkInterfaceCardCount($vmId) {
  $adapters = Get-RBACVM -Id $vmId | Get-VMNetworkAdapter

  return @($adapters).Length
}

<#

.SYNOPSIS
Get the the build number for the OS installed on this server.

.DESCRIPTION
Get the the build number for the OS installed on this server.

#>

function getBuildNumber {
  return [System.Environment]::OSVersion.Version.Build
}

<#

.SYNOPSIS
The main function.

.DESCRIPTION
Get the virtual machines on this server and filter the properties down to just those
needed by the UX model.  The Id property is forced to lower case since Ids from other
sources (Britannica) are lower case.  The Hear Beat status enum may be adjusted for
down level servers and the meta property that indicates this VM uses disaggregated
storage is added.

#>

function main() {
  $private:err = $null

  $isDownlevel = [Environment]::OSVersion.Version.Major -lt $Windows10MajorVersion

  $basicProperties =  'Name', `
    'CPUUsage', `
    'MemoryAssigned', `
    'MemoryDemand', `
    'State', `
    'Status', `
    'CreationTime', `
    'Uptime', `
    'Version', `
    'IsDeleted', `
    'DynamicMemoryEnabled', `
    'MemoryMaximum', `
    'MemoryMinimum', `
    'MemoryStartup', `
    'ProcessorCount', `
    'Generation', `
    'ComputerName', `
    @{Name = $IdPropertyName; Expression = { [System.Guid]::Parse($_.id.ToString().ToLower()) } }, ` # Ensure the ID GUID is lower case...
    @{Name = $HeartBeatPropertyName; Expression = { updateHeatBeatValue $_.$HeartBeatPropertyName $isDownLevel } }, `
    @{Name = $HostBuildServerNumberPropertyName; Expression = { getBuildNumber } }, `
    'OperationalStatus', `
    'VirtualMachineType', `
    'ReplicationHealth', `
    'ReplicationMode', `
    'ReplicationState', `
    'SizeOfSystemFiles', `
    'CheckpointFileLocation', `
    'ConfigurationLocation', `
    'SmartPagingFilePath'


  $advancedProperties = @(
    @{Name = $HostTypePropertyName; Expression = { getVmHostType } }, `
    @{Name = $DisaggregatedStoragePropertyName; Expression = { isDisaggregatedStorageUsed $_ } }, `
    @{Name = $IPAddressPropertyName; Expression = { getIPAddress $_.Id } }, `
    @{Name = $VirtualDiskCountPropertyName; Expression = { getVirtualDiskCount $_.Id } }, `
    @{Name = $NICCardCountPropertyName; Expression = { getNetworkInterfaceCardCount $_.Id } }
  )

  $vmProperties = @{
    Partial = $basicProperties;
    Full = $basicProperties + $advancedProperties;
  }

  $vms = Get-RBACVM -ErrorAction SilentlyContinue -ErrorVariable err | `
    Microsoft.PowerShell.Utility\Select-Object `
    -Property $vmProperties[[FetchType].GetEnumName($fetchType)]

  if (!!$err) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
      -Message "[$ScriptName]: There were errors getting the virtual machines.  Errors: $err." -ErrorAction SilentlyContinue

    Write-Error @($err)[0]

    return @()
  }

  return $vms
}

###############################################################################
# Script execution starts here...
###############################################################################

if (-not ($env:pester)) {
  setupScriptEnv

  try {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    $module = Get-Module -Name Hyper-V -ErrorAction SilentlyContinue -ErrorVariable err
    if ($module) {
      return main
    }
    else {
      Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: The required PowerShell module (Hyper-V) was not found." -ErrorAction SilentlyContinue

      Write-Error $strings.HyperVModuleRequired

      return @()
    }
  }
  finally {
    cleanupScriptEnv
  }
}

return @()

}
## [END] Get-WACVMVirtualMachinesProperties ##
function Get-WACVMVirtualNetworks {
<#

.SYNOPSIS
Gets the Virtual Networks.

.DESCRIPTION
Gets the Virtual Networks objects from the SDN Network Controller.

.ROLE
Readers

.PARAMETER uri
    The uri used to connect to the SDN Network controller
    
#>

param (
		[Parameter(Mandatory = $true)]
		[String]
        $uri
)

Set-StrictMode -Version 5.0;
Import-Module NetworkController;
Import-Module Microsoft.PowerShell.Management;

$vnets = @(Get-NetworkControllerVirtualNetwork -ConnectionUri $uri)
$vnets | ConvertTo-Json -depth 100 | ConvertFrom-Json
}
## [END] Get-WACVMVirtualNetworks ##
function Get-WACVMVirtualSwitch {
<#

.SYNOPSIS
Get the passed in virtual switch.

.DESCRIPTION
Get the passed in virtual switch from this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER vsId
    The Id of the requested virtual switch.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $vsId
)  

Set-StrictMode -Version 5.0;
Import-Module Hyper-V;

# get the normal virtual switch properties
$vs = get-vmswitch -id $vsId;

# get the switch embedded teaming (SET) properties.
$set = $null;
$cmd = get-command Get-VMSwitchTeam -ErrorAction SilentlyContinue;

if ($cmd) {
    $set = $vs | Get-VMSwitchTeam -ErrorAction SilentlyContinue;
}

$properties = @{
    'name'=$vs.name;
    'id'=$vs.id;
    'extensions'=$vs.extensions;
    'switchType'=$vs.switchType;
    'allowManagementOS'=$vs.allowManagementOS;
    'netAdapterInterfaceDescription'=$vs.netAdapterInterfaceDescription;
    'computerName'=$vs.computerName;
    'notes'=$vs.notes;
    'isDeleted'=$vs.isDeleted;
    'IovEnabled'=$vs.IovEnabled;
    'IovSupport'=$vs.IovSupport;
    'IovSupportReasons'=$vs.IovSupportReasons;
};

if ($set) {
    $properties += @{
        'teamingMode'=$set.teamingMode;
        'loadBalancingAlgorithm'=$set.loadBalancingAlgorithm;
        'netAdapterInterfaceDescriptions'=$set.netAdapterInterfaceDescription;
    };
} else {
    $properties += @{
        'teamingMode'=-1;               # -1 means notTeamed
        'loadBalancingAlgorithm'=-1;    # -1 means unknown
        'netAdapterInterfaceDescriptions'=@($vs.netAdapterInterfaceDescription);
    };
}

# define a new object that will hold the properties that will be returned to the caller.
$vsProperties = New-Object psobject -Prop $properties

return $vsProperties;

}
## [END] Get-WACVMVirtualSwitch ##
function Get-WACVMVirtualSwitches {
<#

.SYNOPSIS
Get the virtual switches.

.DESCRIPTION
Get the virtual switches on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0;
Import-Module Hyper-V;

get-vmswitch | `
    Microsoft.PowerShell.Utility\Select-Object `
    name, `
    Id, `
    extensions, `
    switchType, `
    allowManagementOS, `
    netAdapterInterfaceDescription, `
    netAdapterInterfaceDescriptions, `
    computerName, `
    notes, `
    isDeleted, `
    IovEnabled, `
    IovSupport, `
    IovSupportReasons
}
## [END] Get-WACVMVirtualSwitches ##
function Get-WACVMVirtualSwitchesFromBritannica {
<#

.SYNOPSIS
Get the virtual switches of this cluster from Britannica.

.DESCRIPTION
Get the virtual switches of this cluster from Britannica if it avaiable. Otherwise return null.
The supported Operating Systems are Windows Server 2016.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0;

<#

.SYNOPSIS
Determines if Britannica (sddc management resources) are available on the cluster

.DESCRIPTION
Use the existance of the cim namespace root/sddc/Management and class name to determine if Britannica 
is supported or not.

#>
function isBritannicaEnabled() {
    return (Get-CimInstance -Namespace "root\SDDC\Management" -ClassName SDDC_VirtualSwitch -ErrorAction SilentlyContinue) `
        -ne $null
}

<#

.SYNOPSIS
Get cluster virtual switches from Britannica (sddc management resources)

.DESCRIPTION
Get virtual switch data for the whole cluster from Britannica 

#>
function getVmSwitchesFromBritannica()
{
    $vss = Get-CimInstance -Namespace "root\SDDC\Management" -ClassName SDDC_VirtualSwitch `
        | Microsoft.PowerShell.Utility\Select-Object -Property `
        name, `
        @{N='id';E={$_.Id.ToLower()}}, `
        extensions, `
        switchType, `
        allowManagementOS, `
        netAdapterInterfaceDescription, `
        @{N='netAdapterInterfaceDescriptions';E={$_.NetAdapterDescriptions}}, `
        @{N='ComputerName';E={$_.HostName}}, `
        notes, `
        isDeleted, `
        @{N='IovEnabled';E={$_.IsIovEnabled}}, `
        @{N='IovSupport';E={$_.IsIovCapable}}, `
        IovSupportReasons

    return $vss
}

###############################################################################
# main
###############################################################################
if (isBritannicaEnabled) {
    return getVmSwitchesFromBritannica    
} else {
    return $null
}
}
## [END] Get-WACVMVirtualSwitchesFromBritannica ##
function Get-WACVMVolumes {
<#

.SYNOPSIS
Enumerates all of the local volumes of the system.

.DESCRIPTION
Enumerates all of the local volumes of the system.

.ROLE
Readers

#>

param (
    [Parameter(Mandatory = $false)]
    [String]
    $VolumeId
)

Set-StrictMode -Version 5.0
import-module CimCmdlets;

<#
.Synopsis
    Name: Get-Volumes
    Description: Gets all the local volumes of the machine.

.Parameter VolumeId
    The unique identifier of the volume desired (Optional - for cases where only one volume is desired).

.Returns
    The local volume(s).
#>
function Enumerate-Volumes
{
    param (
        [Parameter(Mandatory = $false)]
        [String]
        $VolumeId
    )

    Remove-Module Storage -ErrorAction Ignore; # Remove the Storage module to prevent it from automatically localizing

    $isDownlevel = [Environment]::OSVersion.Version.Major -lt 10;
    if ($isDownlevel)
    {
        $disks = Get-CimInstance -ClassName MSFT_Disk -Namespace root/Microsoft/Windows/Storage | Where-Object { !$_.IsClustered };
        $partitions = $disks | Get-CimAssociatedInstance -ResultClassName MSFT_Partition;
        if (($partitions -eq $null) -or ($partitions.Length -eq 0)) {
            $volumes = Get-CimInstance -ClassName MSFT_Volume -Namespace root/Microsoft/Windows/Storage;
        } else {
            $volumes = $partitions | Get-CimAssociatedInstance -ResultClassName MSFT_Volume;
        }
    }
    else
    {
        $subsystem = Get-CimInstance -ClassName MSFT_StorageSubSystem -Namespace root/Microsoft/Windows/Storage| Where-Object { $_.FriendlyName -like "Win*" };
        $volumes = $subsystem | Get-CimAssociatedInstance -ResultClassName MSFT_Volume;
    }

    if ($VolumeId)
    {
        $volumes = $volumes | Where-Object { $_.Path -eq $VolumeId };
    }

    return $volumes | Microsoft.PowerShell.Utility\Select-Object `
                                    @{Name="Name"; Expression={if ($_.FileSystemLabel) { $_.FileSystemLabel + " (" + $_.DriveLetter + ":)"} else { "(" + $_.DriveLetter + ":)" }}},
                                    HealthStatus,
                                    DriveType,
                                    Size,
                                    SizeRemaining;
}

if ($VolumeId)
{
    Enumerate-Volumes -VolumeId $VolumeId;
}
else
{
    Enumerate-Volumes;
}

}
## [END] Get-WACVMVolumes ##
function Import-WACVMVirtualMachine {
<#

.SYNOPSIS
Import a virtual machine.

.DESCRIPTION
Import the passed in virtual machine on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016, Windows Server 2019.

.ROLE
Hyper-V-Administrators

.PARAMETER configPath
    The path containing the virtual machine configuration files

.PARAMETER vmId
    The name of the virtual machine to be imported

.PARAMETER vmName
    The ID of the virtual machine to be imported

.PARAMETER newName
    The new name of the virtual machine to be imported

.PARAMETER createNewId
    The flag to determine whether a new virtual machine ID should be created or not

.PARAMETER copyVm
    The flag to determine whether virtual machine should be copied or not

.PARAMETER targetPath
    The path where the virtual machines files should be placed

.PARAMETER addClusterRole
    The flag to create a clustered virtual machine

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $configPath,
    [Parameter(Mandatory = $true)]
    [String]
    $vmId,
    [Parameter(Mandatory = $true)]
    [String]
    $vmName,
    [Parameter(Mandatory = $false)]
    [String]
    $newName,
    [Parameter(Mandatory = $true)]
    [boolean]
    $createNewId,
    [Parameter(Mandatory = $true)]
    [boolean]
    $copyVm,
    [Parameter(Mandatory = $false)]
    [String]
    $targetPath,
    [Parameter(Mandatory = $true)]
    [boolean]
    $addClusterRole
)

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Setup script runtime environment.

.DESCRIPTION
Setup script runtime environment.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScript" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Import-VirtualMachine.ps1" -Scope Script
}

<#

.SYNOPSIS
Cleanup script runtime environment.

.DESCRIPTION
Cleanup script runtime environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
}

<#

.SYNOPSIS
The main function.

.DESCRIPTION
Export the passed in virtual machine on this server.

#>

function main(
    [string]$configPath,
    [string]$vmId,
    [string]$vmName,
    [string]$newName,
    [boolean]$createNewId,
    [boolean]$copyVm,
    [string]$targetPath,
    [boolean]$addClusterRole
) {
    $err = $null
    $arguments = @{}
    $renameVm = $false
    $vhdDestinationPath = ''
    $virtualMachinePath = ''

    if (-not ($createNewId) -and -not($copyVm)) {
        $arguments += @{ Path = $configPath }
    } else {
        if ($newName) {
            $virtualMachinePath = "$targetPath\$newName"
            if ($newName -eq $vmName) {
                $date = Get-Date -Format "yyyy-MM-dd HH-mm-ss"
                $vhdDestinationPath = "$targetPath\$vmName\Virtual Hard Disks\$vmName (imported) - $date"
            } else {
                $vhdDestinationPath = "$targetPath\$newName\Virtual Hard Disks"
                $renameVm = $true
            }
        } else {
            $virtualMachinePath = "$targetPath\$vmName"
        }

        $arguments += @{ Path = $configPath; Copy = $true; VirtualMachinePath = $virtualMachinePath; VhdDestinationPath = $vhdDestinationPath }
        if ($createNewId) {
            $arguments += @{ GenerateNewId = $true; }
        }
    } 

    $report = Compare-VM @arguments -ErrorAction SilentlyContinue -ErrorVariable +err
    if (!!$err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Couldn't generate the compatibility report for the selected virtual machine. Error: $err"  -ErrorAction SilentlyContinue

        Write-Error @($err)[0]
        return @()
    }

    if ($report -and @($report.Incompatibilities).Length -eq 0) {
        $newVmId = $report.VM.Id

        Import-VM -CompatibilityReport $report -ErrorAction SilentlyContinue -ErrorVariable +err
        if (!!$err) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: Couldn't import the selected virtual machine. Error: $err"  -ErrorAction SilentlyContinue

            Write-Error @($err)[0]
            return @()
        }

        if ($renameVm) {
            $vm = Get-RBACVM -id $newVmId -ErrorAction SilentlyContinue -ErrorVariable +err
            if (!!$err) {
                Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: Couldn't retrieve the virtual machine. Error: $err"  -ErrorAction SilentlyContinue

                Write-Error @($err)[0]
                return @()
            }

            $vm | Rename-VM -NewName $newName -ErrorAction SilentlyContinue -ErrorVariable +err
            if (!!$err) {
                Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: Couldn't rename the virtual machine. Error: $err"  -ErrorAction SilentlyContinue

                Write-Error @($err)[0]
                return @()
            }
        }

        if ($addClusterRole) {
            $module = Get-Module -Name FailoverClusters -ErrorAction SilentlyContinue
            if (!!$module) {
                Add-ClusterVirtualMachineRole -VMId $newVmId -ErrorAction SilentlyContinue -ErrorVariable +err | Out-Null
                if (!!$err) {
                    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                    -Message "[$ScriptName]: Couldn't create a clustered virtual machine. Error: $err"  -ErrorAction SilentlyContinue

                    Write-Error @($err)[0]
                    return @()
                }
            }
            else {
                Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                    -Message "[$ScriptName]: The required PowerShell module (FailoverClusters) was not found. Virtual Machine $vmName was not added to the cluster." -ErrorAction SilentlyContinue
    
                Write-Error $strings.FailoverClustersModuleRequired
            }
        }
    } else {
        $miniReport = $report.Incompatibilities | Microsoft.PowerShell.Utility\Select-Object Message, MessageId

        $numberOfIncompatibilities = @($miniReport).Length
        $message ="'`r`n $numberOfIncompatibilities incompatibilities were found.`r`n"
        
        @($minireport) | ForEach-Object {
            $message += $_.MessageId.ToString() + " - " + $_.Message + "`r`n"
        }

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: The VM $vmName is not compatible with this host server.  Incompatibilities found: $message" -ErrorAction SilentlyContinue

        $message = $strings.ImportVirtualMachineVMIncompatible -f $vmName
        $err = [System.InvalidOperationException] $message
        
        Write-Error @($err)[0]

        return @()
    } 
}


###############################################################################
# Script execution starts here
###############################################################################
setupScriptEnv

try {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    $module = Get-Module -Name Hyper-V -ErrorAction SilentlyContinue -ErrorVariable +err
    if (!!$module) {
        return main $configPath $vmId $vmName $newName $createNewId $copyVm $targetPath $addClusterRole
    }

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: The required PowerShell module (Hyper-V) was not found."  -ErrorAction SilentlyContinue

    Write-Error $strings.HyperVModuleRequired -ErrorAction Stop

    return @()
} finally {
    cleanupScriptEnv
}

}
## [END] Import-WACVMVirtualMachine ##
function Install-WACVMHyperVPowerShellSupport {
<#

.SYNOPSIS
Install the Hyper-V-Powershell support feature.

.DESCRIPTION
Install the Hyper-V-Powershell support feature on this server.  The server will restart, if needed.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

#>

Set-StrictMode -Version 5.0;
Import-Module ServerManager;
Import-Module Microsoft.PowerShell.Management;

$result=Install-WindowsFeature -Name Hyper-v-Powershell -restart

return $result.ExitCode

}
## [END] Install-WACVMHyperVPowerShellSupport ##
function Install-WACVMSiteRecoveryNodeDependencies {
<#

.SYNOPSIS
Install Azure Site Recovery Dependencies

.DESCRIPTION
Download Azure Site Recovery Provider and run installer

.ROLE
Administrators

#>

[CmdletBinding()]
param ()

$ErrorActionPreference = "Stop"

$ScriptFile = $Env:Temp + "\Install-AzureSiteRecovery.ps1"
if (Test-Path $ScriptFile) {
    Remove-Item $ScriptFile
}

$ProviderExe = $Env:Temp + '\AzureSiteRecoveryProvider.exe'
if (Test-Path $ProviderExe) {
    Remove-Item $ProviderExe
}

Invoke-WebRequest -Uri https://aka.ms/downloaddra -OutFile $ProviderExe

$ExtractFolder = $Env:temp + '\SmeAzureSiteRecoveryInstaller'
if (Test-Path $ExtractFolder) {
    Remove-Item $ExtractFolder -Force -Recurse
}

&$ProviderExe /x:$ExtractFolder /q
$SetupExe = $ExtractFolder + '\setupdr.exe'
for ($i = 1; $i -le 10; $i++) {
    if (-Not(Test-Path $SetupExe)) {
        Start-Sleep -s 6
    }
}

$Output = &$SetupExe /i 2>&1 | Out-Null
if ($LastExitCode -ne 0) {
    $Message = "Something went wrong while installing Azure Site Recovery Provider."

    if($null -ne $Output){
        $Message += " $Output"
    }

    $LogName = "Microsoft-ServerManagementExperience"
    $LogSource = "SMEScript"
    $ScriptName = "Install-SiteRecoveryNodeDependencies.ps1"
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: $Message"  -ErrorAction SilentlyContinue

    Write-Error $Message
}
else {
    Write-Output "Successfully installed Azure Site Recovery Provider."
}

}
## [END] Install-WACVMSiteRecoveryNodeDependencies ##
function Invoke-WACVMCloneVirtualMachine {
<#

.SYNOPSIS
Clone a virtual machine.

.DESCRIPTION
Clone the passed in virtual machine on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016, Windows Server 2019.

.ROLE
Hyper-V-Administrators

.PARAMETER vmId
    The id of the requested virtual machine.

.PARAMETER newVmName
    The name of the new virtual machine.

.PARAMETER clonePath
    The path where the virtual machine should be cloned to.

.PARAMETER username
    The username of the parent VM.

.PARAMETER key
    The key to the parent VM.

.PARAMETER performSysprep
    Whether or not to perform Syprep

.Parameter addClusterRole
	Whether or not to add the newly created VM to cluster
#>

param (
  [Parameter(Mandatory = $true)]
  [String]
  $vmId,
  [Parameter(Mandatory = $true)]
  [String]
  $newVmName,
  [Parameter(Mandatory = $true)]
  [String]
  $clonePath,
  [Parameter(Mandatory = $true)]
  [String]
  $username,
  [Parameter(Mandatory = $true)]
  [String]
  $key,
  [Parameter(Mandatory = $true)]
  [Boolean]
  $performSysprep,
  [Parameter(Mandatory = $true)]
  [Boolean]
  $addClusterRole
)

Set-StrictMode -Version 5.0;
Import-Module Hyper-V -ErrorAction SilentlyContinue;


<#

.SYNOPSIS
Setup script runtime environment.

.DESCRIPTION
Setup script runtime environment.

#>

function setupScriptEnv() {
  Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
  Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScript" -Scope Script
  Set-Variable -Name ScriptName -Option ReadOnly -Value "Invoke-CloneVirtualMachine.ps1" -Scope Script
}


<#

.SYNOPSIS
Cleanup script runtime environment.

.DESCRIPTION
Cleanup script runtime environment.

#>

function cleanupScriptEnv() {
  Remove-Variable -Name LogName -Scope Script -Force
  Remove-Variable -Name LogSource -Scope Script -Force
  Remove-Variable -Name ScriptName -Scope Script -Force
}


function handleErrorAndRestoreVM(
		[string]$error,
		$vm,
		[string]$originalState
) {
  Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
    -Message "[$ScriptName]: $error"  -ErrorAction SilentlyContinue

  $checkpointName = "pre-sypsprep"
  Get-VMSnapshot -Name $checkpointName -VMName $vm.Name -ErrorAction SilentlyContinue |
  Sort-Object CreationTime |
  Microsoft.PowerShell.Utility\Select-Object -Last 1 |
  Restore-VMSnapshot -ErrorAction SilentlyContinue | Remove-VMSnapshot

  if ($originalState -eq "Running") {
    $vm | Start-VM
  }

  Write-Error $error

  return @()
}

<#

.SYNOPSIS
The sysPrepVM function.

.DESCRIPTION
Syspreps a VM in preparation for cloning.

.PARAMETER vmId
The id of the VM to be cloned

#>

function sysPrepVM(
		[String]$vmId,
		[String]$username,
		[String]$key,
		[int]$maxRepeat
) {
  $vm = Get-RBACVM -Id $vmId

  $password = ConvertTo-SecureString -String $key -AsPlainText -Force
  $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $password

  $originalErrorLogContentCount = 0
  $logContentCount = 0

  $logFileExists = Invoke-Command -VMId $vmId -ScriptBlock {
    $logFilePath = "C:\Windows\System32\Sysprep\Panther\setupact.log"
    Test-Path -Path  $logFilePath
  } -Credential $Credential -ErrorAction Silentlycontinue -ErrorVariable err

  if ($logFileExists) {
    Invoke-Command -VMId $vmId -ScriptBlock {
      $logFilePath = "C:\Windows\System32\Sysprep\Panther"
      Remove-Item -Path  $logFilePath -Recurse
    } -Credential $Credential -ErrorAction Silentlycontinue -ErrorVariable err

    $success_file_exists = Invoke-Command -VMId $vmId -ScriptBlock {
      $logFilePath = "C:\Windows\System32\Sysprep\sysprep_succeeded.tag"
      Test-Path -Path  $logFilePath
    } -Credential $Credential -ErrorAction Silentlycontinue -ErrorVariable err

    if ($success_file_exists) {
      Invoke-Command -VMId $vmId -ScriptBlock {
        $logFilePath = "C:\Windows\System32\Sysprep\sysprep_succeeded.tag"
        Remove-Item -Path  $logFilePath -Recurse
      } -Credential $Credential -ErrorAction Silentlycontinue -ErrorVariable err
    }

    $logFileExists = $false
  }

  $currentIteration = 0
  $iterationsSinceLastLog = 0

  do {
    $vm = Get-RBACVM -Id $vmId
    $logFileContent = ""

    $previousLogContentCount = $logContentCount;

    if ($vm.State -eq "Running") {
      if (-not $logFileExists) {
        Invoke-Command -VMId $vmId -ScriptBlock {
          $sysprep = "C:\Windows\System32\Sysprep\Sysprep.exe"
          $arg = "/generalize /oobe /shutdown /quiet /mode:vm"
          $sysprep += " $arg"
          Invoke-Expression $sysprep
        } -Credential $Credential -ErrorAction Silentlycontinue -ErrorVariable sysprepError
      }

      if ($logFileExists) {
        $logFileContent = Invoke-Command -VMId $vmId -ScriptBlock {
          $logFilePath = "C:\Windows\System32\Sysprep\Panther\setupact.log"
          Get-Item -Path  $logFilePath  | Get-Content
        } -Credential $Credential -ErrorAction Silentlycontinue -ErrorVariable err

        $logContentCount = @($logFileContent).Count

      }
      else {
        $logFileExists = Invoke-Command -VMId $vmId -ScriptBlock {
          $logFilePath = "C:\Windows\System32\Sysprep\Panther\setupact.log"
          Test-Path -Path  $logFilePath
        } -Credential $Credential -ErrorAction Silentlycontinue -ErrorVariable err
      }
    }

    if ($previousLogContentCount -eq $logContentCount) {
      $iterationsSinceLastLog++;
    }
    else {
      $iterationsSinceLastLog = 0;
    }

    $percentageComplete = ($currentIteration / $maxRepeat) * 100
    Write-Progress -PercentComplete $percentageComplete -Activity "Sysprep"

    Start-Sleep -Milliseconds 200
    $currentIteration++
  } until ($vm.State -eq "Off" -or $iterationsSinceLastLog -gt $maxRepeat -or $currentIteration -eq $maxRepeat)

  # If we succeed in shutdown, Sysprep was successful
  if ($vm.State -eq "Off") {
    $percentComplete = 50
    Write-Progress -PercentComplete $percentComplete -Activity "Sysprep"
  }
  else {
    if ($sysprepError) {
      return $sysprepError
    }
    $logError = "Sysprep could not be completed.";

    $errorLogFileExists = Invoke-Command -VMId $vmId -ScriptBlock {
      $logFilePath = "C:\Windows\System32\Sysprep\Panther\setuperr.log"
      Test-Path -Path  $logFilePath
    } -Credential $Credential -ErrorAction Silentlycontinue

    if ($errorLogFileExists) {
      $errorLogContent = Invoke-Command -VMId $vmId -ScriptBlock {
        $logFilePath = "C:\Windows\System32\Sysprep\Panther\setuperr.log"
        Get-Item -Path  $logFilePath  | Get-Content
      } -Credential $Credential -ErrorAction Silentlycontinue

      for ($index = $originalErrorLogContentCount; $index -lt @($errorLogContent).Count; $index++) {
        if ($errorLogContent[$index] -Match "error") {
          $logError += $errorLogContent[$index]
        }
      }
    }

    return $logError
  }
}

<#

.SYNOPSIS
Import a virtual machine.

.DESCRIPTION
Import the passed in virtual machine on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016, Windows Server 2019.

.ROLE
Hyper-V-Administrators

.PARAMETER configPath
    The path containing the virtual machine configuration files

.PARAMETER vmId
    The name of the virtual machine to be imported

.PARAMETER vmName
    The ID of the virtual machine to be imported

.PARAMETER newName
    The new name of the virtual machine to be imported

.PARAMETER createNewId
    The flag to determine whether a new virtual machine ID should be created or not

.PARAMETER copyVm
    The flag to determine whether virtual machine should be copied or not

.PARAMETER targetPath
    The path where the virtual machines files should be placed

.PARAMETER addClusterRole
    The flag to create a clustered virtual machine

#>
function importVM(
		[string]$configPath,
		[string]$vmId,
		[string]$vmName,
		[string]$newName,
		[string]$targetPath,
		[boolean]$createNewId,
		[boolean]$copyVm,
		[boolean]$addClusterRole
) {
  $err = $null
  $args = @{}
  $renameVm = $false
  $vhdDestinationPath = ''
  $virtualMachinePath = ''

  if (-not ($createNewId) -and -not($copyVm)) {
    $args += @{ Path = $configPath }
  }
  else {
    if ($newName) {
      $virtualMachinePath = "$targetPath\$newName"
      if ($newName -eq $vmName) {
        $date = Get-Date -Format "yyyy-MM-dd HH-mm-ss"
        $vhdDestinationPath = "$targetPath\$vmName\Virtual Hard Disks\$vmName (imported) - $date"
      }
      else {
        $vhdDestinationPath = "$targetPath\$newName\Virtual Hard Disks"
        $renameVm = $true
      }
    }
    else {
      $virtualMachinePath = "$targetPath\$vmName"
    }

    $args += @{ Path = $configPath; Copy = $true; VirtualMachinePath = $virtualMachinePath; VhdDestinationPath = $vhdDestinationPath }
    if ($createNewId) {
      $args += @{ GenerateNewId = $true; }
    }
  }

  $report = Compare-VM @args -ErrorAction SilentlyContinue -ErrorVariable err
  if ($err) {
    return $err[0].Exception.Message
  }

  if ($report -and -not ($report.Incompatibilities)) {
    $newVmId = $report.VM.Id
    Import-VM -CompatibilityReport $report -ErrorAction SilentlyContinue -ErrorVariable err

    if ($err) {
      return $err[0].Exception.Message
    }
    else {
      $percentComplete = 100
      Write-Progress -PercentComplete $percentComplete -Activity "Import completed"
    }

    $vm = Get-RBACVM -id $newVmId -ErrorAction SilentlyContinue -ErrorVariable err

    if ($renameVm) {
      if ($err) {
        return $err[0].Exception.Message
      }

      $vm | Rename-VM -NewName $newName -ErrorAction SilentlyContinue -ErrorVariable err

      if ($err) {
        return $err[0].Exception.Message
      }

    }

    if ($addClusterRole) {
      Add-ClusterVirtualMachineRole -VMId $newVmId -ErrorAction SilentlyContinue -ErrorVariable err

      if ($err) {
        return $err[0].Exception.Message
      }
    }

    # Remove all snapshots in cloned VM since the snapshot files don't actually exist
    $vm | Remove-VMSnapshot -ErrorAction SilentlyContinue

  }
  else {
    return "The selected virtual machine has an incompatibility with the host: {0}" -f $report.Incompatibilities[0].Message
  }
}

<#

.SYNOPSIS
The main function.

.DESCRIPTION
Clone the passed in virtual machine on this server.

#>
function main(
		[string]$vmId,
		[string]$newVmName,
		[string]$clonePath,
		[string]$username,
		[string]$key,
		[Boolean]$performSysprep,
		[Boolean]$addClusterRole
) {

  # Setup
  $parentVM = Get-RBACVM -id $vmId -ErrorAction SilentlyContinue -ErrorVariable getVmError

  if ($getVmError) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
      -Message "[$ScriptName]: $getVmError"  -ErrorAction SilentlyContinue

    Write-Error $getVmError
    return @()
  }

  $parentVMOriginalState = $parentVM.State
  $parentVMName = $parentVM.Name

  if ($performSysprep) {
    # Step 1. Create a checkpoint in the parent VM.
    #         The checkpoint will be used to return the VM to its original state

    $checkpointName = "pre-sypsprep"
    $parentVM | Checkpoint-VM -SnapshotName $checkpointName -ErrorVariable checkpointVmError -ErrorAction SilentlyContinue

    if ($checkpointVmError) {
      return handleErrorAndRestoreVM $checkpointVmError[0].Exception.Message $parentVM $parentVMOriginalState
    }
    else {
      $percentComplete = 10
      Write-Progress -PercentComplete $percentComplete -Activity ("Checkpoint created for {0}" -f $parentVM.Name)
    }

    # Start the machine if it was off
    $percentComplete = 20
    Write-Progress -PercentComplete $percentComplete -Activity "Starting virtual machine"
    if ($parentVM.State -ne "Running") {
      Start-VM -VM $parentVM -ErrorVariable operationError -ErrorAction SilentlyContinue
      if ($operationError) {
        return handleErrorAndRestoreVM $operationError[0].Exception.Message $parentVM $parentVMOriginalState
      }
      else {
        $percentComplete = 30
        Write-Progress -PercentComplete $percentComplete -Activity "Parent vm started"
      }
    }

    # Step 3. Sysprep the parent VM
    # Iterations for sysprep wait are in half seconds
    $maxRepeat = 360;
    if ($parentVMOriginalState -eq "Off") {
      $maxRepeat = 600;
    }
    $percentComplete = 35
    Write-Progress -PercentComplete $percentComplete -Activity "Syspreping the parent VM"
    $sysprepError = sysprepVM $vmId $username $key $maxRepeat
    if ($sysprepError) {
      return handleErrorAndRestoreVM $sysprepError $parentVM $parentVMOriginalState
    }
  }

  # Step 4. Export the parent VM to a temp path
  $exportPath = "$clonePath\$newVmName"
  $parentVM | Export-VM -Path  $exportPath -ErrorAction SilentlyContinue -ErrorVariable exportError
  if ($exportError) {
    return handleErrorAndRestoreVM $exportError[0].Exception.Message $parentVM $parentVMOriginalState
  }
  else {
    $percentComplete = 55
    Write-Progress -PercentComplete $percentComplete -Activity "Export completed"
  }

  # Revert the parent VM back to its original state
  if ($performSysprep) {
    Get-VMSnapshot -Name $checkpointName -VMName $parentVMName -ErrorVariable snapshotError -ErrorAction SilentlyContinue |
    Sort-Object CreationTime |
    Microsoft.PowerShell.Utility\Select-Object -Last 1 |
    Restore-VMSnapshot -Confirm:$false -Passthru |
    Remove-VMSnapshot

    if ($snapshotError) {
      return handleErrorAndRestoreVM $snapshotError[0].Exception.Message $parentVM $parentVMOriginalState
    }
    else {
      $percentComplete = 60
      Write-Progress -PercentComplete $percentComplete -Activity "Snapshot restore complete"
    }

    if ($parentVMOriginalState -eq "Running") {
      $parentVM | Start-VM
    }
  }


  # Step 6. Import the exported VM
  $configPath = "$exportPath\$parentVMName\Virtual Machines\$vmId.vmcx"
  $copyVm = $true
  $createNewId = $true
  importVM $configPath $vmId $parentVMName $newVmName $clonePath $createNewId $copyVm $addClusterRole

  Remove-Item -Path "$exportPath\$parentVMName" -ErrorAction SilentlyContinue -Recurse
}

###############################################################################
# Script execution starts here
###############################################################################
setupScriptEnv

try {
  Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

  $module = Get-Module -Name Hyper-V -ErrorAction SilentlyContinue -ErrorVariable +err
  if ($module) {
    return main $vmId $newVmName $clonePath $username $key $performSysprep $addClusterRole
  }

  Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
    -Message "[$ScriptName]: The required PowerShell module (Hyper-V) was not found."  -ErrorAction SilentlyContinue

  Write-Error @($err)[0]

  return @()
}
finally {
  cleanupScriptEnv
}



}
## [END] Invoke-WACVMCloneVirtualMachine ##
function Join-WACVMDomainVirtualMachine {
<#

.SYNOPSIS
Domain join a virtual machine.

.DESCRIPTION
Domain join Windows Server or Windows 10 VMs

.ROLE
Hyper-V-Administrators

.PARAMETER domainName
Domain to join

.PARAMETER domainUsername
The domain's username

.PARAMETER domainPassword
The domain's password

.PARAMETER vmId
The id of the requested virtual machine.

.PARAMETER vmUsername
The VM's username

.PARAMETER vmPassword
The VM's password
#>

param (
	[Parameter(Mandatory = $true)]
	[String]
	$domainName,
	[Parameter(Mandatory = $true)]
	[String]
	$domainUsername,
	[Parameter(Mandatory = $true)]
	[String]
	$domainPassword,
	[Parameter(Mandatory = $true)]
	[String]
	$vmId,
	[Parameter(Mandatory = $true)]
	[String]
	$vmUsername,
	[Parameter(Mandatory = $true)]
	[String]
	$vmPassword
)

Set-StrictMode -Version 5.0;
Import-Module Hyper-V -ErrorAction SilentlyContinue;

<#

.SYNOPSIS
Setup script runtime environment.

.DESCRIPTION
Setup script runtime environment.

#>

function setupScriptEnv() {
  Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
  Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScript" -Scope Script
  Set-Variable -Name ScriptName -Option ReadOnly -Value "Join-DomainirtualMachine.ps1" -Scope Script
}


<#

.SYNOPSIS
Cleanup script runtime environment.

.DESCRIPTION
Cleanup script runtime environment.

#>

function cleanupScriptEnv() {
  Remove-Variable -Name LogName -Scope Script -Force
  Remove-Variable -Name LogSource -Scope Script -Force
  Remove-Variable -Name ScriptName -Scope Script -Force
}

<#

.SYNOPSIS
Create secure credentials function

.DESCRIPTION
The function to create secure credentials

#>

function createSecureCreds($username, $key) {
  $secureString = ConvertTo-SecureString -String $key -AsPlainText -Force
  $secureCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $secureString

  return $secureCreds
}

<#

.SYNOPSIS
Domain join VM function

.DESCRIPTION
The function to join a VM to a domain

#>

function domainJoinVm(
	[String]$domainName,
	[String]$domainUsername,
	[String]$domainPassword,
  [String]$vmId,
  [String]$vmUsername,
  [String]$vmPassword
) {
  $vmCredential = createSecureCreds $vmUsername $vmPassword
  $domainCredential = createSecureCreds $domainUsername $domainPassword

  $domainJoin = Invoke-Command -VMId $vmId -ScriptBlock {
    Add-computer -DomainName $args[0] -Credential $args[1] -restart -force
  } -Credential $vmCredential -ArgumentList $domainName, $domainCredential -ErrorAction SilentlyContinue -ErrorVariable +err

  return $domainJoin
}

<#

.SYNOPSIS
The main function.

.DESCRIPTION
Join the VM to a domain

#>

function main(
	[String]$domainName,
	[String]$domainUsername,
	[String]$domainPassword,
  [String]$vmId,
  [String]$vmUsername,
  [String]$vmPassword
) {

  $joinDomain = domainJoinVm $domainName $domainUsername $domainPassword $vmId $vmUsername $vmPassword

  if (!!$err) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: There were errors joining the VM to a domain.  Errors: $err." -ErrorAction SilentlyContinue

    Write-Error @($err)[0]

    return $err[0].Exception.Message
  }

  return $joinDomain
}

if (-not ($env:pester)) {
  setupScriptEnv

  try {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    $module = Get-Module -Name Hyper-V -ErrorAction SilentlyContinue -ErrorVariable +err

    if ($module) {
      return main $domainName $domainUsername $domainPassword $vmId $vmUsername $vmPassword
    }

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: The required PowerShell module (Hyper-V) was not found." -ErrorAction SilentlyContinue

    Write-Error $strings.HyperVModuleRequired

    return @()
  }
  finally {
    cleanupScriptEnv
  }
}

}
## [END] Join-WACVMDomainVirtualMachine ##
function Move-WACVMVirtualMachine {
<#

.SYNOPSIS
Moves (live migrates) the passed in virtual machine to the passed in host server.

.DESCRIPTION
Moves (live migrates) the passed in virtual machine to the passed in host server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER parameters
    vmId: The Id of the requested virtual machine.
    vmName: The virtual machine name.
    currentHostServer: The current host server. This could be a cluster node.
    destinationHostServer: The name of the new host server. If the new host server is a member of the current cluster
                           then cluster migration will be used.
    includeStorage:
    destinationPath:
    isClustered:

#>

param (
    [Parameter(Mandatory = $true)]
    [Object] $parameters
)

Set-StrictMode -Version 5.0

Import-Module Hyper-V -ErrorAction SilentlyContinue
Import-Module FailoverClusters -ErrorAction SilentlyContinue
Import-Module Microsoft.PowerShell.Management -ErrorAction SilentlyContinue
Import-Module CimCmdlets -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Indicates the type of move that should be performed

.DESCRIPTION
Indicates the type of move that should be performed

#>

enum MoveType {
    WithinCluster
    NewCluster
    StandAloneServer
    Unknown
}

enum ValidationErrorId
{
    SavedStateIncompatible = 21016
    MissingSnapshot = 40002
    SaveStateFileMissing = 40004
    MemoryFileMissing = 40006
    PassThroughDiskDetected = 40008
    VhdFileMissing = 40010
    MemoryWeightAboveMax = 40012
    MemoryQuantityAboveMax = 40014
    MemoryQuantityBelowMin = 40016
    MemoryQuantityNotMultipleOf2 = 40018
    MemoryQuantityAboveLimit = 40020
    MemoryQuantityBelowReservation = 40022
    MemoryLimitAboveMax = 40024
    MemoryLimitBelowMin = 40026
    MemoryLimitNotMultipleOf2 = 40028
    MemoryReservationAboveMax = 40030
    MemoryReservationBelowMin = 40032
    MemoryReservationNotMultipleOf2 = 40034
    MemoryBufferAboveMax = 40036
    MemoryBufferBelowMin = 40038
    DynamicMemoryNumaSpanningConflict = 40040
    VDevInvalidPoolId = 12638
    SynthFcPoolIdNotFound = 32172
    SynthFcPoolIdInvalid = 32173
    DeviceNotCompatible = 24008
    VmVersionNotSupported = 24006
    VmFailedTopologyInit = 25014
    ProcessorVendorMismatch = 24002
    ProcessorFeaturesNotSupported = 24004
    MemoryPoolIdInvalid = 23134
    ProcessorLimitOutOfRange = 14390
    ProcessorReservationOutOfRange = 14400
    ProcessorWeightOutOfRange = 14410
    ProcessorVirtualQuantityOutOfRange = 14420
    ProcessorPoolIdInvalid = 14424
    EthernetPoolNotFound = 33010
    EthernetSwitchNotFound = 33012
    EthernetSwitchNotFoundInPool = 33014
    ConfigurationDataRootCreationFailure = 13000
    SnapshotDataRootCreationFailure = 16350
    SlpDataRootCreationFailure = 16352
    PassThroughDiskNotFound = 27106
    StoragePoolAbsolutePathRequired = 32900
    StoragePoolAmbiguousRelativePath = 32906
    StoragePoolAbsolutePathNotInBaseDirectories = 32908
    StoragePoolPathContainingIntegrityStream = 32928
    RemoteFxIncompatible = 32605
    GroupNotFound = 40046
}

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.  Create read only (constant) variables
that add context to the said constants.

#>

function setupScriptEnv() {
    ##SkipCheck=true##
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Move-VirtualMachine.ps1" -Scope Script
    Set-Variable -Name VmRefreshValue -Option ReadOnly -Value 0 -Scope Script
    Set-Variable -Name BritannicaNamespace -Option ReadOnly -Value "root\sddc\management" -Scope Script
    Set-Variable -Name SDDCVirtualMachineClassName -Option ReadOnly -Value "SDDC_VirtualMachine" -Scope Script
    Set-Variable -Name RefreshMethodName -Option ReadOnly -Value "Refresh" -Scope Script
    Set-Variable -Name RefreshTypeParamName -Option ReadOnly -Value "RefreshType" -Scope Script
    Set-Variable -Name RunningState -Option ReadOnly -Value "Running" -Scope Script
    Set-Variable -Name VmIdParameterName -Option ReadOnly -Value "VmId" -Scope Script
    Set-Variable -Name VmNameParameterName -Option ReadOnly -Value "VmName" -Scope Script
    Set-Variable -Name CurrentHostServerParameterName -Option ReadOnly -Value "CurrentHostServer" -Scope Script
    Set-Variable -Name DestinationHostServerParameterName -Option ReadOnly -Value "DestinationHostServer" -Scope Script
    Set-Variable -Name DestinationHostClusterParameterName -Option ReadOnly -Value "DestinationHostCluster" -Scope Script
    Set-Variable -Name IncludeStorageParameterName -Option ReadOnly -Value "IncludeStorage" -Scope Script
    Set-Variable -Name DestinationPathParameterName -Option ReadOnly -Value "DestinationPath" -Scope Script
    Set-Variable -Name DestinationHostArgumentName -Option ReadOnly -Value "DestinationHost" -Scope Script
    Set-Variable -Name DestinationStoragePathArgumentName -Option ReadOnly -Value "DestinationStoragePath" -Scope Script
    Set-Variable -Name VirtualMachinePathArgumentName -Option ReadOnly -Value "VirtualMachinePath" -Scope Script
    Set-Variable -Name IncludeStorageArgumentName -Option ReadOnly -Value "IncludeStorage" -Scope Script
    Set-Variable -Name NodeArgumentName -Option ReadOnly -Value "Node" -Scope Script
    Set-Variable -Name VMIdArgumentName -Option ReadOnly -Value "VMID" -Scope Script
    Set-Variable -Name MigrationTypeArgumentName -Option ReadOnly -Value "MigrationType" -Scope Script
    Set-Variable -Name VhdsArgumentName -Option ReadOnly -Value "Vhds" -Scope Script
    Set-Variable -Name MigrationTypeArgumentValueLive -Option ReadOnly -Value "Live" -Scope Script
    Set-Variable -Name MigrationTypeArgumentValueQuick -Option ReadOnly -Value "Quick" -Scope Script
    Set-Variable -Name VhdsPropertyName -Option ReadOnly -Value "Vhds" -Scope Script
    Set-Variable -Name ErrPropertyName -Option ReadOnly -Value "Err" -Scope Script
    Set-Variable -Name SourceFilePathPropertyName -Option ReadOnly -Value "SourceFilePath" -Scope Script
    Set-Variable -Name DestinationFilePathPropertyName -Option ReadOnly -Value "DestinationFilePath" -Scope Script
    Set-Variable -Name PathPropertyName -Option ReadOnly -Value "Path" -Scope Script
    Set-Variable -Name IsClusteredPropertyName -Option ReadOnly -Value "IsClustered" -Scope Script
    Set-Variable -Name VirtualAdapterVirtualSwitchMapsParameterName -Option ReadOnly -Value "VirtualAdapterVirtualSwitchMaps" -Scope Script
    Set-Variable -Name VirtualMachineResourceQueryString -Option ReadOnly -Value "select PrivateProperties, Id from mscluster_resource where type='virtual machine' and PrivateProperties.vmId='{0}'" -Scope Script
    Set-Variable -Name MSClusterNamespace -Option ReadOnly -Value "Root\MSCluster" -Scope Script
    Set-Variable -Name HyperVModuleName -Option ReadOnly -Value "Hyper-V" -Scope Script
    Set-Variable -Name FailoverClustersModuleName -Option ReadOnly -Value "FailoverClusters" -Scope Script
    Set-Variable -Name IncompatibilitiesPropertyName -Option ReadOnly -Value "Incompatibilities" -Scope Script
    Set-Variable -Name MessageIdPropertyName -Option ReadOnly -Value "MessageId" -Scope Script
    Set-Variable -Name DisconnectSwitchSwitchId -Option ReadOnly -Value "disconnectSwitch" -Scope Script
    ##SkipCheck=false##
}

<#

.SYNOPSIS
Cleanup the script environment.

.DESCRIPTION
Cleanup the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name VmRefreshValue -Scope Script -Force
    Remove-Variable -Name BritannicaNamespace -Scope Script -Force
    Remove-Variable -Name SDDCVirtualMachineClassName -Scope Script -Force
    Remove-Variable -Name RefreshMethodName -Scope Script -Force
    Remove-Variable -Name RefreshTypeParamName -Scope Script -Force
    Remove-Variable -Name RunningState -Scope Script -Force
    Remove-Variable -Name VmIdParameterName -Scope Script -Force
    Remove-Variable -Name VmNameParameterName -Scope Script -Force
    Remove-Variable -Name CurrentHostServerParameterName -Scope Script -Force
    Remove-Variable -Name DestinationHostServerParameterName -Scope Script -Force
    Remove-Variable -Name DestinationHostClusterParameterName -Scope Script -Force
    Remove-Variable -Name IncludeStorageParameterName -Scope Script -Force
    Remove-Variable -Name DestinationPathParameterName -Scope Script -Force
    Remove-Variable -Name DestinationHostArgumentName -Scope Script -Force
    Remove-Variable -Name DestinationStoragePathArgumentName -Scope Script -Force
    Remove-Variable -Name VirtualMachinePathArgumentName -Scope Script -Force
    Remove-Variable -Name IncludeStorageArgumentName -Scope Script -Force
    Remove-Variable -Name NodeArgumentName -Scope Script -Force
    Remove-Variable -Name VMIdArgumentName -Scope Script -Force
    Remove-Variable -Name MigrationTypeArgumentName -Scope Script -Force
    Remove-Variable -Name VhdsArgumentName -Scope Script -Force
    Remove-Variable -Name MigrationTypeArgumentValueLive -Scope Script -Force
    Remove-Variable -Name MigrationTypeArgumentValueQuick -Scope Script -Force
    Remove-Variable -Name VhdsPropertyName -Scope Script -Force
    Remove-Variable -Name ErrPropertyName -Scope Script -Force
    Remove-Variable -Name SourceFilePathPropertyName -Scope Script -Force
    Remove-Variable -Name DestinationFilePathPropertyName -Scope Script -Force
    Remove-Variable -Name PathPropertyName -Scope Script -Force
    Remove-Variable -Name IsClusteredPropertyName -Scope Script -Force
    Remove-Variable -Name VirtualAdapterVirtualSwitchMapsParameterName -Scope Script -Force
    Remove-Variable -Name VirtualMachineResourceQueryString -Scope Script -Force
    Remove-Variable -Name MSClusterNamespace -Scope Script -Force
    Remove-Variable -Name HyperVModuleName -Scope Script -Force
    Remove-Variable -Name FailoverClustersModuleName -Scope Script -Force
    Remove-Variable -Name IncompatibilitiesPropertyName -Scope Script -Force
    Remove-Variable -Name MessageIdPropertyName -Scope Script -Force
    Remove-Variable -Name DisconnectSwitchSwitchId -Scope Script -Force
}

<#

.SYNOPSIS
Get the fully qualified domain name for the passed in server name from DNS.

.DESCRIPTION
Get the fully qualified domain name for the passed in server name from DNS.

#>

function getServerFqdn([string]$netBIOSName) {
    try {
        return ([System.Net.DNS]::GetHostByName($netBIOSName).HostName)
    }
    catch {
        $errMessage = $_.Exception.Message

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: There was an error looking up the FQDN for server $netBIOSName.  Error: $errMessage"  -ErrorAction SilentlyContinue

        return $netBIOSName
    }
}

<#

.SYNOPSIS
Turn a server name, or server FQDN, into a NetBIOS name to match the cluster node names.

.DESCRIPTION
Turn a server name, or server FQDN, into a NetBIOS name to match the cluster node names.

#>

function toNetBIOSName([string] $serverName) {
    $parts = $serverName -Split "\."

    return @($parts)[0]
}

<#

.SYNOPSIS
Find the passed in server name in the list of cluster nodes.

.DESCRIPTION
Find the passed in server name in the list of cluster nodes.

#>

function findClusterNode($nodes, [String] $serverName) {
    return $nodes | Microsoft.PowerShell.Core\Where-Object { $_.Name -eq (toNetBIOSName $serverName) }
}

<#

.SYNOPSIS
Determines the type of move that should be performed

.DESCRIPTION
Determines the type of move that should be performed

#>

function determineMoveType([Object] $parameters) {
    $err = $null

    if ($parameters.$IsClusteredPropertyName) {
        $cluster = Get-Cluster -ErrorAction SilentlyContinue -ErrorVariable +err
        if (!!$err) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: There was an error getting the cluster on this cluster node.  Error: $err" -ErrorAction SilentlyContinue

            Write-Error @($err)[0]

            return [MoveType]::Unknown
        }

        # If this server is a cluster member, and the current host server and the destination host server are also
        # members of this cluster then we are moving the VM within the cluster using cluster migration commands.
        if (!!$cluster) {
            $clusterName = $cluster.Name

            $nodes = @($cluster | Get-ClusterNode -ErrorAction SilentlyContinue -ErrorVariable +err)
            if (!!$err) {
                Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                    -Message "[$ScriptName]: There was an error getting the nodes of cluster $clusterName.  Error: $err" -ErrorAction SilentlyContinue

                Write-Error @($err)[0]

                return [MoveType]::Unknown
            }

            $currentHostNode = findClusterNode $nodes $parameters.$CurrentHostServerParameterName

            # Set to any node since the most important test is if the current host server is in this cluster.
            # The destination server can be null for "best available"...
            $destinationHostNode = @($nodes)[0]

            if ($parameters.$DestinationHostServerParameterName) {
                $destinationHostNode = findClusterNode $nodes $parameters.$DestinationHostServerParameterName
            }

            if (!!$currentHostNode -and !!$destinationHostNode) {
                return [MoveType]::WithinCluster
            }
        }
    }

    # If a new destination host cluster has been provided then we are moving the VM to a new server
    # within that cluster.  The best host node script will be used to determine the exact node
    # to use.  The operation requires CredSSP be enabled between this server and the gateway.
    if ($parameters.$DestinationHostClusterParameterName) {
        return [MoveType]::NewCluster
    }

    # If none of the above are true, then we expect to be moving the VM to a new stand alone server..
    if ($parameters.$DestinationHostServerParameterName) {
        return [MoveType]::StandAloneServer
    }

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Unable to detemine how to move the virtual machine to the requested destination host. Parameters: $parameters" -ErrorAction SilentlyContinue

    return [MoveType]::Unknown
}

<#

.SYNOPSIS
Validate the storage parameters as being complete.

.DESCRIPTION
Validate the storage parameters as being complete.

#>

function validateStorageParameters([Object] $parameters) {
    $storageValid = $parameters.$IncludeStorageParameterName -and !!$parameters.$DestinationPathParameterName

    if (!$storageValid) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: The storage parameters were not valid. Parameters: $parameters" -ErrorAction SilentlyContinue

        Write-Error $strings.MoveVirtualMachineStorageParametersInvalid
    }

    return $storageValid
}

<#

.SYNOPSIS
Validate the parameters as being complete for each move type.

.DESCRIPTION
Each move type will require a unique set of parameter to be considered a complete move reqest.

#>

function validateParameters([MoveType] $moveType, [Object] $parameters) {
    $valid = $false

    if ($moveType -eq [MoveType]::WithinCluster) {
        $valid = !!$parameters.$CurrentHostServerParameterName
    }

    if ($moveType -eq [MoveType]::NewCluster) {
        $storageValid = validateStorageParameters $parameters

        $valid = !!$parameters.$DestinationHostClusterParameterName -and $storageValid
    }

    if ($moveType -eq [MoveType]::StandAloneServer) {
        $storageValid = validateStorageParameters $parameters

        $valid = !!$parameters.$DestinationHostServerParameterName -and $storageValid
    }

    if (-not($valid)) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: The parameters to move the VM to another node of the cluster are not valid." -ErrorAction SilentlyContinue

        Write-Error $strings.MoveVirtualMachineInvalidParameters
    }

    return $valid
}

<#

.SYNOPSIS
Determines if Britannica (sddc management resources) are available on the cluster

.DESCRIPTION

Use the existance of the cim namespace root/sddc/Management and class name to determine if Britannica
is supported or not.

#>

function isBritannicaEnabled() {
    $err = $null

    $enabled = !!(Get-CimInstance -Namespace $BritannicaNamespace -ClassName $SDDCVirtualMachineClassName -ErrorAction SilentlyContinue -ErrorVariable +err)
    if (!!$err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: There was an error determining if Britannica is available.  Error: $err" -ErrorAction SilentlyContinue

        return $false
    }

    if ($enabled) {$true } else {$false}
}

<#

.SYNOPSIS
Refresh virtual machine match given $vmId

.DESCRIPTION
Find vm match given $vmId from Britannica, then force refresh it

#>

function refreshBritannicaVm([string] $vmId) {
    $err = $null

    $vm = Get-CimInstance -Namespace $BritannicaNamespace -ClassName $SDDCVirtualMachineClassName | `
        Microsoft.PowerShell.Core\Where-Object { $_.Id.ToLower() -eq $vmId.ToLower() } -ErrorAction SilentlyContinue -ErrorVariable +err
    if (!!$err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: There was an error find the VM with Id $vmId in the Britannica cache.  Error: $err" -ErrorAction SilentlyContinue

        return
    }

    if (!!$vm) {
        Invoke-CimMethod -CimInstance $vm -MethodName $RefreshMethodName -Arguments @{ $RefreshTypeParamName = $VmRefreshValue } -ErrorAction SilentlyContinue -ErrorVariable +err
        if (!!$err) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: There was an error refreshing the Britannica cache.  Error: $err" -ErrorAction SilentlyContinue
            
            return
        }
    }
}

<#

.SYNOPSIS
Move the VM to a new host in the cluster of which this server is a member.

.DESCRIPTION
Move the VM to a new host in the cluster of which this server is a member.

#>

function moveVmToNewClusterHostNode($parameters) {
    $err = $null
    $vmId = $parameters.$VMIdArgumentName

    $vm = getVirtualMachine $vmId
    if (-not($vm) -or $global:Error.Count -gt 0) {
        return $global:Error
    }

    $arguments = @{
        $VMIdArgumentName = $vm.Id;
    }

    $newHostNode = $parameters.$DestinationHostServerParameterName
    if ($newHostNode) {
        $arguments += @{ $NodeArgumentName = $newHostNode }
    }

    if ($vm.State -eq $RunningState) {
        $arguments += @{ $MigrationTypeArgumentName = $MigrationTypeArgumentValueLive }
    }
    else {
        $arguments += @{ $MigrationTypeArgumentName = $MigrationTypeArgumentValueQuick }
    }

    try {
        $group = getClusterGroupForVm $vm
        if (-not($group) -or $global:Error.Count -gt 0) {
             return $global:Error
        }
    
        $vmName = $vm.Name

        $group | Move-ClusterVirtualMachineRole @args -ErrorAction SilentlyContinue -ErrorVariable +err
        if (!!$err) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: There was an error moving virtual machine $vmName to node $newHostNode within the cluster.  Error: $err" -ErrorAction SilentlyContinue

            Write-Error @($err)[0]

            return $err
        }

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Info `
            -Message "[$ScriptName]: Successfully moved virtual machine $vmName to another node $newHostNode within the cluster." -ErrorAction SilentlyContinue

        return $null
    }
    finally {
        if (isBritannicaEnabled) {
            refreshBritannicaVm $vm.Id
        }
    }
}

<#

.SYNOPSIS
Add the VM to the cluster.

.DESCRIPTION
This function is a script block that will be invoked on the destination host server.

#>

function addVmToCluster {
    [CmdletBinding()]
    PARAM (
        [string]$vmId
    )

    begin {
        Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Local
        Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Local
        Set-Variable -Name ScriptName -Option ReadOnly -Value "New-VirtualMachine.ps1" -Scope Local
        Set-Variable -Name FailoverClustersModuleName -Option ReadOnly -Value "FailoverClusters" -Scope Local
    }
    process {
        $err = $null

        Import-Module -Name $FailoverClustersModuleName -ErrorAction SilentlyContinue -ErrorVariable +err
        if (!!$err) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: The required PowerShell module (FailoverClusters) was not found. Error: $err" -ErrorAction SilentlyContinue

            Write-Error @($err)[0]

            return $err
        }

        $cluster = Get-Cluster
        $clusterName = $cluster.Name

        Add-ClusterVirtualMachineRole -VMId $vmId -ErrorAction SilentlyContinue -ErrorVariable +err | Out-Null
        if (!!$err) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: There was an error adding virtual machine with VMId $vmId to cluster $clusterName. Error: $err" -ErrorAction SilentlyContinue

            Write-Error @($err)[0]

            return $err
        }

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Info `
            -Message "[$ScriptName]: Successfully added virtual machine with VMId $vmId to cluster $clusterName." -ErrorAction SilentlyContinue

        return $null
    }
    end {
        Remove-Variable -Name LogName -Scope Local -Force
        Remove-Variable -Name LogSource -Scope Local -Force
        Remove-Variable -Name ScriptName -Scope Local -Force
        Remove-Variable -Name FailoverClustersModuleName -Scope Local -Force
    }
}

<#

.SYNOPSIS
Move the VM to a new host cluster.  This requires that CredSSP be enabled between the gateway and this server.

.DESCRIPTION
Move the VM to a new host cluster.

#>

function moveVmToNewCluster($parameters) {
    $err = $null
    $vmId = $parameters.$VMIdArgumentName

    $vm = getVirtualMachine $vmId
    if (-not($vm) -or $global:Error.Count -gt 0) {
        return
    }

    $vmName = $vm.Name
    $clusterName = $parameters.$DestinationHostClusterParameterName

    $err = removeFromCluster $vm
    if (!!$err) {
        return $err
    }

    if ($vm.$IsClusteredPropertyName) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Warning `
            -Message "[$ScriptName][moveVmToNewCluster]: Virtual machine $vmName ($vmId) thinks it is still clustered." -ErrorAction SilentlyContinue
    }
    
    $err = moveVmToStandAloneServer $vm $parameters
    if (!!$err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Info `
            -Message "[$ScriptName]: Attempting to add virtual machine with VM $vmName ($vmId) back to its host cluster because VM moved failed." -ErrorAction SilentlyContinue

        addVmToCluster $vmId

        if (isBritannicaEnabled) {
            refreshBritannicaVm $vm.Id
        }

        return $err
    }

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Info `
        -Message "[$ScriptName]: Attempting to add virtual machine with VM $vmName ($vmId) to new host cluster $clusterName." -ErrorAction SilentlyContinue

    Invoke-Command -ScriptBlock ${function:addVmToCluster} -ComputerName $parameters.$DestinationHostServerParameterName `
        -ArgumentList $vmId -ErrorAction SilentlyContinue -ErrorVariable +err
    if (!!$err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: There was an error adding virtual machine with VM $vmName ($vmId) to cluster $clusterName. Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return $err
    }

    return $null
}

<#

.SYNOPSIS
Move the VM to a new host server.  This requires that CredSSP be enabled between the gateway and this server.

.DESCRIPTION
Move the VM to a new host server.  Manage the clustered state of the VM to support this move.

#>

function moveVmToNewServer($parameters) {
    $err = $null
    $vmId = $parameters.$VMIdArgumentName

    $vm = getVirtualMachine $vmId
    if (-not($vm) -or $global:Error.Count -gt 0) {
        return
    }

    $vmName = $vm.Name

    $isClustered = $parameters.$IsClusteredPropertyName
    if ($isClustered) {
        $err = removeFromCluster $vm
        if (!!$err) {
            return $err
        }
    }

    if ($vm.$IsClusteredPropertyName) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Info `
            -Message "[$ScriptName][moveVmToNewServer]: Virtual machine $vmName ($vmId) thinks it is still clustered." -ErrorAction SilentlyContinue
    }
    
    $err = moveVmToStandAloneServer $vm $parameters
    if (!!$err) {
        if ($isClustered) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Info `
                -Message "[$ScriptName]: Attempting to add virtual machine with VM $vmName ($vmId) back to its host cluster because VM moved failed." -ErrorAction SilentlyContinue

            addVmToCluster $vmId

            if (isBritannicaEnabled) {
                refreshBritannicaVm $vm.Id
            }
        }

        return $err
    }

    return $null
}

<#

.SYNOPSIS
Since the VM is clustered it it will have a cluster group.

.DESCRIPTION
Find the cluster group (role) that manages the VM.

#>
function getClusterGroupForVm($vm) {
    $err = $null
    $vmName = $vm.Name

    $queryString = $VirtualMachineResourceQueryString -f $vm.Id

    $vmResource = Get-CimInstance -Namespace $MSClusterNamespace -Query $queryString -ErrorAction SilentlyContinue -ErrorVariable +err
    if (!!$err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: There was an error getting the virtual machine resource for $vmName from CIM.  Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return $null
    }

    if (-not($vmResource)) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: The virtual machine resource for $vmName was not found." -ErrorAction SilentlyContinue

        $err = [System.IO.FileNotFoundException] $vmName
        Write-Error @($err)[0]

        return $null
    }

    $resource = Get-ClusterResource -Name $vmResource.Id -ErrorAction SilentlyContinue -ErrorVariable +err
    if (!!$err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: There was an error getting the virtual machine resource for $vmName.  Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return $null
    }

    $group = Get-ClusterGroup -Name $resource.OwnerGroup.Id -ErrorAction SilentlyContinue -ErrorVariable +err
    if (!!$err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: There was an error getting the virtual machine role for $vmName.  Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return $null
    }

    return $group
}

<#

.SYNOPSIS
Since the VM is clustered it must be removed (detached) from the cluster before it can be moved.

.DESCRIPTION
Find the cluster group (role) that manages the VM and remove it from the cluster.

#>
function removeFromCluster($vm) {
    $err = $null

    # If the VM is not currently clustered then it is in the desired non-clustered state...
    if (-not($vm.$IsClusteredPropertyName)) {
        return $null
    }

    $group = getClusterGroupForVm $vm
    if (-not($group) -or $global:Error.Count -gt 0) {
         $err = $global:Error

         return $err
    }

    $group | Remove-ClusterGroup -RemoveResources -Force -ErrorAction SilentlyContinue -ErrorVariable +err
    if (!!$err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: There was an error removing the virtual machine role for $vmName and detaching it from the cluster.  Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return $err
    }
    
    if (isBritannicaEnabled) {
        refreshBritannicaVm $vm.Id
    }

    # It seems that VMMS is holding onto the isClustered state for some time after the VM is removed from the cluster...
    # Wait for up to 10 seconds for the VM to update...
    for ($i = 0; $i -lt 10; $i++) {
        if (-not($vm.isClustered)) {
            break
        }

        Start-Sleep -Seconds 1
    }

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Info `
        -Message "[$ScriptName]: Successfully removed the virtual machine role for $vmName and detached it from the cluster." -ErrorAction SilentlyContinue

    return $null
}

<#

.SYNOPSIS
Enable virtual machine migration, and configure live migration networks as needed.

.DESCRIPTION
This function can be called as a  script block that will be invoked on the destination host server.

#>

function enableMigration() {
    [CmdletBinding()]
    PARAM()
    begin {
        Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Local
        Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Local
        Set-Variable -Name ScriptName -Option ReadOnly -Value "New-VirtualMachine.ps1" -Scope Local
        Set-Variable -Name AnySubnetIPv4 -Option ReadOnly -Value "0.0.0.0" -Scope Local
        Set-Variable -Name AnySubnetIPv6 -Option ReadOnly -Value "::0" -Scope Local
        Set-Variable -Name UserManagedAllNetworks -Option ReadOnly -Value "Microsoft:UserManagedAllNetworks" -Scope Local
        Set-Variable -Name UserManaged -Option ReadOnly -Value "Microsoft:UserManaged" -Scope Local
        Set-Variable -Name MsvmVirtualSystemMigrationNetworkSettingDataClassName -Option ReadOnly -Value "Msvm_VirtualSystemMigrationNetworkSettingData" -Scope Local
        Set-Variable -Name MsvmVirtualSystemMigrationServiceClassName -Option ReadOnly -Value "Msvm_VirtualSystemMigrationService" -Scope Local
        Set-Variable -Name AddNetworkSettingsMethodName -Option ReadOnly -Value "AddNetworkSettings" -Scope Local
        Set-Variable -Name VirtualizationNamespace -Option ReadOnly -Value "root\virtualization\v2" -Scope Local
        Set-Variable -Name HyperVModuleName -Option ReadOnly -Value "Hyper-V" -Scope Local
        Set-Variable -Name PrefixLengthPropertyName -Option ReadOnly -Value "PrefixLength" -Scope Local
        Set-Variable -Name SubnetNumberPropertyName -Option ReadOnly -Value "SubnetNumber" -Scope Local
        Set-Variable -Name TagsPropertyName -Option ReadOnly -Value "Tags" -Scope Local
        Set-Variable -Name MetricPropertyName -Option ReadOnly -Value "Metric" -Scope Local
        Set-Variable -Name NetworkSettingsParameterName -Option ReadOnly -Value "NetworkSettings" -Scope Local
        Set-Variable -Name Server2012BuildNumber -Option ReadOnly -Value 9200 -Scope Local
        Set-Variable -Name MsvmVirtualSystemMigrationServiceSettingDataClassName -Option ReadOnly -Value "Msvm_VirtualSystemMigrationServiceSettingData" -Scope Local
        Set-Variable -Name AuthenticationTypeCredSSP -Option ReadOnly -Value 0 -Scope Local
        Set-Variable -Name ModifyServiceSettingsMethodName -Option ReadOnly -Value "ModifyServiceSettings" -Scope Local
        Set-Variable -Name ServiceSettingDataParameterName -Option ReadOnly -Value "ServiceSettingData" -Scope Local
        Set-Variable -Name AuthenticationTypePropertyName -Option ReadOnly -Value "AuthenticationType" -Scope Local
    }
    process {
        $err = $null

        Import-Module $HyperVModuleName -ErrorAction SilentlyContinue -ErrorVariable +err
        if (!!$err) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: The required PowerShell module (Hyper-V) was not found. Error: $err" -ErrorAction SilentlyContinue

            Write-Error @($err)[0]

            return $err
        }

        $buildNumber = [System.Environment]::OSVersion.Version.Build

        if ($buildNumber -eq $Server2012BuildNumber) {
            Set-VMHost -UseAnyNetworkForMigration $true -VirtualMachineMigrationAuthenticationType CredSSP -ErrorAction SilentlyContinue -ErrorVariable +err

            if (!!$err) {
                Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                    -Message "[$ScriptName]: There was an error setting the host to use any migration network. Error: $err" -ErrorAction SilentlyContinue

                Write-Error @($err)[0]

                return $err
            }
        }
        else {
            Import-Module CimCmdlets -ErrorAction SilentlyContinue -ErrorVariable +err
            if (!!$err) {
                Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                    -Message "[$ScriptName]: The required PowerShell module (CimCmdlets) was not found. Error: $err" -ErrorAction SilentlyContinue

                Write-Error @($err)[0]

                return $err
            }

            $migrationService = Get-CimInstance -Namespace $VirtualizationNamespace -Class $MsvmVirtualSystemMigrationServiceClassName -ErrorAction SilentlyContinue -ErrorVariable +err

            if (!!$err) {
                Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                    -Message "[$ScriptName]: There was an error getting the $MsvmVirtualSystemMigrationServiceClassName class. Error: $err" -ErrorAction SilentlyContinue

                Write-Error @($err)[0]

                return $err
            }

            if (!!$migrationService) {
                $class = Get-CimClass -ClassName $MsvmVirtualSystemMigrationNetworkSettingDataClassName -Namespace $VirtualizationNamespace -ErrorAction SilentlyContinue -ErrorVariable +err
                if (!!$err) {
                    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                        -Message "[$ScriptName]: There was an error creating the $MsvmVirtualSystemMigrationNetworkSettingDataClassName class. Error: $err" -ErrorAction SilentlyContinue

                    Write-Error @($err)[0]

                    return $err
                }

                $anyV4Network = New-CimInstance -CimClass $class -ClientOnly -Property @{
                    $MetricPropertyName       = [UInt32]0;
                    $PrefixLengthPropertyName = [Byte]0;
                    $SubnetNumberPropertyName = $AnySubnetIPv4;
                    $TagsPropertyName         = @($UserManagedAllNetworks);
                }

                $anyV6Network = New-CimInstance -CimClass $class -ClientOnly -Property @{
                    $MetricPropertyName       = [UInt32]0;
                    $PrefixLengthPropertyName = [Byte]0;
                    $SubnetNumberPropertyName = $AnySubnetIPv6;
                    $TagsPropertyName         = @($UserManagedAllNetworks);
                }

                try {
                    $serializer = [Microsoft.Management.Infrastructure.Serialization.CimSerializer]::Create()
                }
                catch {
                    $errMsg = $_.Exception.Message

                    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                        -Message "[$ScriptName]: There was an error creating the serializer. Error: $errMsg" -ErrorAction SilentlyContinue

                    Write-Error $errMsg

                    return $errMsg
                }

                $params = @()

                try {
                    $temp = $serializer.Serialize($anyV4Network, [Microsoft.Management.Infrastructure.Serialization.InstanceSerializationOptions]::None)
                    $params += [System.Text.Encoding]::Unicode.GetString($temp)

                    $temp = $serializer.Serialize($anyV6Network, [Microsoft.Management.Infrastructure.Serialization.InstanceSerializationOptions]::None)
                    $params += [System.Text.Encoding]::Unicode.GetString($temp)
                }
                catch {
                    $errMsg = $_.Exception.Message

                    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                        -Message "[$ScriptName]: There was an error serializing the $MsvmVirtualSystemMigrationNetworkSettingDataClassName instances. Error: $errMsg" -ErrorAction SilentlyContinue

                    Write-Error $errMsg

                    return $errMsg
                }

                $job = ($migrationService | `
                        Invoke-CimMethod -MethodName $AddNetworkSettingsMethodName -Arguments @{ $NetworkSettingsParameterName = $params } -ErrorAction SilentlyContinue -ErrorVariable +err)
                if (!!$err) {
                    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                        -Message "[$ScriptName]: There was an error setting the UseAnyNetworksForMigration settings. Error: $err" -ErrorAction SilentlyContinue

                    Write-Error @($err)[0]

                    return $err
                }

                if (!!$job -and $job.ReturnValue -ne 0) {
                    # Not really sure what to do here since I don't have a localized error message available when this is a script block...
                    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                        -Message "[$ScriptName]: There was a job error setting the UseAnyNetworksForMigration settings. Result: $job" -ErrorAction SilentlyContinue

                    return $job.ReturnValue
                }

                $serviceSettingsClass = Get-CimClass -ClassName $MsvmVirtualSystemMigrationServiceSettingDataClassName -Namespace $VirtualizationNamespace -ErrorAction SilentlyContinue -ErrorVariable +err
                $serviceSettings = New-CimInstance -CimClass $serviceSettingsClass -ClientOnly -Property @{ $AuthenticationTypePropertyName = $AuthenticationTypeCredSSP; }
                $param = $null

                try {
                    $temp = $serializer.Serialize($serviceSettings, [Microsoft.Management.Infrastructure.Serialization.InstanceSerializationOptions]::None)
                    $param = [System.Text.Encoding]::Unicode.GetString($temp)
                }
                catch {
                    $errMsg = $_.Exception.Message

                    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                        -Message "[$ScriptName]: There was an error serializing the $MsvmVirtualSystemMigrationServiceSettingDataClassName instance. Error: $errMsg" -ErrorAction SilentlyContinue

                    Write-Error $errMsg

                    return $errMsg
                }

                $job = ($migrationService | `
                        Invoke-CimMethod -MethodName $ModifyServiceSettingsMethodName -Arguments @{ $ServiceSettingDataParameterName = $param } -ErrorAction SilentlyContinue -ErrorVariable +err)
                if (!!$err) {
                    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                        -Message "[$ScriptName]: There was an error setting the Authentication type to CredSSP. Error: $err" -ErrorAction SilentlyContinue

                    Write-Error @($err)[0]

                    return $err
                }

                if (!!$job -and $job.ReturnValue -ne 0) {
                    # Not really sure what to do here since I don't have a localized error message available when this is a script block...
                    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                        -Message "[$ScriptName]: There was a job error setting the Authentication type to CredSSP. Result: $job" -ErrorAction SilentlyContinue

                    return $job.ReturnValue
                }
            }
        }

        Enable-VMMigration -ErrorAction SilentlyContinue -ErrorVariable +err
        if (!!$err) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: There was an error enabling migration. Error: $err" -ErrorAction SilentlyContinue

            Write-Error @($err)[0]

            return $err
        }
    }
    end {
        Remove-Variable -Name LogName -Scope Local -Force
        Remove-Variable -Name LogSource -Scope Local -Force
        Remove-Variable -Name ScriptName -Scope Local -Force
        Remove-Variable -Name AnySubnetIPv4 -Scope Local -Force
        Remove-Variable -Name AnySubnetIPv6 -Scope Local -Force
        Remove-Variable -Name UserManagedAllNetworks -Scope Local -Force
        Remove-Variable -Name UserManaged -Scope Local -Force
        Remove-Variable -Name MsvmVirtualSystemMigrationNetworkSettingDataClassName -Scope Local -Force
        Remove-Variable -Name MsvmVirtualSystemMigrationServiceClassName -Scope Local -Force
        Remove-Variable -Name AddNetworkSettingsMethodName -Scope Local -Force
        Remove-Variable -Name VirtualizationNamespace -Scope Local -Force
        Remove-Variable -Name HyperVModuleName -Scope Local -Force
        Remove-Variable -Name PrefixLengthPropertyName -Scope Local -Force
        Remove-Variable -Name SubnetNumberPropertyName -Scope Local -Force
        Remove-Variable -Name TagsPropertyName -Scope Local -Force
        Remove-Variable -Name MetricPropertyName -Scope Local -Force
        Remove-Variable -Name NetworkSettingsParameterName -Scope Local -Force
        Remove-Variable -Name Server2012BuildNumber -Scope Local -Force
        Remove-Variable -Name MsvmVirtualSystemMigrationServiceSettingDataClassName -Scope Local -Force
        Remove-Variable -Name AuthenticationTypeCredSSP -Scope Local -Force
        Remove-Variable -Name ModifyServiceSettingsMethodName -Scope Local -Force
        Remove-Variable -Name ServiceSettingDataParameterName -Scope Local -Force
        Remove-Variable -Name AuthenticationTypePropertyName -Scope Local -Force
    }
}

<#

.SYNOPSIS
Build a planned VM.

.DESCRIPTION
Build a planned VM on the passed in via the parameters destination server.

#>

function buildPlannedVm($vm, $parameters) {
    $global:Error.Clear()
    $err = $null
    $arguments = @{}

    if ($parameters.$IncludeStorageParameterName) {
        $arguments += @{ $IncludeStorageArgumentName = $null; $DestinationStoragePathArgumentName = $parameters.$DestinationPathParameterName }
    }

    $server = $parameters.$DestinationHostServerParameterName

    $arguments += @{ $DestinationHostArgumentName = $server }

    $vmName = $vm.Name

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Info `
        -Message "[$ScriptName]: Attempting to build a planned VM for $vmName on host server $server." -ErrorAction SilentlyContinue

    $report = $vm | Compare-VM @arguments -ErrorAction SilentlyContinue -ErrorVariable +err
    if (!!$err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: There was an error building a planned VM for $vmName on host server $server.  Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return $null
    }

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Info `
        -Message "[$ScriptName]: Successfully built the planned VM for $vmName on host server $server." -ErrorAction SilentlyContinue

    return $report
}

<#

.SYNOPSIS
Remove the planned VM from the passed in server.

.DESCRIPTION
Remove the planned VM on the destination server for the passed in VM.  These values are in the passd in the compatibility report.
This should only be done when the planned VM is not compatible with the destination server, or if the live migration fails.

#>

function removePlannedVmFromServer($report, $destinationServer) {
    $err = $null
    $vmId = $report.VM.VMId
    $vmName = $report.VM.Name

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Info `
        -Message "[$ScriptName]: Attempting to remove the planned VM for $vmName from $destinationServer." -ErrorAction SilentlyContinue

    $vm = Get-RBACVM -Id $vmId -ComputerName $destinationServer
    if ($vm) {
        $vm | Remove-VM -Force -ErrorAction SilentlyContinue -ErrorVariable +err
        if (!!$err) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: Could not remove the planned VM for $vmName from $destinationServer.  Error: $err" -ErrorAction SilentlyContinue

            Write-Error @($err)[0]

            return $err
        }

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Info `
            -Message "[$ScriptName]: Successfully removed the planned VM for $vmName from $destinationServer." -ErrorAction SilentlyContinue
    } else {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Info `
            -Message "[$ScriptName]: The planned VM for $vmName on $destinationServer was not found." -ErrorAction SilentlyContinue
    }

    return $null
}

<#

.SYNOPSIS
Disconnect the network adapters in the incompatibilites of the report.

.DESCRIPTION
Disconnect the VM network adatpers in the report so that they will not interfere with the network adapters that are connected to the mapped
virtual switches on the destination server.  This will hopefully resolve most incompatibilies in the report.

#>
# TODO: Enable when a way to use the resolved report to remove incompatibilities is implemented
# function disconnectNetAdaptersInReport($report) {
#     $err = $null

#     for ($i = 0; $i -lt $report.Incompatibilities.Length; $i++) {
#         $message = $report.$IncompatibilitiesPropertyName[$i];

#         if ($message.$MessageIdPropertyName -eq [ValidationErrorId]::EthernetSwitchNotFound) {
#             Disconnect-VMNetworkAdapter -VMNetworkAdapter $message.Source -ErrorAction SilentlyContinue -ErrorVariable +err
#             if (!!$err) {
#                 $vmName = $report.VM.Name
    
#                 Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
#                     -Message "[$ScriptName]: Could not disconnect network adapters from the planned VM report for $vmName.  Error: $err" -ErrorAction SilentlyContinue
        
#                 Write-Error @($err)[0]
    
#                 return $err
#             }
#         }
#     }

#     return $null
# }

<#

.SYNOPSIS
Connect the VM network adapters in the planned VM to the proper virtual switches on the destinatiton servers using the adapter to switch mappings in the parameters.

.DESCRIPTION
Use the Hyper-V cmdlets to connect the mapped virtual switches to the network adapters in the planned VM on the remote server. This function relies on the fact
that the VMId of the planned VM on the remote server is the same as the VM on this, the current host, server.

#>

function connectNetAdaptersInPlannedVmToMappedSwitches($parameters) {
    $err = $null
    $vmName = $parameters.$VmNameParameterName
    $vmId = $parameters.$VmIdParameterName
    $server = $parameters.$DestinationHostServerParameterName

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Info `
        -Message "[$ScriptName]: Connecting the mapped virtual switches to the network adapters for VM $vmName ($vmId) from server $server." -ErrorAction SilentlyContinue

    $adapterIdToDestSwitchId = @{}
    $parameters.$VirtualAdapterVirtualSwitchMapsParameterName | ForEach-Object {
        $adapterIdToDestSwitchId.add($_.adapterId, $_.destSwitchId)
    }

    $vm = Get-RBACVM -Id $vmId -ComputerName $server -ErrorAction SilentlyContinue -ErrorVariable +err
    if (!!$err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Could not get VM $vmName ($vmId) from server $server.  Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return $err
    }

    $adapters = $vm | Get-VMNetworkAdapter -ErrorAction SilentlyContinue -ErrorVariable +err
    if (!!$err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Could not get the network adapters for VM $vmName ($vmId) from server $server.  Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return $err
    }

    for ($i = 0; $i -lt @($adapters).Length; $i++) {
        $adapter = @($adapters)[$i]
        $adapterId = $adapter.id

        if ($adapterIdToDestSwitchId.containsKey($adapterId)) {
            $switchId = $adapterIdToDestSwitchId[$adapterId]
            $adapterName = $adapter.Name

            if ($switchId -eq $DisconnectSwitchSwitchId) {
                Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Info `
                    -Message "[$ScriptName]: Disconnecting network adapter $adapterName in VM $vmName ($vmId) from a virtual switch on server $server." -ErrorAction SilentlyContinue
        
                Disconnect-VMNetworkAdapter -VMNetworkAdapter $adapter -ErrorAction SilentlyContinue -ErrorVariable +err
                if (!!$err) {
                    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                        -Message "[$ScriptName]: Could not disconnect network adapter $adapterName in VM $vmName ($vmId) from server $server.  Error: $err" -ErrorAction SilentlyContinue
            
                    Write-Error @($err)[0]
            
                    return $err
                }

                Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Info `
                    -Message "[$ScriptName]: Successfully disconnected network adapter $adapterName in VM $vmName ($vmId) from a virtual switch on server $server." -ErrorAction SilentlyContinue
        
                continue
            }

            $switch = Get-VMSwitch -Id $switchId -ComputerName $server -ErrorAction SilentlyContinue -ErrorVariable +err
            if (!!$err) {
                Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                    -Message "[$ScriptName]: Could not get the virtual switch with Id $switchId from server $server.  Error: $err" -ErrorAction SilentlyContinue
        
                Write-Error @($err)[0]
        
                return $err
            }

            if (-not($switch)) {
                Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                    -Message "[$ScriptName]: The virtual switch with Id $switchId does not exist on server $server." -ErrorAction SilentlyContinue
        
                $err = [System.IO.FileNotFoundException] $switchId
                Write-Error @($err)[0]
        
                return $err
            }

            $adapter | Connect-VMNetworkAdapter -VMSwitch $switch -ErrorAction SilentlyContinue -ErrorVariable +err
            if (!!$err) {
                $switchName = $switch.Name

                Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                    -Message "[$ScriptName]: Could not connect network adapter $adapterName ($adapterId) to virtual switch $switchName for $vmName ($vmId) on server $server.  Error: $err" -ErrorAction SilentlyContinue
        
                Write-Error @($err)[0]
        
                return $err
            }
        }
    }

    if (!!$err) {
        return $err
    }

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Info `
        -Message "[$ScriptName]: Successfully connected the mapped virtual switches to the network adapters for VM $vmName ($vmId) from server $server." -ErrorAction SilentlyContinue

    return $null
}

<#

.SYNOPSIS
Move the VM to a new host server.  This requires that CredSSP be enabled between the gateway and this server.

.DESCRIPTION
Move the VM to a new host server.

#>

function moveVmToStandAloneServer($vm, $parameters) {
    $err = $null
    $vmName = $vm.Name
    $server = $parameters.$DestinationHostServerParameterName

    Invoke-Command -ScriptBlock ${function:enableMigration} -ComputerName $parameters.$DestinationHostServerParameterName `
        -ErrorAction SilentlyContinue -ErrorVariable +err
    if (!!$err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: There was an error enabling virtual machine migration on host server $server.  Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return $err
    }

    $report = buildPlannedVm $vm $parameters
    if (-not($report) -or $global:Error.Count -gt 0) {
        return $globale:Error
    }

    try {
        # TODO: Enable when a way to use the resolved report to remove incompatibilities is implemented
        # $err = disconnectNetAdaptersInReport $report
        # if (!!$err) {
        #     return $err
        # }

        # TODO: This compare-vm must be run on the destination server using the "resolved" compatibility report from this server.  And that is not currently possible.
        # $postFixesReport = Compare-VM -CompatibilityReport $report -ComputerName $server -ErrorAction SilentlyContinue -ErrorVariable +err
        # if (!!$err) {
        #     Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        #         -Message "[$ScriptName]: There was an error creating a planned VM for $vmName on host server $server using the previous compatibility report.  Error: $err" -ErrorAction SilentlyContinue
    
        #     Write-Error @($err)[0]
    
        #     return $global:Error
        # }
    
        if (@($report.Incompatibilities).Length -gt 0) {
            $hostServer = $parameters.$CurrentHostServerParameterName
            $miniReport = $report.Incompatibilities | Microsoft.PowerShell.Utility\Select-Object Message, MessageId

            $numberOfIncompatibilities = @($miniReport).Length
            $message ="'`r`n $numberOfIncompatibilities incompatibilities were found.`r`n"
            
            @($minireport) | ForEach-Object {
                $message += $_.MessageId.ToString() + " - " + $_.Message + "`r`n"
            }

            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: The VM $vmName is not compatible with the new host server $hostServer.  Incompatibilities found: $message" -ErrorAction SilentlyContinue

            $message = $strings.MoveVirtualMachineVMIncompatible -f $vmName, $hostServer
            $err = [System.InvalidOperationException] $message
            
            Write-Error @($err)[0]

            return $err
        }

        $err = connectNetAdaptersInPlannedVmToMappedSwitches $parameters
        if (!!$err) {
            return $err
        }

        # Move the VM using the compatibility report as the sole parameter.
        Move-VM -CompatibilityReport $report -ErrorAction SilentlyContinue -ErrorVariable +err
        if (!!$err) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: There was an error moving virtual machine $vmName to server $server.  Error: $err" -ErrorAction SilentlyContinue

            Write-Error @($err)[0]

            return $err
        }

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Info `
            -Message "[$ScriptName]: Successfully moved virtual machine $vmName to server $server." -ErrorAction SilentlyContinue
    
        return $null
    }
    finally {
        # Any error above means we should attempt to remove the planned VM from the destination server.
        if (!!$err) {
            removePlannedVmFromServer $report $parameters.$DestinationHostServerParameterName
        }
    }
}

<#

.SYNOPSIS
Get the VM with the passed in vmId...

.DESCRIPTION
Get the VM with the passed in VM id.  Will return null on error, if Get-RBACVM returns null...

#>

function getVirtualMachine($vmId) {
    $global:Error.Clear()
    $err = $null

    $vm = Get-RBACVM -Id $vmId -ErrorAction SilentlyContinue -ErrorVariable +err
    if (!!$err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: There was an error getting the virtual machine with Id = $vmId.  Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return $null
    }

    if (-not($vm)) {
        $vmName = $parameters.$VmNameParameterName
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: The virtual machine $vmName ($vmId) was not found." -ErrorAction SilentlyContinue

        $err = [System.IO.FileNotFoundException] $vmName
        Write-Error @($err)[0]

        return $null
    }

    return $vm
}

<#

.SYNOPSIS
Main

.DESCRIPTION
Implementation of moving a virtual machine from one node of a cluster to another node of the cluster using cluster migration, or moving
the virtual machine to a new host cluster using Move-VM and GetBestHostNode, or move to a stand alone server.

.PARAMETER parameters

#>

function main([Object] $parameters) {
    $err = $null

    $err = enableMigration
    if (!!$err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: There was an error enabling virutal machine migration on this host.  Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return $err
    }

    $moveType = determineMoveType $parameters
    if ($moveType -eq [MoveType]::WithinCluster) {
        if (validateParameters $moveType $parameters) {
            return moveVmToNewClusterHostNode $parameters
        }

        return $global:Error
    }

    if ($moveType -eq [MoveType]::NewCluster) {
        return moveVmToNewCluster $parameters
    }

    if ($moveType -eq [MoveType]::StandAloneServer) {
        return moveVmToNewServer $parameters
    }
}

###############################################################################
# Script execution starts here
###############################################################################

if (-not ($env:pester)) {
    $err = $null

    setupScriptEnv

    Start-Transcript -Append -IncludeInvocationHeader -Debug -Force -Confirm:$False | Out-Null

    try {
        Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

        if ($parameters.$IsClusteredPropertyName) {
            $clusterModule = Get-Module -Name $FailoverClustersModuleName -ErrorAction SilentlyContinue

            if (-not($clusterModule)) {
                Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                    -Message "[$ScriptName]: The required PowerShell module (FailoverClusters) was not found." -ErrorAction SilentlyContinue

                Write-Error $strings.FailoverClustersModuleRequired -ErrorAction Stop

                return
            }
        }

        $hyperVModule = Get-Module -Name $HyperVModuleName -ErrorAction SilentlyContinue

        if (-not($hyperVModule)) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: The required PowerShell module (Hyper-V) was not found." -ErrorAction SilentlyContinue

            Write-Error $strings.HyperVModuleRequired -ErrorAction Stop

            return
        }

        $err = main $parameters
        if ($global:Error.Count -gt 0) {
            # Need a terminating error to make the work item result be an error in the UI.  Write-Error is not terminating...
            Write-Error @($global:Error)[0] -ErrorAction Stop
        }

        return $err
    }
    finally {
        Stop-Transcript | Out-Null

        cleanupScriptEnv
    }
}

}
## [END] Move-WACVMVirtualMachine ##
function Move-WACVMVirtualMachineStorage {
<#

.SYNOPSIS
Moves (live migrates) the passed in virtual machine storage components to the passed in host server.

.DESCRIPTION
Moves (live migrates) the passed in virtual machine storage components to the passed in host server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER vmId
The Id of the requested virtual machine.

.PARAMETER isBritannicaEnabled
The parameter that determines where to get the VM object from.

.PARAMETER destinationStoragePath
The destination path for all storage (valid when all storage is going to same location)

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $vmId,
    [Parameter(Mandatory = $false)]
    [bool]
    $isBritannicaEnabled,
    [Parameter(Mandatory = $false)]
    [String]
    $destinationStoragePath
)

Set-StrictMode -Version 5.0

Import-Module Hyper-V -ErrorAction SilentlyContinue
Import-Module FailoverClusters -ErrorAction SilentlyContinue
Import-Module Microsoft.PowerShell.Management -ErrorAction SilentlyContinue
Import-Module CimCmdlets -ErrorAction SilentlyContinue
Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.  Create read only (constant) variables
that add context to the said constants.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Move-VirtualMachineStorage.ps1" -Scope Script
    Set-Variable -Name HyperVModuleName -Option ReadOnly -Value "Hyper-V" -Scope Script
}

<#

.SYNOPSIS
Cleanup the script environment.

.DESCRIPTION
Cleanup the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name HyperVModuleName -Scope Script -Force
}

<#
.SYNOPSIS
Get the VM using the Britannica cache.

.DESCRIPTION
Use the Britannica virtual machine interface to get the VM info.  This is preferred
since no double hop is needed.
#>

function getVmFromBritannica([string]$vmId) {
    $vm = Get-CimInstance -Namespace "root\SDDC\Management" -ClassName SDDC_VirtualMachine | Where-Object { $_.Id -ieq $vmId }

    if (-not ($vm)) {
        return $null
    }

    return $vm
}

<#

.SYNOPSIS
Main

.DESCRIPTION
Implementation of moving virtual machine storage components
#>
function main(
    [string]$vmId,
    [bool]$isBritannicaEnabled,
    [string]$destinationStoragePath
) {
    $vm = $null
    if ($isBritannicaEnabled) {
        Import-Module CimCmdlets -ErrorAction SilentlyContinue -ErrorVariable +err

        if (!!$err) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: The required PowerShell module (CimCmdlets) was not found. Error: $err" -ErrorAction SilentlyContinue

            Write-Error @($err)[0]

            return
        }

        $vm = getVmFromBritannica $vmId -ErrorAction SilentlyContinue -ErrorVariable +err
    }
    else {
        $vm = Get-RBACVM -Id $vmId -ErrorAction SilentlyContinue -ErrorVariable +err
    }

    if (-not $vm) {
        if ($err) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: There was an error getting the virtual machine with Id = $vmId.  Error: $ " -ErrorAction SilentlyContinue

            Write-Error @($err)[0]
        }
    }

    $vm | Move-VMStorage -DestinationStoragePath $destinationStoragePath -ErrorAction SilentlyContinue -ErrorVariable +err

    if (!!$err) {
        $vmName = $vm.Name

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: There was an error moving virtual machine $vmName to destination $destinationStoragePath .  Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return $err
    }

    return $null
}

###############################################################################
# Script execution starts here
###############################################################################

if (-not ($env:pester)) {
    setupScriptEnv

    try {
        Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

        $hyperVModule = Get-Module -Name $HyperVModuleName -ErrorAction SilentlyContinue

        if (-not($hyperVModule)) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: The required PowerShell module (Hyper-V) was not found." -ErrorAction SilentlyContinue

        Write-Error $strings.HyperVModuleRequired

        return $null
        }

        return main $vmId $isBritannicaEnabled $destinationStoragePath
    }
    finally {
        cleanupScriptEnv
    }
}

}
## [END] Move-WACVMVirtualMachineStorage ##
function New-WACVMAffinityRule {
<#

.SYNOPSIS
Removes a specific affinity rule

.DESCRIPTION
Removes a specific affinity rule

.ROLE
Hyper-V-Administrators

#>

param (
  [Parameter(Mandatory = $true)]
  [String]
  $name,
  [Parameter(Mandatory = $true)]
  [Int]
  $type,
  [Parameter(Mandatory = $true)]
  [String[]]
  $vms,
  [Parameter(Mandatory = $true)]
  [Boolean]
  $addCSVs
)
Set-StrictMode -Version 5.0

New-ClusterAffinityRule -Name $name -Ruletype $type
Add-ClusterGroupToAffinityRule -Groups $vms -Name $name
if ($addCSVs) {
  $csvNames = Get-ClusterSharedVolume | ForEach-Object { $_.name }
  if ($csvNames -ne $null) {
    Add-ClusterSharedVolumeToAffinityRule -ClusterSharedVolumes $csvNames -Name $name
  }
}

}
## [END] New-WACVMAffinityRule ##
function New-WACVMNetworkInterfaces {
<#

.SYNOPSIS
Set up new network interfaces

.DESCRIPTION
Create new network interfaces.

.ROLE
Hyper-V-Administrators

.PARAMETER securityTagResourceRefs
    The security tags associated with the new NIC

.PARAMETER ncUri
    The network controller URI used for SDN connections

.PARAMETER sdnNetworkType
    SDN Network connection type. 0 is None, 1 is vlan, 2 is vnet, 3 is lnet

.PARAMETER ipAddress
    The IP Address to assign to this VM when connected to a virtual network.

.PARAMETER subnetResourceRef
    The resourceRef used for assigning this vm to a subnet

#>

param (
  [Parameter(Mandatory = $true)]
  [string]
  $vmId,
  [Parameter(Mandatory = $true)]
  [string]
  $vmName,
  [Parameter(Mandatory = $true)]
  [string]
  $adapterId,
  [Parameter(Mandatory = $true)]
  [string]
  $ncUri,
  [Parameter(Mandatory = $true)]
  [int]
  $sdnNetworkType,
  [Parameter(Mandatory = $false)]
  [string]
  $ipAddress = $null,
  [Parameter(Mandatory = $false)]
  [string]
  $subnetResourceRef = $null,
  [Parameter(Mandatory = $false)]
  [string]
  $aclResourceRef = $null,
  [Parameter(Mandatory = $false)]
  [int[]]
  $portOptions = $null,
  [Parameter(Mandatory = $false)]
  [boolean]
  $useDefaultNetworkPolicies = $false,
  [Parameter(Mandatory = $false)]
  [string[]]
  $securityTagResourceRefs
)

Import-Module NetworkController -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Types of SDN network connections

.DESCRIPTION
This enum is used to determine what type of SDN connection we are creating.

#>
enum SdnNetworkType {
  None = 0
  Vlan = 1
  Vnet = 2
  Lnet = 3
}

<#

.SYNOPSIS
Types of default ports to open

.DESCRIPTION
This enum is used to determine what type of ports we want to include in a custom ACL

#>
enum VirtualMachinePorts {
  HTTP = 0
  HTTPS = 1
  SSH = 2
  RDP = 3
  WinRM = 4
  SMB = 5
}

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.  Create read only (constant) variables
that add context to the said constants.

#>
function setupScriptEnv() {
  Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
  Set-Variable -Name LogSource -Option ReadOnly -Value "SMEGateway" -Scope Script
  Set-Variable -Name ScriptName -Option ReadOnly -Value "New-NetworkInterfaces.ps1" -Scope Script
  Set-Variable -Name PortProfileFeatureId -Option ReadOnly -Value "9940cd46-8b06-43bb-b9d5-93d50381fd56" -Scope Script
  Set-Variable -Name PortProfileNetCfgInstanceId -Option ReadOnly -Value "{56785678-a0e5-4a26-bc9b-c0cba27311a3}" -Scope Script
  Set-Variable -Name NetworkControllerVendorId -Option ReadOnly -Value "{1FA41B39-B444-4E43-B35A-E1F7985FD548}" -Scope Script
  Set-Variable -Name NetworkControllerVendorName -Option ReadOnly -Value "NetworkController" -Scope Script
  Set-Variable -Name NetworkControllerCdnLabelName -Option ReadOnly -Value "TestCdn" -Scope Script
  Set-Variable -Name NetworkControllerCdnLabelId -Option ReadOnly -Value 1111 -Scope Script
  Set-Variable -Name NetworkControllerProfileName -Option ReadOnly -Value "Testprofile" -Scope Script
  Set-Variable -Name PortProfileSDNNetwork -Option ReadOnly -Value 1 -Scope Script
  Set-Variable -Name PortProfileVlan -Option ReadOnly -Value 2 -Scope Script
  Set-Variable -Name PortProfileUntaggedLnet -Option ReadOnly -Value 6 -Scope Script
  Set-Variable -Name DefaultAclRuleType -Option ReadOnly -Value "Inbound" -Scope Script
  Set-Variable -Name DefaultAclRuleOutboundType -Option ReadOnly -Value "Outbound" -Scope Script
  Set-Variable -Name DefaultAclRuleProtocolTCP -Option ReadOnly -Value "TCP" -Scope Script
  Set-Variable -Name DefaultAclRuleProtocolAll -Option ReadOnly -Value "All" -Scope Script
  Set-Variable -Name DefaultAclRuleWildcard -Option ReadOnly -Value "*" -Scope Script
  Set-Variable -Name DefaultAclRuleAllowAction -Option ReadOnly -Value "Allow" -Scope Script
  Set-Variable -Name DefaultAclRuleDenyAction -Option ReadOnly -Value "Deny" -Scope Script
  Set-Variable -Name DefaultAclRuleLogging -Option ReadOnly -Value "Disabled" -Scope Script
  Set-Variable -Name DefaultAclRuleHTTPName -Option ReadOnly -Value "HTTP" -Scope Script
  Set-Variable -Name DefaultAclRuleHTTPPriority -Option ReadOnly -Value "340" -Scope Script
  Set-Variable -Name DefaultAclRuleHTTPDestinationPort -Option ReadOnly -Value "80" -Scope Script
  Set-Variable -Name DefaultAclRuleHTTPSName -Option ReadOnly -Value "HTTPS" -Scope Script
  Set-Variable -Name DefaultAclRuleHTTPSPriority -Option ReadOnly -Value "320" -Scope Script
  Set-Variable -Name DefaultAclRuleHTTPSDestinationPort -Option ReadOnly -Value "443" -Scope Script
  Set-Variable -Name DefaultAclRuleSSHName -Option ReadOnly -Value "SSH" -Scope Script
  Set-Variable -Name DefaultAclRuleSSHPriority -Option ReadOnly -Value "300" -Scope Script
  Set-Variable -Name DefaultAclRuleSSHDestinationPort -Option ReadOnly -Value "22" -Scope Script
  Set-Variable -Name DefaultAclRuleRDPName -Option ReadOnly -Value "RDP" -Scope Script
  Set-Variable -Name DefaultAclRuleRDPPriority -Option ReadOnly -Value "360" -Scope Script
  Set-Variable -Name DefaultAclRuleRDPDestinationPort -Option ReadOnly -Value "3389" -Scope Script
  Set-Variable -Name DefaultAclRuleWinRMName -Option ReadOnly -Value "WinRM" -Scope Script
  Set-Variable -Name DefaultAclRuleWinRMPriority -Option ReadOnly -Value "280" -Scope Script
  Set-Variable -Name DefaultAclRuleWinRMDestinationPort -Option ReadOnly -Value "5985-5986" -Scope Script
  Set-Variable -Name DefaultAclRuleSMBName -Option ReadOnly -Value "SMB" -Scope Script
  Set-Variable -Name DefaultAclRuleSMBPriority -Option ReadOnly -Value "260" -Scope Script
  Set-Variable -Name DefaultAclRuleSMBDestinationPort -Option ReadOnly -Value "139,445" -Scope Script
  Set-Variable -Name DefaultAclRuleVNServiceTag -Option ReadOnly -Value "VIRTUALNETWORK" -Scope Script
  Set-Variable -Name DefaultAclRuleVNPriority -Option ReadOnly -Value "380" -Scope Script
  Set-Variable -Name DefaultAclRuleVNInResourceId -Option ReadOnly -Value "AllowInboundVirtualNetwork" -Scope Script
  Set-Variable -Name DefaultAclRuleVNOutResourceId -Option ReadOnly -Value "AllowOutboundVirtualNetwork" -Scope Script
  Set-Variable -Name DefaultAclRuleDenyPriority -Option ReadOnly -Value "65000" -Scope Script
  Set-Variable -Name DefaultAclRuleDenyResourceId -Option ReadOnly -Value "BlockOtherTraffic" -Scope Script
}

<#

.SYNOPSIS
Cleanup the script environment.

.DESCRIPTION
Cleanup the script variables that were set in setupScriptEnv.

#>

function cleanupScriptEnv() {
  Remove-Variable -Name LogName -Scope Script -Force
  Remove-Variable -Name LogSource -Scope Script -Force
  Remove-Variable -Name ScriptName -Scope Script -Force
  Remove-Variable -Name PortProfileFeatureId -Scope Script -Force
  Remove-Variable -Name PortProfileNetCfgInstanceId -Scope Script -Force
  Remove-Variable -Name NetworkControllerVendorId -Scope Script -Force
  Remove-Variable -Name NetworkControllerVendorName -Scope Script -Force
  Remove-Variable -Name NetworkControllerCdnLabelName -Scope Script -Force
  Remove-Variable -Name NetworkControllerCdnLabelId -Scope Script -Force
  Remove-Variable -Name NetworkControllerProfileName -Scope Script -Force
  Remove-Variable -Name PortProfileSDNNetwork -Scope Script -Force
  Remove-Variable -Name PortProfileVlan -Scope Script -Force
  Remove-Variable -Name PortProfileUntaggedLnet -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleType -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleOutboundType -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleProtocolTCP -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleProtocolAll -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleWildcard -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleAllowAction -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleDenyAction -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleLogging -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleHTTPName -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleHTTPPriority -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleHTTPDestinationPort -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleHTTPSName -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleHTTPSPriority -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleHTTPSDestinationPort -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleSSHName -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleSSHPriority -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleSSHDestinationPort -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleRDPName -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleRDPPriority -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleRDPDestinationPort -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleWinRMName -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleWinRMPriority -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleWinRMDestinationPort -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleSMBName -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleSMBPriority -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleSMBDestinationPort -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleVNServiceTag -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleVNPriority -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleVNInResourceId -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleVNOutResourceId -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleDenyPriority -Scope Script -Force
  Remove-Variable -Name DefaultAclRuleDenyResourceId -Scope Script -Force
}

<#

.SYNOPSIS
Create a new resource ID with a numerical suffix

.DESCRIPTION
Create a new resource ID with a numerical suffix

#>

function generateUnusedResourceId($baseValue, $existingResources) {
  $count = 0
  $newResourceId = "$($baseValue)_$($count)"
  if ($existingResources -ne $null ) {
    while ($null -ne ($existingResources | Where-Object { $_.ResourceId -ieq $newResourceId })) {
      $newResourceId = "$($baseValue)_$($count)"
      $count += 1
    }
  }

  Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
    -Message "[$ScriptName]: Creating a new resource with the resourceID $newResourceId" -ErrorAction SilentlyContinue

  return $newResourceId
}

function generatePortAclRule([VirtualMachinePorts]$portOption, [string]$aclName, [string]$ncUri) {
  # Properties independent of the port choice
  $ruleproperties = New-Object Microsoft.Windows.NetworkController.AclRuleProperties
  $ruleproperties.Type = $DefaultAclRuleType
  $ruleproperties.Protocol = $DefaultAclRuleProtocolTCP
  $ruleproperties.SourceAddressPrefix = $DefaultAclRuleWildcard
  $ruleproperties.SourcePortRange = $DefaultAclRuleWildcard
  $ruleproperties.DestinationAddressPrefix = $DefaultAclRuleWildcard
  $ruleproperties.Action = $DefaultAclRuleAllowAction
  $ruleproperties.Logging = $DefaultAclRuleLogging

  # Dependent on port option
  $ruleName = ""
  if ($portOption -eq [VirtualMachinePorts]::HTTP) {
    $ruleName = $DefaultAclRuleHTTPName
    $ruleproperties.Priority = $DefaultAclRuleHTTPPriority
    $ruleproperties.DestinationPortRange = $DefaultAclRuleHTTPDestinationPort
  }
  elseif ($portOption -eq [VirtualMachinePorts]::HTTPS) {
    $ruleName = $DefaultAclRuleHTTPSName
    $ruleproperties.Priority = $DefaultAclRuleHTTPSPriority
    $ruleproperties.DestinationPortRange = $DefaultAclRuleHTTPSDestinationPort
  }
  elseif ($portOption -eq [VirtualMachinePorts]::SSH) {
    $ruleName = $DefaultAclRuleSSHName
    $ruleproperties.Priority = $DefaultAclRuleSSHPriority
    $ruleproperties.DestinationPortRange = $DefaultAclRuleSSHDestinationPort
  }
  elseif ($portOption -eq [VirtualMachinePorts]::RDP) {
    $ruleName = $DefaultAclRuleRDPName
    $ruleproperties.Priority = $DefaultAclRuleRDPPriority
    $ruleproperties.DestinationPortRange = $DefaultAclRuleRDPDestinationPort
    $ruleproperties.Protocol = $DefaultAclRuleProtocolAll
  }
  elseif ($portOption -eq [VirtualMachinePorts]::WinRM) {
    $ruleName = $DefaultAclRuleWinRMName
    $ruleproperties.Priority = $DefaultAclRuleWinRMPriority
    $ruleproperties.DestinationPortRange = $DefaultAclRuleWinRMDestinationPort
  }
  elseif ($portOption -eq [VirtualMachinePorts]::SMB) {
    $ruleName = $DefaultAclRuleSMBName
    $ruleproperties.Priority = $DefaultAclRuleSMBPriority
    $ruleproperties.DestinationPortRange = $DefaultAclRuleSMBDestinationPort
    $ruleproperties.Protocol = $DefaultAclRuleProtocolAll
  }

  New-NetworkControllerAccessControlListRule -ConnectionUri $ncUri -ResourceId $ruleName -AccessControlListId $aclName -Properties $ruleproperties -Force
}

function generateVnetAclRule([string]$aclName, [string]$ncUri, [bool]$isOutbound) {
  $ruleproperties = New-Object Microsoft.Windows.NetworkController.AclRuleProperties
  $ruleproperties.Protocol = $DefaultAclRuleProtocolTCP
  $ruleproperties.SourceAddressPrefix = $DefaultAclRuleVNServiceTag
  $ruleproperties.SourcePortRange = $DefaultAclRuleWildcard
  $ruleproperties.DestinationAddressPrefix = $DefaultAclRuleVNServiceTag
  $ruleproperties.DestinationPortRange = $DefaultAclRuleWildcard
  $ruleproperties.Action = $DefaultAclRuleAllowAction
  $ruleproperties.Logging = $DefaultAclRuleLogging
  $ruleproperties.Priority = $DefaultAclRuleVNPriority

  if ($isOutbound) {
    $ruleproperties.Type = $DefaultAclRuleType
    $ruleName = $DefaultAclRuleVNInResourceId
  }
  else {
    $ruleproperties.Type = $DefaultAclRuleOutboundType
    $ruleName = $DefaultAclRuleVNOutResourceId
  }

  New-NetworkControllerAccessControlListRule -ConnectionUri $ncUri -ResourceId $ruleName -AccessControlListId $aclName -Properties $ruleproperties -Force
}

<#

.SYNOPSIS
Create a new ACL based off of the chosen ports to open

.DESCRIPTION
Create a new ACL based off of the chosen ports to open

#>

function generateNewAcl(
  [string]$ncUri,
  [string]$vmName,
  [int[]]$portOptions,
  [bool] $isVnet
) {
  $existingAcls = Get-NetworkControllerAccessControlList -ConnectionUri $ncUri

  $newRef = generateUnusedResourceId -baseValue "$($vmName)_NSG" -existingResources $existingAcls

  $aclProps = New-Object Microsoft.Windows.NetworkController.AccessControlListProperties
  $acl = New-NetworkControllerAccessControlList -ConnectionUri $ncUri -ResourceId $newRef -Properties $aclProps -Force

  foreach ($port in $portOptions) {
    generatePortAclRule -portOption $port -aclName $newRef -ncUri $ncUri | Out-Null
  }

  if ($isVnet) {
    # Allow traffic within a virtual subnet, if it's applicable
    generateVnetAclRule -aclName $newRef -ncUri $ncUri -isOutbound $true | Out-Null
    generateVnetAclRule -aclName $newRef -ncUri $ncUri -isOutbound $true | Out-Null
  }

  # Block all other traffic
  $ruleproperties = New-Object Microsoft.Windows.NetworkController.AclRuleProperties
  $ruleproperties.Type = $DefaultAclRuleType
  $ruleproperties.Protocol = $DefaultAclRuleProtocolTCP
  $ruleproperties.SourceAddressPrefix = $DefaultAclRuleWildcard
  $ruleproperties.SourcePortRange = $DefaultAclRuleWildcard
  $ruleproperties.DestinationAddressPrefix = $DefaultAclRuleWildcard
  $ruleproperties.DestinationPortRange = $DefaultAclRuleWildcard
  $ruleproperties.Action = $DefaultAclRuleDenyAction
  $ruleproperties.Logging = $DefaultAclRuleLogging
  $ruleproperties.Priority = $DefaultAClRuleDenyPriority
  New-NetworkControllerAccessControlListRule -ConnectionUri $ncUri -ResourceId  $DefaultAClRuleDenyResourceId -AccessControlListId $newRef -Properties $ruleproperties -Force | Out-Null

  return $acl
}

function LnetVlanValue($lSubnet) {
  if ($null -eq $lSubnet) {
    return $null
  }
  return $lSubnet.properties.vlanId
}


<#

.SYNOPSIS
Configures SDN for the given virtual machine

.DESCRIPTION
Configures SDN for the given virtual machine

#>

function configureSdn(
  [string] $vmId,
  [string] $vmName,
  [string] $adapterId,
  [string] $ncUri,
  [SdnNetworkType] $sdnNetworkType,
  [string] $ipAddress,
  [string] $subnetResourceRef,
  [string] $aclResourceRef
) {

  $logString = @{
    vmId = $vmId
    vmName = $vmName
    adpaterId = $adapterId
    ncUri = $ncUri
    sdnNetworkType = $sdnNetworkType
    ipAddress = $ipAddress
    subnetRef = $subnetResourceRef
    aclRef = $aclResourceRef
  } | ConvertTo-Json

  Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
  -Message "Logging the parameters of [$ScriptName]: $logString" -ErrorAction SilentlyContinue

  try {
    # get all exisitng NICs to ensure that we do not duplicate resourceID
    $ncNics = Get-NetworkControllerNetworkInterface -ConnectionUri $ncUri

    # create new nic/ipconfig
    $nicProps = New-Object Microsoft.Windows.NetworkController.NetworkInterfaceProperties
    $nicProps.IsPrimary = $true
    $nicProps.PrivateMacAllocationMethod = "Dynamic"
    if ($null -ne $securityTagResourceRefs) {
      $nicProps.SecurityTags = @()
      foreach ($tag in $securityTagResourceRefs) {
        $newTag = New-Object Microsoft.Windows.NetworkController.SecurityTag -Property @{ResourceRef = $tag }
        $nicProps.SecurityTags += $newTag
      }
    }

    $ipConfig = New-Object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfiguration
    $ipConfig.ResourceId = generateUnusedResourceId "$($vmName)_Net_Adapter".Replace(' ', '_') $ncNics
    $ipConfigProps = New-Object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfigurationProperties
    $ipConfigProps.Subnet = New-Object Microsoft.Windows.NetworkController.Subnet
    $ipConfigProps.Subnet.ResourceRef = $subnetResourceRef

    $lsubnet = $null

    if ($sdnNetworkType -eq [SdnNetworkType]::Lnet) {
      $splitLsubnet = $subnetResourceRef -split '/'
      $lsubnet = Get-NetworkControllerLogicalSubnet -ConnectionUri $ncUri -ResourceId $splitLsubnet[4] -LogicalNetworkId $splitLsubnet[2]
      if ($null -eq $lsubnet.Properties.AddressPrefix) {
        $usingUnmanagedLSubnet = $true
      }
      else {
        $usingUnmanagedLSubnet = $false
      }
    }
    else {
      $usingUnmanagedLSubnet = $false
    }

    if (($null -ne $aclResourceRef) -and ($aclResourceRef -ne "")) {
      $ipConfigProps.AccessControlList = New-Object Microsoft.Windows.NetworkController.AccessControlList
      $ipConfigProps.AccessControlList.ResourceRef = $aclResourceRef
    }
    elseif ($null -ne $portOptions -and $portOptions.Length -gt 0) {
      $newAcl = generateNewAcl -ncUri $ncUri -vmName $vmName -portOptions $portOptions -isVnet ($sdnNetworkType -eq [SdnNetworkType]::Vnet)
      $ipConfigProps.AccessControlList = New-Object Microsoft.Windows.NetworkController.AccessControlList
      $ipConfigProps.AccessControlList.ResourceRef = $newAcl.ResourceRef
    }
    if (($sdnNetworkType -eq [SdnNetworkType]::Vnet) -or (($ipAddress -ne $null) -and ($ipAddress -ne ""))) {
      $ipConfigProps.PrivateIPAddress = $ipAddress
      $ipConfigProps.PrivateIPAllocationMethod = "Static"
    }
    if ($usingUnmanagedLSubnet) {
      $ipConfigProps.PrivateIPAddress = ""
      $ipConfigProps.PrivateIPAllocationMethod = "Unmanaged"
    }
    $ipConfig.Properties = $ipConfigProps
    $nicProps.IpConfigurations = @($ipConfig)

    # create, then grab the instance Id and mac address
    $ncNic = $null
    $newResourceId = generateUnusedResourceId "$($vmName)_Net_Adapter".Replace(' ', '_') $ncNics
    $adapterIdTag = $adapterId.Substring($adapterId.IndexOf('\') + 1)

    $tags = New-Object psobject -Property @{
      'vmId'      = $vmId
      'adapterId' = $adapterIdTag
    }
    $ncNic = New-NetworkControllerNetworkInterface -ConnectionUri $ncUri -ResourceId $newResourceId -Properties $nicProps -Tags $tags -Force -PassInnerException

    while ($ncNic.Properties.ProvisioningState -ne "Succeeded" -and $ncNic.Properties.ProvisioningState -ne "Failed") {
      $ncNic = Get-NetworkControllerNetworkInterface -ConnectionUri $ncUri -ResourceId $newResourceId
    }

    # set mac address on hyper-v NIC
    $nicInstanceId = $ncNic.InstanceId
    $nicMacAddress = $ncNic.Properties.PrivateMacAddress

    # choose port profile id and isolation mode to set on host, depending on default network policies and the protection choices
    $isUnmanagedLnet = $useDefaultNetworkPolicies -and $sdnNetworkType -eq [SdnNetworkType]::Lnet -and $usingUnmanagedLSubnet
    $hasNoAcl = $null -eq $ipConfigProps.AccessControlList
    $vlanAdapters = @()
    $untaggedAdapters = @()

    if ($isUnmanagedLnet) {
      if ($hasNoAcl) {
        $profileId = "{$([System.Guid]::Empty)}"
        $profileData = $PortProfileVlan #2
        $vlanId = LnetVlanValue $lSubnet
        if ($null -ne $vlanId) {
          $vlanAdapters += [PSCustomObject]@{
            adapterId = $adapterId
            vlanId    = $vlanId
          }
        }
        else {
          $untaggedAdapters += $adapterId
        }
      }
      else {
        $profileId = "{$nicInstanceId}"
        $profileData = $PortProfileUntaggedLnet #6
        $untaggedAdapters += $adapterId
      }
    }
    else {
      # ASZ build VMs on Vnet and managed Lnets are treated the same as non-ASZ build VMs
      $profileId = "{$nicInstanceId}"
      $profileData = $PortProfileSDNNetwork #1
      $untaggedAdapters += $adapterId
    }

    $profileSettings = New-Object psobject -Property @{
      'vmId'        = $vmId
      'adapterId'   = $adapterId
      'profileId'   = $profileId
      'profileData' = $profileData
      'macAddress'  = $nicMacAddress
    }

    return New-Object psobject -Property @{
      'vmId'             = $vmId
      'profileSettings'  = $profileSettings
      'vlanAdapters'     = $vlanAdapters
      'untaggedAdapters' = $untaggedAdapters
    }
  }
  catch {
    $errMsg = $_

    if ($null -ne $_.Exception.InnerException.Message) {
      $errMsg = $_.Exception.InnerException.Message
    } elseif ($null -ne $_.Exception.InnerException) {
      $errMsg = $_.Exception.InnerException
    } elseif ($null -ne $_.Exception.Message) {
      $errMsg = $_.Exception.Message
    } elseif ($null -ne $_.Exception) {
      $errMsg = $_.Exception
    }

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
      -Message "[$ScriptName]: There was an error configuring SDN for $vmName. Error: $errMsg" -ErrorAction SilentlyContinue

    Write-Error $errMsg
  }
}

###############################################################################
# Script execution starts here.
###############################################################################


if (-not($env:pester)) {
  setupScriptEnv

  Import-Module NetworkController -ErrorAction SilentlyContinue -ErrorVariable err

  # Networkcontroller module must be available for this script to run.
  if (!$err) {
    $returnValue = configureSdn `
      $vmId `
      $vmName `
      $adapterId `
      $ncUri `
      $sdnNetworkType `
      $ipAddress `
      $subnetResourceRef `
      $aclResourceRef `
      $portOptions
  }
  else {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
      -Message "[$ScriptName]: The required PowerShell module (Network Controller) was not found. Virtual Machine $vmName will not have SDN configured" -ErrorAction SilentlyContinue

    cleanupScriptEnv
    $returnValue = @{}
  }

  return $returnValue
}

}
## [END] New-WACVMNetworkInterfaces ##
function New-WACVMVirtualMachine {
<#

.SYNOPSIS
Create a new virtual machine.

.DESCRIPTION
Create a new virtual machine on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER vmName
    The name of the new virtual machine.

.PARAMETER hostName
    The optional name of the target cluster node in NetBIOS format.

.PARAMETER path
    The optional path to use for the configuration files.

.PARAMETER generation
    The generation that this virtual machine should be -- 1 or 2.

.PARAMETER memorySize
    The optional starting memory of this virutal machine in bytes.

.PARAMETER dynamicMemoryEnabled
    Optionally enable dynamic memory support in this virtual machine.

.PARAMETER maximumMemory

.PARAMETER minimumMemory

.PARAMETER processorCount

.PARAMETER enabledNestedVirtualization

.PARAMETER enableProcessorCompatibility

.PARAMETER newVHDSizeBytes

.PARAMETER existingVHDPath

.PARAMETER vswitchName

.PARAMETER existingIsoPath

.PARAMETER bootFromNetwork

.PARAMETER addToCluster

.PARAMETER useDefaultStorage
#>

param (
  [Parameter(Mandatory = $true)]
  [string]
  $vmName,
  [Parameter(Mandatory = $false)]
  [string]
  $hostName,
  [Parameter(Mandatory = $false)]
  [string]
  $path,
  [Parameter(Mandatory = $false)]
  [AllowNull()][System.Nullable[int]]
  $generation,
  [Parameter(Mandatory = $false)]
  [long]
  $memorySize,
  [Parameter(Mandatory = $false)]
  [boolean]
  $dynamicMemoryEnabled,
  [Parameter(Mandatory = $false)]
  [long]
  $maximumMemory,
  [Parameter(Mandatory = $false)]
  [long]
  $minimumMemory,
  [Parameter(Mandatory = $false)]
  [int]
  $processorCount,
  [Parameter(Mandatory = $false)]
  [boolean]
  $enabledNestedVirtualization,
  [Parameter(Mandatory = $false)]
  [boolean]
  $enableProcessorCompatibility,
  [Parameter(Mandatory = $false)]
  [long[]]
  $newVHDSizeBytes,
  [Parameter(Mandatory = $false)]
  [string[]]
  $existingVHDPath,
  [Parameter(Mandatory = $false)]
  [string]
  $vswitchName,
  [Parameter(Mandatory = $false)]
  [string]
  $existingIsoPath,
  [Parameter(Mandatory = $false)]
  [boolean]
  $bootFromNetwork,
  [Parameter(Mandatory = $false)]
  [boolean]
  $addToCluster,
  [Parameter(Mandatory = $false)]
  [boolean]
  $useDefaultStorage,
  [Parameter(Mandatory = $false)]
  [int]
  $vlanIdentifier = $null
)

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue
Import-Module FailoverClusters -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

<#

.SYNOPSIS
WindowsServerVersion

.DESCRIPTION
This enum is used for various Windows Server versions.

#>
enum WindowsServerVersion {
  Unknown
  Server2008R2
  Server2012
  Server2012R2
  Server2016
  Server2019
}

<#

.SYNOPSIS
HypervisorSchedulerType

.DESCRIPTION
The Hypervisor scheduler type that is in effect on this host server.

#>

enum HypervisorSchedulerType {
  Unknown = 0
  ClassicSmtDisabled = 1
  Classic = 2
  Core = 3
  Root = 4
}

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.  Create read only (constant) variables
that add context to the said constants.

#>

function setupScriptEnv() {
  Set-Variable -Name HypervisorEventChannelName -Option ReadOnly -Value "Microsoft-Windows-Hyper-V-Hypervisor" -Scope Script
  Set-Variable -Name Server2008R2BuildNumber -Option ReadOnly -Value 7600 -Scope Script
  Set-Variable -Name Server2012BuildNumber -Option ReadOnly -Value 9200 -Scope Script
  Set-Variable -Name Server2012R2BuildNumber -Option ReadOnly -Value 9600 -Scope Script
  Set-Variable -Name Server2016BuildNumber -Option ReadOnly -Value 14393 -Scope Script
  Set-Variable -Name Server2019BuildNumber -Option ReadOnly -Value 17763  -Scope Script
  Set-Variable -Name ClassicSmtDisabled -Option ReadOnly -Value "0x1" -Scope Script
  Set-Variable -Name Classic -Option ReadOnly -Value "0x2" -Scope Script
  Set-Variable -Name Core -Option ReadOnly -Value "0x3" -Scope Script
  Set-Variable -Name Root -Option ReadOnly -Value "0x4" -Scope Script
  Set-Variable -Name MaxHThreadCountPerCoreForSmt -Option ReadOnly -Value 2 -Scope Script
  Set-Variable -Name DisableSmt -Option ReadOnly -Value 1 -Scope Script
  Set-Variable -Name EnableSmt -Option ReadOnly -Value 2 -Scope Script
  Set-Variable -Name InheritFromHost -Option ReadOnly -Value 0 -Scope Script
  Set-Variable -Name DefaultVHDSize -Option ReadOnly -Value 127GB -Scope Script
  Set-Variable -Name DisksArgs -Option ReadOnly -Value "DisksArgs" -Scope Script
  Set-Variable -Name AdditionalNewVHDSizeArray -Option ReadOnly -Value "AdditionalNewVHDSizeArray" -Scope Script
  Set-Variable -Name AdditionalExistingPathArray -Option ReadOnly -Value "AdditionalExistingPathArray" -Scope Script
  Set-Variable -Name Ide -Option ReadOnly -Value "IDE" -Scope Script
  Set-Variable -Name NetworkAdapter -Option ReadOnly -Value "NetworkAdapter" -Scope Script
  Set-Variable -Name Gen1 -Option ReadOnly -Value 1 -Scope Script
  Set-Variable -Name Gen2 -Option ReadOnly -Value 2 -Scope Script
  Set-Variable -Name VirtualHardDisks -Option ReadOnly -Value "Virtual Hard Disks" -Scope Script
  Set-Variable -Name DynamicMemoryEnabledPropertyName -Option ReadOnly -Value "DynamicMemoryEnabled" -Scope Script
  Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
  Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
  Set-Variable -Name ScriptName -Option ReadOnly -Value "New-VirtualMachine.ps1" -Scope Script
  Set-Variable -Name PortProfileFeatureId -Option ReadOnly -Value "9940cd46-8b06-43bb-b9d5-93d50381fd56" -Scope Script
  Set-Variable -Name PortProfileNetCfgInstanceId -Option ReadOnly -Value "{56785678-a0e5-4a26-bc9b-c0cba27311a3}" -Scope Script
  Set-Variable -Name NetworkControllerVendorId -Option ReadOnly -Value "{1FA41B39-B444-4E43-B35A-E1F7985FD548}" -Scope Script
  Set-Variable -Name NetworkControllerVendorName -Option ReadOnly -Value "NetworkController" -Scope Script
  Set-Variable -Name NetworkControllerCdnLabelName -Option ReadOnly -Value "TestCdn" -Scope Script
  Set-Variable -Name NetworkControllerCdnLabelId -Option ReadOnly -Value 1111 -Scope Script
  Set-Variable -Name NetworkControllerProfileName -Option ReadOnly -Value "Testprofile" -Scope Script
  Set-Variable -Name PortProfileVlan -Option ReadOnly -Value 2 -Scope Script
}

<#

.SYNOPSIS
Cleanup the script environment.

.DESCRIPTION
Cleanup the script environment.

#>

function cleanupScriptEnv() {
  Remove-Variable -Name HypervisorEventChannelName -Scope Script -Force
  Remove-Variable -Name Server2008R2BuildNumber -Scope Script -Force
  Remove-Variable -Name Server2012BuildNumber -Scope Script -Force
  Remove-Variable -Name Server2012R2BuildNumber -Scope Script -Force
  Remove-Variable -Name Server2016BuildNumber -Scope Script -Force
  Remove-Variable -Name Server2019BuildNumber -Scope Script -Force
  Remove-Variable -Name ClassicSmtDisabled -Scope Script -Force
  Remove-Variable -Name Classic -Scope Script -Force
  Remove-Variable -Name Core -Scope Script -Force
  Remove-Variable -Name Root -Scope Script -Force
  Remove-Variable -Name MaxHThreadCountPerCoreForSmt -Scope Script -Force
  Remove-Variable -Name DisableSmt -Scope Script -Force
  Remove-Variable -Name EnableSmt -Scope Script -Force
  Remove-Variable -Name InheritFromHost -Scope Script -Force
  Remove-Variable -Name DefaultVHDSize -Scope Script -Force
  Remove-Variable -Name DisksArgs -Scope Script -Force
  Remove-Variable -Name AdditionalNewVHDSizeArray -Scope Script -Force
  Remove-Variable -Name AdditionalExistingPathArray -Scope Script -Force
  Remove-Variable -Name Ide -Scope Script -Force
  Remove-Variable -Name NetworkAdapter -Scope Script -Force
  Remove-Variable -Name Gen1 -Scope Script -Force
  Remove-Variable -Name Gen2 -Scope Script -Force
  Remove-Variable -Name VirtualHardDisks -Scope Script -Force
  Remove-Variable -Name DynamicMemoryEnabledPropertyName -Scope Script -Force
  Remove-Variable -Name LogName -Scope Script -Force
  Remove-Variable -Name LogSource -Scope Script -Force
  Remove-Variable -Name ScriptName -Scope Script -Force
  Remove-Variable -Name PortProfileFeatureId -Scope Script -Force
  Remove-Variable -Name PortProfileNetCfgInstanceId -Scope Script -Force
  Remove-Variable -Name NetworkControllerVendorId -Scope Script -Force
  Remove-Variable -Name NetworkControllerVendorName -Scope Script -Force
  Remove-Variable -Name NetworkControllerCdnLabelName -Scope Script -Force
  Remove-Variable -Name NetworkControllerCdnLabelId -Scope Script -Force
  Remove-Variable -Name NetworkControllerProfileName -Scope Script -Force
  Remove-Variable -Name PortProfileVlan -Scope Script -Force
}

<#

.SYNOPSIS
Get the fully qualified domain name for the passed in server name from DNS.

.DESCRIPTION
Get the fully qualified domain name for the passed in server name from DNS.

#>

function getServerFqdn([string]$netBIOSName) {
  try {
      return ([System.Net.DNS]::GetHostByName($netBIOSName).HostName)
  }
  catch {
      $errMessage = $_.Exception.Message

      Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
          -Message "[$ScriptName]: There was an error looking up the FQDN for server $netBIOSName.  Error: $errMessage"  -ErrorAction SilentlyContinue

      return $netBIOSName
  }
}

<#

.SYNOPSIS
Get the Hypervisor scheduler type for this server.

.DESCRIPTION
Convert the event string value into an enum that is the current Hypervisor scheduler type.

The message looks like this:

 "Hypervisor scheduler type is 0x1."

 Since the hex value is all we care about this localized message should not be a problem...

#>

function getSchedulerType {
  $schedulerEvent = Get-WinEvent -FilterHashtable @{ProviderName = $HypervisorEventChannelName; ID = 2 } -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object -First 1 Message

  # $event.message may not exist on downlevel servers
  if ($null -ne $schedulerEvent -AND $null -ne $schedulerEvent.message) {

    if ($schedulerEvent.message -match $ClassicSmtDisabled) {
      return [HypervisorSchedulerType]::ClassicSmtDisabled
    }

    if ($schedulerEvent.message -match $Classic) {
      return [HypervisorSchedulerType]::Classic
    }

    if ($schedulerEvent.message -match $Core) {
      return [HypervisorSchedulerType]::Core
    }

    if ($schedulerEvent.message -match $Root) {
      return [HypervisorSchedulerType]::Root
    }
  }

  Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
    -Message "[$ScriptName]: Could not determine the HyperVisor scheduler type." -ErrorAction SilentlyContinue

  return [HypervisorSchedulerType]::Unknown
}

<#

.SYNOPSIS
Get the the build number for the OS installed on this server.

.DESCRIPTION
Get the the build number for the OS installed on this server.

#>

function getBuildNumber {
  return [System.Environment]::OSVersion.Version.Build
}

<#

.SYNOPSIS
Get the Windows Server version for the OS installed on this server.

.DESCRIPTION
Get the Windows Server version for the OS installed on this server.

#>

function getServerVersion {
  $build = getBuildNumber

  if ($build -eq $Server2008R2BuildNumber) {
    return [WindowsServerVersion]::Server2008R2
  }

  if ($build -eq $Server2012BuildNumber) {
    return [WindowsServerVersion]::Server2012
  }

  if ($build -eq $Server2012R2BuildNumber) {
    return [WindowsServerVersion]::Server2012R2
  }

  if ($build -eq $Server2016BuildNumber) {
    return [WindowsServerVersion]::Server2016
  }

  #TODO: This isn't right.  Need to update with 2019 build number once known.
  if ($build -ge $Server2019BuildNumber) {
    return [WindowsServerVersion]::Server2019
  }

  Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
    -Message "[$ScriptName]: Unknown build number $build." -ErrorAction SilentlyContinue

  return [WindowsServerVersion]::Unknown
}

<#

.SYNOPSIS
Determine if this Windows Server 2016 server has been patched.

.DESCRIPTION
Returns true if the patch for CVE-2018-3646 has been installed on this Windows 2016 server.

#>

function isServer2016Patched {
  $patchedEvent = Get-WinEvent -FilterHashtable @{ProviderName = $HypervisorEventChannelName; ID = 156 }  -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object -First 1

  if ($patchedEvent) { return $true } else { return $false }
}

<#

.SYNOPSIS
Compute the final value for hwThreadCountPerCore

.DESCRIPTION
Compute the value for hwThreadCountPerCore that should be persisted based upon the server version
and scheduler type.

#>

function getHwThreadCountPerCore() {

  $schedulerType = getSchedulerType

  # If we cannot get, or do not have, a scheduler type then return hwThreadCountPerCore
  if ($schedulerType -eq [HypervisorSchedulerType]::Unknown) {
    return $null
  }

  $serverVersion = getServerVersion

  if ($serverVersion -eq [WindowsServerVersion]::Server2016) {
    if (-not (isServer2016Patched)) {
      return $null
    }

    if ($schedulerType -eq [HypervisorSchedulerType]::Core) {
      return $EnableSmt
    }

    return $null
  }

  # Is the OS version greater then 2016?  Which really means 2019...
  if ($serverVersion -ge [WindowsServerVersion]::Server2019) {
    if ($schedulerType -eq [HypervisorSchedulerType]::Core) {
      return $InheritFromHost
    }

    return $null
  }

  # Unknown, or unexpected, server version -- don't set the value
  return $null
}

function configureVlan([string]$vmId, [int]$vlanIdentifier) {
  try {
    $vm = Get-RBACVM -Id $vmId
    $vmNic = $vm | Get-VMNetworkAdapter
    $currentFeature = Get-VMSwitchExtensionPortFeature -FeatureId $PortProfileFeatureId -VMNetworkAdapter $vmNic
    $feature = $null

    if (-not ($currentFeature)) {
      $feature = Get-VMSystemSwitchExtensionPortFeature -FeatureId $PortProfileFeatureId
      # leave the following untouched. All of the IDs are hardcoded properly
      $feature.SettingData.NetCfgInstanceId = $PortProfileNetCfgInstanceId
      $feature.SettingData.CdnLabelstring = $NetworkControllerCdnLabelName
      $feature.SettingData.CdnLabelId = $NetworkControllerCdnLabelId
      $feature.SettingData.ProfileName = $NetworkControllerProfileName
      $feature.SettingData.VendorId = $NetworkControllerVendorId
      $feature.SettingData.VendorName = $NetworkControllerVendorName
    }
    # Connect to VLAN
    $vm | Set-VMNetworkAdapterVlan -Access -VlanId $vlanIdentifier

    # set Port Profile data for VLAN
    $feature.SettingData.ProfileId = "{$([System.Guid]::Empty)}"
    $feature.SettingData.ProfileData = $PortProfileVlan
    if (-not ($currentFeature)) {
      Add-VMSwitchExtensionPortFeature -VMSwitchExtensionFeature $feature -VMNetworkAdapter $vmNic
    }
    else {
      Set-VMSwitchExtensionPortFeature -VMSwitchExtensionFeature $currentFeature -VMNetworkAdapter $vmNic
    }
  }
  catch {
    $errMsg = $_

    if ($null -ne $_.Exception.InnerException.Message) {
      $errMsg = $_.Exception.InnerException.Message
    } elseif ($null -ne $_.Exception.InnerException) {
      $errMsg = $_.Exception.InnerException
    } elseif ($null -ne $_.Exception.Message) {
      $errMsg = $_.Exception.Message
    } elseif ($null -ne $_.Exception) {
      $errMsg = $_.Exception
    }

    $vmName = $null

    if ($vm) {
      $vmName = $vm.Name
    }
    else {
      $vmName = $vmId
    }

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
      -Message "[$ScriptName]: There was an error configuring SDN for $vmName. Error: $errMsg" -ErrorAction SilentlyContinue
  }
}

<#

.SYNOPSIS
Process the storage parameters.

.DESCRIPTION
Process the disk parameters provided and build up the args needed by the New-VM cmdlet, and
build the additional, and optional, storage configuration that is applied after the VM has
been created.

#>

function buildDiskArgs([string] $vmName, [long[]]$newVHDSizeBytes, [string[]]$existingVHDPath, [boolean]$useDefaultStorage) {
  $arguments = @{ }

  # Create VHD with new VM using the first provided parameter, the addition VHD will be created
  # after VM created.
  $additionNewVHDSizeArray = @()      # additional new VHD size to be added after new VM created
  $additionExistingPathArray = @()    # additional existing VHD to be added after new VM created

  # check for a parameter presence since single zero will be treat as false
  if (!!$newVHDSizeBytes -or $existingVHDPath) {
    # If only a file name is specified, the virtual hard disk is created in the default path configured for the host.

    $defaultPath = ''

    if ($useDefaultStorage) {
      $defaultPath = Join-Path (Get-VMHost).VirtualHardDiskPath -ChildPath "$vmName" | Join-Path -ChildPath $VirtualHardDisks
      $fileName = "$vmName.vhdx"
      $pathstr = Join-Path $defaultPath $fileName
    }
    else {
      $pathstr = "$vmName.vhdx"
    }

    if (!!$newVHDSizeBytes) {
      # -New VHD
      $arguments += @{ "NewVHDPath" = $pathstr; }

      if ($newVHDSizeBytes[0] -eq 0) {
        $vhdSize = $DefaultVHDSize
      }
      else {
        # if it set use this value
        $vhdSize = $newVHDSizeBytes[0]
      }

      $arguments += @{ "NewVHDSizeBytes" = $vhdSize; }
      if ($newVHDSizeBytes.Length -gt 1) {
        # get remaining elements other than first one
        $additionNewVHDSizeArray = $newVHDSizeBytes[1..($newVHDSizeBytes.Length - 1)]
      }

      # any setting in $existingVHDPath will be added after new VM created
      $additionExistingPathArray = $existingVHDPath
    }
    elseif ($existingVHDPath) {
      # Existing VHD
      # # copy template (won't work for share) to vm default path
      # Copy-Item $vhdTemplatePath $pathstr
      $arguments += @{ "VHDPath" = $existingVHDPath[0]; }

      if (@($existingVHDPath).Length -gt 1) {
        # make sure 1 element string array return 1 instead of string length
        $additionExistingPathArray = $existingVHDPath[1..($existingVHDPath.Length - 1)]
      }
    }
  }
  else {
    # No VHD
    $arguments += @{ "NoVHD" = $null; }
  }

  return @{
    $DisksArgs                   = $arguments;
    $AdditionalNewVHDSizeArray   = $additionNewVHDSizeArray;
    $AdditionalExistingPathArray = $additionExistingPathArray;
  }
}

<#

.SYNOPSIS
Process the boot parameters

.DESCRIPTION
Build the args needed to configure the boot order of the new VM.

#>

function buildBootArgs([AllowNull()][System.Nullable[int]]$generation, [string]$existingIsoPath, [boolean]$bootFromNetwork) {
  $arguments = @{ }

  #change boot order
  if (!$generation -or $generation -eq $Gen1) {
    if ($existingIsoPath -and (Test-Path -Path $existingIsoPath)) {
      $arguments += @{ "BootDevice" = $Ide; }
    }
    elseif ($bootFromNetwork) {
      # only for Generation 1
      $arguments += @{ "BootDevice" = $LegacyNetworkAdapter; }
    }
  }
  elseif ($generation -eq $Gen2) {
    if ($bootFromNetwork) {
      $arguments += @{ "BootDevice" = $NetworkAdapter; }
    }
  }

  return $arguments
}

<#

.SYNOPSIS
Set the memory configuration from the provided parameters.

.DESCRIPTION
Set the memory configuration from the provided parameters.

#>

function setMemoryConfiguration([string]$vmId, [AllowNull()][System.Nullable[boolean]]$dynamicMemoryEnabled, [long]$minimumMemory, [long]$maximumMemory) {
  # boolean parameter is provided or not
  if ($null -ne $dynamicMemoryEnabled) {

    # Create memory arguments
    $memargs = @{ $DynamicMemoryEnabledPropertyName = $dynamicMemoryEnabled }

    if ($maximumMemory) {
      $memargs += @{ "MaximumBytes" = $maximumMemory; }
    }

    if ($minimumMemory) {
      $memargs += @{ "MinimumBytes" = $minimumMemory; }
    }

    Get-RBACVM -Id $vmId | Set-VMMemory @memargs
  }
}

<#

.SYNOPSIS
Set the virtual processor configuration from the provided parameters.

.DESCRIPTION
Set the virtual processor configuration from the provided parameters.

#>

function setProcessorConfiguration(
  [string]$vmId,
  [int]$processorCount,
  [boolean]$enabledNestedVirtualization,
  [boolean]$enableProcessorCompatibility) {

  $processorArgs = @{ }

  if ($processorCount) {
    $processorArgs += @{ "Count" = $processorCount; }
  }

  if ($enabledNestedVirtualization) {
    $processorArgs += @{ "ExposeVirtualizationExtensions" = $enabledNestedVirtualization; }
  }

  if ($enableProcessorCompatibility) {
    $processorArgs += @{ "CompatibilityForMigrationEnabled" = $enableProcessorCompatibility; }
  }

  # Set SMT (hwThreadCountPerCore) setting
  $hwThreadCountPerCore = getHwThreadCountPerCore
  if ($null -ne $hwThreadCountPerCore) {
    $processorArgs += @{ "HwThreadCountPerCore" = $hwThreadCountPerCore; }
  }

  if ($processorArgs.Count -gt 0) {
    Get-RBACVM -Id $vmId | Set-VMProcessor @processorArgs
  }
}

<#

.SYNOPSIS
Configure the additional storage that is needed after the VM has been created.

.DESCRIPTION
Process the provided parameters and build any needed VHDs and attach those VHDs, and
any ISO (CD-ROMs) to the VM.

#>

function configureStorage([string]$vmId, [string]$existingIsoPath, $additionNewVHDSizeArray, $additionExistingPathArray, $useDefaultStorage) {
  # create and add VHD for remaining parameters from $newVHDSizeBytes and $existingVHDPath
  $index = 0
  # Get default path
  $defaultPath = ''

  $vm = Get-RBACVM -Id $vmId

  if ($useDefaultStorage -or !$vm.Path ) {
    $defaultPath = Join-Path (Get-VMHost).VirtualHardDiskPath $VirtualHardDisks
  }
  else {
    $defaultPath = Join-Path $vm.Path $VirtualHardDisks
  }

  foreach ($newVHD in $additionNewVHDSizeArray) {
    $index++
    $fileName = "{0}-{1}.vhdx" -f $vm.Name, $index
    $fullPathToVhd = Join-Path $defaultPath $fileName
    $newVHDargs = @{ "Path" = $fullPathToVhd }

    if ($newVHD -eq 0) {
      # is not set, using default value
      $newVHD = $defaultVHDSize;
    }

    $newVHDargs += @{ "SizeBytes" = $newVHD }

    # create a VHD
    New-VHD @newVHDargs

    # add the hard disk drive to virtual machine
    Add-VMHardDiskDrive -VM $vm -Path $fullPathToVhd -ErrorAction Continue
  }

  foreach ($extVHD in $additionExistingPathArray) {
    if (Test-Path($extVHD)) {

      # add the hard disk drive to virtual machine
      $vm | Add-VMHardDiskDrive -Path $extVHD -ErrorAction Continue
    }
  }

  # create dvd drive for iso file
  if ($existingIsoPath -and (Test-Path -Path $existingIsoPath)) {
    Add-VMDvdDrive -VM $vm -Path $existingIsoPath
    $dvd = Get-VMDvdDrive -VM $vm

    if ($generation -and $generation -eq $Gen2) {
      $vm | Set-VMFirmware -FirstBootDevice $dvd
    }
  }
}

<#

.SYNOPSIS
Does this server support Hyper-V generation 2 virtual machines.

.DESCRIPTION
Only host operating systems greater than or equal to Windows Server 2012R2 support
generation 2 virtual machines.

#>

function isGeneration2Supported() {
  $build = getBuildNumber

  return ($build -ge $Server2012R2BuildNumber)
}

<#

.SYNOPSIS
Main function, called whenever the script can actually be ran.

.DESCRIPTION
Create a new VM and set all provided settings.

#>

function main(
  [string]$vmName,
  [string]$hostName,
  [string]$path,
  [AllowNull()][System.Nullable[int]]$generation,
  [long]$memorySize,
  [AllowNull()][System.Nullable[boolean]]$dynamicMemoryEnabled,
  [long]$maximumMemory,
  [long]$minimumMemory,
  [int]$processorCount,
  [boolean]$enabledNestedVirtualization,
  [boolean]$enableProcessorCompatibility,
  [long[]]$newVHDSizeBytes,
  [string[]]$existingVHDPath,
  [string]$vswitchName,
  [string]$existingIsoPath,
  [boolean]$bootFromNetwork,
  [boolean]$addToCluster,
  [int]$vlanIdentifier
) {

  $vm = $null

  # Create new-vm arguments
  $arguments = @{ "Name" = $vmName; }

  if ($generation) {
    if (isGeneration2Supported) {
      $arguments += @{ "Generation" = $generation; }
    }
    else {
      # Force Windows Server 2012 to Generation 1
      $generation = $Gen1
    }
  }

  if ($path) {
    $hypervPath = $path
    $arguments += @{ "Path" = $hypervPath; }
  }

  if ($memorySize) {
    $arguments += @{ "MemoryStartupBytes" = $memorySize; }
  }

  if ($vswitchName) {
    $arguments += @{ "SwitchName" = $vswitchName; }
  }

  $diskArgs = buildDiskArgs $vmName $newVHDSizeBytes $existingVHDPath $useDefaultStorage
  if ($diskArgs.$DisksArgs) {
    $arguments += $diskArgs.$DisksArgs
  }

  $bootArgs = buildBootArgs $generation $existingIsoPath $bootFromNetwork
  if ($bootArgs) {
    $arguments += $bootArgs
  }

  # Create the VM
  $vm = New-VM @arguments -ErrorAction SilentlyContinue -ErrorVariable +err
  if ($err) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
      -Message "[$ScriptName]: Failed to create virtual machine $vmName. Error: $err" -ErrorAction SilentlyContinue

    Write-Error @($err)[0]

    return @{ }
  }

  Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Info `
    -Message "[$ScriptName]: Successfully created virtual machine $vmName." -ErrorAction SilentlyContinue

  #
  # More settings for other parameters
  #

  # Configure the memory settings.
  setMemoryConfiguration $vm.Id $dynamicMemoryEnabled $minimumMemory $maximumMemory

  # Set the virtual processor settings...
  setProcessorConfiguration $vm.Id $processorCount $enabledNestedVirtualization $enableProcessorCompatibility

  # Configure the optional, and extra, storage
  configureStorage $vm.Id $existingIsoPath $diskArgs.$AdditionalNewVHDSizeArray $diskArgs.$AdditionalExistingPathArray $useDefaultStorage

  # Configure VLAN if needed
  if ($null -ne $vlanIdentifier) {
    configureVlan $vm.Id $vlanIdentifier
  }

  # Get a fresh copy of the VM PSObject since we added many new things after the VM was created.
  # On downlevel servers the value of Heartbeat is one less than expected.  However, in the new VM scenario Heartbeat is a readonly property and cannot be adjusted here.
  # Since this VM model has only a short life, it only lives until the next QC update, this should not be a problem.
  $vm = Get-RBACVM $vm.Id -ErrorAction SilentlyContinue -ErrorVariable +err
  if ($err) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
      -Message "[$ScriptName]: Failed to get the new created virtual machine $vmName. Error: $err" -ErrorAction SilentlyContinue

    Write-Error @($err)[0]

    return @{ }
  }

  # The last step is to add the VM to the cluster.  This is done last since there is a small
  # chance the VM will be moved to a new host node.
  if ($addToCluster) {
    $localServerName = getServerFqdn (hostname)
    $message = $strings.NewVirtualMachineCreatedAddToClusterFailed -f $vmName, $localServerName

    $module = Get-Module -Name FailoverClusters -ErrorAction SilentlyContinue
    if (!!$module) {
      $vm | Add-ClusterVirtualMachineRole -ErrorAction SilentlyContinue -ErrorVariable +err | Out-Null
      if (!!$err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
          -Message "[$ScriptName]: Virtual Machine $vmName was not added to the cluster. Error: $err" -ErrorAction SilentlyContinue

        Write-Error $message
      }
    }
    else {
      Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: The required PowerShell module (FailoverClusters) was not found. Virtual Machine $vmName was not added to the cluster." -ErrorAction SilentlyContinue

      Write-Error $message
    }
  }

  return $vm | Microsoft.PowerShell.Utility\Select-Object `
    Name, `
    Id, `
    CPUUsage, `
    MemoryAssigned, `
    MemoryDemand, `
    State, `
    Status, `
    CreationTime, `
    Uptime, `
    Heartbeat, `
    Version, `
    IsDeleted, `
    DynamicMemoryEnabled, `
    MemoryMaximum, `
    MemoryMinimum, `
    MemoryStartup, `
    ProcessorCount, `
    Generation, `
    NetworkAdapters, `
    ComputerName
}

###############################################################################
# Script execution starts here.
###############################################################################

if (-not($env:pester)) {
  setupScriptEnv

  Start-Transcript -Append -IncludeInvocationHeader -Debug -Force -Confirm:$False | Out-Null

  try {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    $module = Get-Module Hyper-V -ErrorAction SilentlyContinue
    if (-not($module)) {
      Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: The required PowerShell module (HyperV) was not found. Virtual Machine $vmName was not added to the cluster." -ErrorAction SilentlyContinue

      Write-Error $strings.HyperVModuleRequired -ErrorAction Stop

      return @{ }
    }

    return main `
      $vmName `
      $hostName `
      $path `
      $generation `
      $memorySize `
      $dynamicMemoryEnabled `
      $maximumMemory `
      $minimumMemory `
      $processorCount `
      $enabledNestedVirtualization `
      $enableProcessorCompatibility `
      $newVHDSizeBytes `
      $existingVHDPath `
      $vswitchName `
      $existingIsoPath `
      $bootFromNetwork `
      $addToCluster `
      $vlanIdentifier
  }
  finally {
    Stop-Transcript | Out-Null
    cleanupScriptEnv
  }
}

}
## [END] New-WACVMVirtualMachine ##
function New-WACVMVirtualSwitch {
<#

.SYNOPSIS
Create a new virtual switch.

.DESCRIPTION
Create a new virtual switch on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER name
    The name of the new virtual switch.

.PARAMETER netAdapterNames
    The optional array of names of network adapters to assign to this switch.  When there is 
    more than one adapter provided a Switch Embedded Teaming (SET) switch will be created.  This parameter
    is not required for Private or Internal virtual switch types.

.PARAMETER switchType
    The switch type.  
    [Microsoft.HyperV.PowerShell.VMSwitchType]::Private (0)
    [Microsoft.HyperV.PowerShell.VMSwitchType]::Internal (1)
    [Microsoft.HyperV.PowerShell.VMSwitchType]::External (2)

.PARAMETER allowManagementOs
    Ooptionally allow the host operationg system to use the virtual switch as a network adapter.

.PARAMETER loadBalancingAlgorithm
    Optional load balancing algoritm for SET switches.
    hyperVPort = 4,
    dynamic = 5

#>

param (
    [Parameter(Mandatory = $true)]
    [string]
    $name,
    [Parameter(Mandatory = $false)]
    [string []]
    $netAdapterNames,
    [Parameter(Mandatory = $true)]
    [int]
    $switchType,
    [Parameter(Mandatory = $false)]
    [boolean]
    $allowManagementOs,
    [Parameter(Mandatory = $false)]
    [AllowNull()][System.Nullable[int]]
    $loadBalancingAlgorithm
)  

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

###############################################################################
# Constants
###############################################################################

Set-Variable -Name LogName -Option Constant -Value "Microsoft-ServerManagementExperience" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SMEScripts" -ErrorAction SilentlyContinue
Set-Variable -Name ScriptName -Option Constant -Value "New-VirtualSwitch.ps1" -ErrorAction SilentlyContinue

function main([string]$name, [string []]$netAdapterNames, [int]$switchType, [boolean]$allowManagementOs, [AllowNull()][System.Nullable[int]]$loadBalancingAlgorithm) {

    $vs = $null

    $args = @{ 'Name'=$name; }

    if (($netAdapterNames -and $netAdapterNames.Length -gt 0) -and $switchType -eq 2) {
        # Since all versions, current and downlevel, accept a string argument, when the array is only
        # one element force to a string...
        if ($netAdapterNames.Length -eq 1) {
            $netAdapterName = $netAdapterNames[0]

            $args += @{ 'NetAdapterName'=$netAdapterName; }
        } else {
            $args += @{ 'NetAdapterName'=$netAdapterNames; }
        }

        $args += @{ 'AllowManagementOS'=$allowManagementOs; }
    } else {
        $args += @{ 'SwitchType'=$switchType; }
    }

    $vs = New-VMSwitch @args

    # If a load balancing algorithm param is supplied we need to set it on the new SET switch.
    if ($loadBalancingAlgorithm) {
        $cmd = get-command Set-VMSwitchTeam -ErrorAction SilentlyContinue

        if ($cmd -and $cmd.Name -eq "Set-VMSwitchTeam") {
            Set-VMSwitchTeam -Name $vs.Name -LoadBalancingAlgorithm $loadBalancingAlgorithm
        } else {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: The Load Balancing Algorithm parameter was supplied when Switch Embedded Teaming (SET) is not supported." -ErrorAction SilentlyContinue
                
            Write-Error $strings.InvalidLoadBalancingAlgorithmType
        }
    }

    return $vs | `
        Microsoft.PowerShell.Utility\Select-Object `
        name, `
        Id, `
        extensions, `
        switchType, `
        allowManagementOS, `
        netAdapterInterfaceDescription, `
        netAdapterInterfaceDescriptions, `
        computerName, `
        isDeleted
}

Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

$module = Get-Module -Name Hyper-V -ErrorAction SilentlyContinue
if ($module) {
    return main $name $netAdapterNames $switchType $allowManagementOs $loadBalancingAlgorithm
}

return $null

}
## [END] New-WACVMVirtualSwitch ##
function Register-WACVMSiteRecoveryAgent {
<#
.SYNOPSIS
Register Site Recovery Agent to Azure

.DESCRIPTION
Use provided credential content to create a credential file then register the node to Azure Site Recovery

.ROLE
Administrators

#>

[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $VaultKeyContent,
    [Parameter()]
    [string]
    $NodeName
)

$ErrorActionPreference = 'Stop'

$ScriptFile = $env:temp + "\Register-AzureSiteRecovery.ps1"
if (Test-Path $ScriptFile) {
    Remove-Item $ScriptFile
}

$VaultCredentialFile = [System.IO.Path]::GetTempFileName()
if (Test-Path $VaultCredentialFile) {
    Remove-Item $VaultCredentialFile
}

$VaultKeyContent | Out-File $VaultCredentialFile -Force | Out-Null
$InstallPath = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Azure Site Recovery' -Name 'InstallPath'
$DRConfiguratorPath = $InstallPath + 'DRConfigurator.exe'
$Output = &$DRConfiguratorPath  /r /friendlyName $NodeName /Credentials $VaultCredentialFile 2>&1
if ($LastExitCode -ne 0) {
    $Message = "Something went wrong while registering Azure Site Recovery."
    if ($null -ne $Output) {
        $Message += " $Output"
    }

    $LogName = "Microsoft-ServerManagementExperience"
    $LogSource = "SMEScript"
    $ScriptName = "Register-SiteRecoveryAgent.ps1"
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: $Message"  -ErrorAction SilentlyContinue

    Write-Error $Message
}
else {
    Write-Output "Everything went smoothly: $Output"
}

}
## [END] Register-WACVMSiteRecoveryAgent ##
function Remove-WACVMAffinityRule {
<#

.SYNOPSIS
Removes a specific affinity rule

.DESCRIPTION
Removes a specific affinity rule

.ROLE
Hyper-V-Administrators

#>

param (
	[Parameter(Mandatory = $true)]
	[String]
  $name
)

Set-StrictMode -Version 5.0

Remove-ClusterAffinityRule -Name $name

}
## [END] Remove-WACVMAffinityRule ##
function Remove-WACVMNetworkInterfaces {
<#

.SYNOPSIS
Remove NICS that match any of the passed in indicators

.DESCRIPTION
Remove the SDN network interfaces that match the passed in instance IDs, MAC addresses, or VM Ids

.ROLE
Hyper-V-Administrators

.PARAMETER hypervNicMacAddresses
    The requested NIC's mac addresses.

.PARAMETER ncUri
    The Network Controller uri used for Software Defined Networking connections.

.PARAMETER portProfiles
    The instance id's of nc nics to remove.

.PARAMETER vmIds
    The VMID of vms that are being entirely deleted. This will delete ALL NC nics tagged with that VMID, so
    do not use this parameter if the VM is just being edited.

.PARAMETER errors
    The collected errors from previous parts of VM removal.
#>

param (
  [Parameter(Mandatory = $false)]
  [String[]]
  $hypervNicMacAddresses = @(),
  [Parameter(Mandatory = $false)]
  [String[]]
  $portProfiles = @(),
  [Parameter(Mandatory = $false)]
  [String[]]
  $errors = @(),
  [Parameter(Mandatory = $false)]
  [String[]]
  $adapterIds = @(),
  [Parameter(Mandatory = $false)]
  [String[]]
  $vmIds = @(),
  [Parameter(Mandatory = $true)]
  [String]
  $ncUri
)

Set-StrictMode -Version 5.0
Import-Module NetworkController -ErrorAction SilentlyContinue

###############################################################################
# Constants
###############################################################################

Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option ReadOnly -Value "SMEGateway" -Scope Script -ErrorAction SilentlyContinue
Set-Variable -Name ScriptName -Option ReadOnly -Value "Remove-NetworkInterfaces.ps1" -Scope Script -ErrorAction SilentlyContinue

function removeSdnSettings($hypervNicMacAddresses, $portProfiles, [string] $ncUri, $adapterIds, $vmIds, [string []] $err) {
  $allNics = Get-NetworkControllerNetworkInterface -ConnectionUri $ncUri -ErrorAction SilentlyContinue -ErrorVariable err

  if (!!$err) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
      -Message "[$ScriptName]: Couldn't retrieve selected virtual machine network adapters. Error: $($err[0])" -ErrorAction SilentlyContinue

    Write-Error @($err)[0]
  }

  foreach ($nic in $allNics) {
    $instanceId = $nic.InstanceId
    $matchesInstanceId = $portProfiles.Contains("{$instanceId}")

    $matchesMacAddress = $hypervNicMacAddresses.contains($nic.Properties.PrivateMacAddress)

    $matchesVmTag = $false
    if ($null -ne $nic.tags -and $nic.tags.PSobject.Properties.name -match "vmId" -and $vmIds) {
      $matchesVmTag = $vmIds.contains($nic.tags.vmId)
    }

    $matchesAdapterTag = $false
    if ($null -ne $nic.tags -and $nic.tags.PSobject.Properties.name -match "adapterId" -and $adapterIds) {
      $matchesAdapterTag = $adapterIds.contains($nic.tags.adapterId)
    }

    if ($matchesInstanceId -or $matchesMacAddress -or $matchesVmTag -or $matchesAdapterTag) {
      try {
        Remove-NetworkControllerNetworkInterface -ConnectionUri $ncUri -ResourceId $nic.ResourceId -Force -ErrorVariable err

        if (!!$err) {
          Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Couldn't remove the selected nic. Error: $($err[0])" -ErrorAction SilentlyContinue

          Write-Error @($err)[0]
        }

        # Don't save as error variable - we want these to fail eventually
        $nic = Get-NetworkControllerNetworkInterface -ConnectionUri $ncUri -ResourceId $nic.ResourceId
        while ($nic.Properties.ProvisioningState -ne "Failed") {
          $nic = Get-NetworkControllerNetworkInterface -ConnectionUri $ncUri -ResourceId $nic.ResourceId
        }
      }
      catch {
        # SDN error messages are sometimes formatted in a particular way.
        # Try to get the message if avaliable.
        $errMsg = $_
        if ($null -ne $_.Exception.InnerException.Message) {
          $errMsg = $_.Exception.InnerException.Message
        } elseif ($null -ne $_.Exception.InnerException) {
          $errMsg = $_.Exception.InnerException
        } elseif ($null -ne $_.Exception.Message) {
          $errMsg = $_.Exception.Message
        } elseif ($null -ne $_.Exception) {
          $errMsg = $_.Exception
        }
        # After deleting the object, we expect it to be not found. In other cases, there is actually
        # an error occuring
        if ($errMsg -NotMatch "not found") {
          $err += $errMsg
        }
      }
    }
  }

  return $err
}

$result = removeSdnSettings -hypervNicMacAddresses $hypervNicMacAddresses -portProfiles $portProfiles -ncUri $ncUri -adapterIds $adapterIds -vmIds $vmIds -err $errors

Remove-Variable -Name LogSource -Scope Script -Force
Remove-Variable -Name LogName -Scope Script -Force
Remove-Variable -Name ScriptName -Scope Script -Force

return $result

}
## [END] Remove-WACVMNetworkInterfaces ##
function Remove-WACVMVirtualMachine {
<#

.SYNOPSIS
Remove the passed in virtual machine from this server.

.DESCRIPTION
Remove the virtual machine from this server, and optionally delete the VHD files the virtual machine was using.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER vmIds
    The list of requested virtual machine Ids.

.PARAMETER includeVhdFiles
    When true the virtual hard disk (VHD) files used by the virtual machine are deleted. after the virtual machine has been removed.
#>

param (
    [Parameter(Mandatory = $true)]
    [String []]
    $vmIds,
    [Parameter(Mandatory = $true)]
    [boolean]
    $includeVhdFiles
)

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue
Import-Module FailoverClusters -ErrorAction SilentlyContinue

###############################################################################
# Constants
###############################################################################

Set-Variable -Name LogName -Option Constant -Value "Microsoft-ServerManagementExperience" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SMEScripts" -ErrorAction SilentlyContinue
Set-Variable -Name ScriptName -Option Constant -Value "Remove-VirtualMachine.ps1" -ErrorAction SilentlyContinue
Set-Variable -Name PortProfileFeatureId -Option Constant -Value "9940cd46-8b06-43bb-b9d5-93d50381fd56" -ErrorAction SilentlyContinue

<#

.SYNOPSIS
    Recursive function to get the paths of a VHD tree.

.DESCRIPTION
    Find and return the paths to all of the VHDs that are children of the passed in VHD.

.Parameter vhd
    The starting point VHD
#>

function getPath($vhd) {
    if ($vhd.parentPath) {
        $parentVhd = Get-Vhd -path $vhd.parentPath

        getpath($parentVhd)
    }

    return $vhd.path
}

<#

.SYNOPSIS
    Find the paths to all of the VHDs used by the passed in VM.

.DESCRIPTION
    Search all attached VHDs to build a flat list of the VHD files used by
    the VM.

.Parameter vmId
    The Id of the VM to operate on.

.Outputs
    An array of the paths to all VHDs used by the VM.
#>

function getVhdFiles([string] $vmId) {
    $vhds = Get-Vhd -id $vmId -ErrorAction SilentlyContinue -ErrorVariable +vhdError

    $vhdFiles = @()

    # Checkpoints will cause there to be VHDs that can only be found by traversing the tree.
    foreach ($vhd in $vhds) {
        if ($vhd.path) {
            $vhdFiles += $vhd.path
        }

        if ($vhd.parentPath) {
            $parentVhd = Get-Vhd -path $vhd.parentPath

            $vhdFiles += getPath($parentVhd)
        }
    }

    if ($vhdError) {
        $err = @($vhdError)[0]
        if ($err.exception.ErrorIdentifier -eq "ObjectNotFound") {
            # one of VHDs could be physical drive, make it as progress message.
            Write-Progress -Activity "VHDObjectNotFound" -Status $err.Exception.Message
        } else {
            Write-Error $err
        }
    }

    return $vhdFiles
}

<#

.SYNOPSIS
    Delete the VHD files.

.DESCRIPTION
    Delete each VHD file whose path is in the array of paths.

.Parameter vhdsToDelete
    The array of VHD file paths.

#>

function deleteVhdFiles([string []] $vhdsToDelete) {
    # Make a best effort to delete the VHD files.
    # This list will likely contain checkpoint (AVHD(x)) that will have been cleaned up when the VM was removed so there is no need to report an error.
    foreach ($vhdFileToDelete in $vhdFilesToDelete) {
        Microsoft.PowerShell.Management\Remove-Item $vhdFileToDelete -ErrorAction SilentlyContinue
    }
}

<#

.SYNOPSIS
    Check for the presence of the Failover Cluster PowerShell cmdlets.

.DESCRIPTION
    Check for the presence of the Failover Cluster PowerShell cmdlets.

.Outputs
    A boolean value that is true when the PowerShell cmdlets are available.

#>

function isClusterPowerShellAvailable() {
    $cmdletInfo = Get-Command "Remove-ClusterGroup" -ErrorAction SilentlyContinue

    return $cmdletInfo -and $cmdletInfo.Name -eq "Remove-ClusterGroup"
}

<#

.SYNOPSIS
    Delete a virtual machine.

.DESCRIPTION
    Delete a virtual machine and perform all optional clean up as needed.

.Parameter vmId
    The Id of the VM to delete

.Parameter includeVhdFiles
    Should the optional step of removing the VHDs used by the VM from storage be performed

.Parameter clusterPowerShellAvailable
    When true the Failover Cluster PowerShell cmdlets are available.

.Parameter err
    The errors accumulated in.

.Outputs
    All of the accumulated errors.

#>

function deleteVirtualMachine(
    [string] $vmId,
    [bool] $includeVhdFiles,
    [bool] $clusterPowerShellAvailable,
    [string []] $err) {
    # The VM may have moved to another node of the cluster so some extra checking is needed.
    $vm = Get-RBACVM -Id $vmId -ErrorVariable +err -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object Name, Id, IsClustered
    if(-not $vm) {
        return $err
    }

    $isClustered = $vm.isClustered
    $vhdFilesToDelete = @()

    if ($includeVhdFiles) {
        $vhdFilesToDelete = getVhdFiles $vmId
    }

    $removeErrors = @()

    # Gather potentially needed SDN data before we remove the VM
    $relevantAdapters = Get-VMNetworkAdapter -VMName $vm.Name -ErrorAction SilentlyContinue
    $macsToDelete = @($relevantAdapters | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty MacAddress)
    $portProfiles = (Get-VMSwitchExtensionPortFeature -FeatureId $PortProfileFeatureId -VMNetworkAdapter $relevantAdapters).SettingData.ProfileId

    Remove-VM -Name $vm.Name -Force -ErrorAction SilentlyContinue -ErrorVariable +removeErrors
    $err += $removeErrors

    # If the VM was deleted without error then do the rest of the clean up.
    if ($removeErrors.Count -eq 0) {
        if ($includeVhdFiles) {
            deleteVhdFiles $vhdFilesToDelete
        }

        # Make a best effort to clean up the cluster resources. Failure should not stop the script from continuing.
        if ($isClustered -and $clusterPowerShellAvailable) {
            Get-ClusterGroup -VMId $vmId | Remove-ClusterGroup -RemoveResources -Force -ErrorAction SilentlyContinue
        } else {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Warning `
                -Message "[$ScriptName]: The required PowerShell module (FailoverClusters) was not found. Cluster resources were not removed from the cluster." -ErrorAction SilentlyContinue
        }
    } else {
        # Zero out SDN options - if the VM didn't delete then keep SDN resources
        $macsToDelete = @()
        $portProfiles = @()
    }

    return New-Object psobject -Property @{
      'macAddresses' = $macsToDelete
      'portProfiles' = $portProfiles
      'errors'  = $err
    }
}

<#

.SYNOPSIS
    The scripts main function

.DESCRIPTION
    Delete the provided list of virtual machine(s) and perform all optional clean up as needed.

.PARAMETER vmIds
    The list of requested virtual machine Ids.

.PARAMETER includeVhdFiles
    When true the virtual hard disk (VHD) files used by the virtual machine are deleted. after the virtual machine has been removed.

.Outputs
    The results of the operation.

#>

function main([string []] $vmIds, [boolean] $includeVhdFiles) {
  $clusterPowerShellAvailable = isclusterPowerShellAvailable

  $err = @()
  $portProfiles = @()
  $macAddresses = @()

  foreach ($vmId in $vmIds) {
      $deleteValues = deleteVirtualMachine $vmId $includeVhdFiles $clusterPowerShellAvailable $err
      $err += $deleteValues.errors
      $portProfiles += $deleteValues.portProfiles
      $macAddresses += $deleteValues.macAddresses
  }

  return New-Object psobject -Property @{
    'hypervNicMacAddresses'  = $macAddresses
    'portProfiles' = $portProfiles
    'errors' = $err
  }
}

Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

main $vmIds $includeVhdFiles

}
## [END] Remove-WACVMVirtualMachine ##
function Remove-WACVMVirtualMachineCheckpoint {
<#

.SYNOPSIS
Remove the passed in snapshot from its associated virtual machine.

.DESCRIPTION
Remove the passed in snapshot from its associated virtual machine on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER snapshotId
    The id of the checkpoint (snapshot) to delete.

.PARAMETER includeSubtree
    Should all of the children checkpoints of this checkpoint also be removed?

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $snapshotId,
    [Parameter(Mandatory = $true)]
    [boolean]
    $includeSubtree
)

Set-StrictMode -Version 5.0;
Import-Module Hyper-V;

$args = @{};

if ($includeSubtree)
{
    $args += @{'IncludeAllChildSnapshots'= $null};
}

get-vmsnapshot -Id $snapshotId | remove-VMSnapshot @args;

}
## [END] Remove-WACVMVirtualMachineCheckpoint ##
function Remove-WACVMVirtualMachineSavedState {
<#

.SYNOPSIS
Delete the saved state for passed in virtual machines.

.DESCRIPTION
Delete the saved states for virtual machines.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER vmIds
  The Ids of the requested virtual machines.

#>

param (
    [Parameter(Mandatory = $true)]
    [String[]]
    $vmIds
)

Set-StrictMode -Version 5.0
Import-Module -Name Hyper-V -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

<#

.SYNOPSIS
The main function.

.DESCRIPTION
Delete the saved state for the virtual machines whose Ids are passed in and report the progress.

.PARAMETER vmIds
The list of VM Ids.

#>

function main([string[]]$vmIds) {
    $virtualMachineCount = 0
    $virtualMachineSuccesses = New-Object System.Collections.ArrayList
    $virtualMachineFailures = ""

    ForEach($vmId in $vmIds)
    {
        $percentComplete = $virtualMachineCount++/$vmIds.Count * 100

        $vm = Get-RBACVM -id $vmId -ErrorVariable getVmError -ErrorAction SilentlyContinue
        if ($getVmError)
        {
            $errorMessage = $getVmError[0].Exception.Message
            Write-Progress -PercentComplete $percentComplete -Activity ($errorMessage)
            $virtualMachineFailures += $errorMessage + " "
        }
        else
        {
            $vmName = $vm.Name

            Write-Progress -PercentComplete $percentComplete -Activity ($strings.DeleteSavedStateVirtualMachineStartingMessage -f $vmName)

            Remove-VMSavedState $vm -ErrorVariable operationError -ErrorAction SilentlyContinue
            if ($operationError)
            {
                $errorMessage = $strings.DeleteSavedStateVirtualMachineFailureMessage -f $vmName, $operationError[0].Exception.Message
                Write-Progress -PercentComplete $percentComplete -Activity ($errorMessage)
                $virtualMachineFailures += $errorMessage + " "
            } else 
            {
                Write-Progress -PercentComplete $percentComplete -Activity ($strings.DeleteSavedStateVirtualMachineSuccessMessage -f $vmName)

                $virtualMachineSuccesses.Add($vmName) > $null
            }
        }
    }

    if ($virtualMachineFailures)
    {
        if ($virtualMachineSuccesses.Count -gt 0)
        {
            # Prepend success 
            $virtualMachineFailures = $strings.DeleteSavedStateVirtualMachineOperationMessage -f ($virtualMachineSuccesses -join ", "), $virtualMachineFailures
        }

        throw $virtualMachineFailures
    }
}

###############################################################################
# Script execution starts here
###############################################################################

main $vmIds

}
## [END] Remove-WACVMVirtualMachineSavedState ##
function Remove-WACVMVirtualSwitch {
<#

.SYNOPSIS
Remove the passed in virtual switch from this server.

.DESCRIPTION
Remove the passed in virtual switch from this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER vsId
    The Id of the requested virtual switch.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $vsId
)  

Set-StrictMode -Version 5.0;
Import-Module Hyper-V;

Get-VMSwitch -id $vsId | Remove-VMSwitch -Force

}
## [END] Remove-WACVMVirtualSwitch ##
function Rename-WACVMVirtualMachine {
<#

.SYNOPSIS
Rename a virtual machine.

.DESCRIPTION
Rename the passed in virtual machine on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER vmId
    The id of the requested virtual machine.

.PARAMETER newName
    The new name for the passed in virtual machine.  This name does not have to be unique.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $vmId,
    [Parameter(Mandatory = $true)]
    [String]
    $newName
)  

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue
Import-Module CimCmdlets -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.  Create read only (constant) variables
that add context to the said constants.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScript" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Rename-VirtualMachine.ps1" -Scope Script
    Set-Variable -Name BritannicaNamespace -Option ReadOnly -Value "root\SDDC\Management" -Scope Script
    Set-Variable -Name VmRefreshValue -Option Readonly -Value 0 -Scope Script
    Set-Variable -Name RefreshMethodName -Option ReadOnly -Value "Refresh" -Scope Script
    Set-Variable -Name IdPropertyName -Option ReadOnly -Value "Id" -Scope Script
}

<#

.SYNOPSIS
Cleanup the script environment.

.DESCRIPTION
Cleanup the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name BritannicaNamespace -Scope Script -Force
    Remove-Variable -Name VmRefreshValue -Scope Script -Force
    Remove-Variable -Name RefreshMethodName -Scope Script -Force
    Remove-Variable -Name IdPropertyName -Scope Script -Force
}

<#

.SYNOPSIS
Write an error level log message.

.DESCRIPTION
Write an error level log message.

.PARAMETER message
    The error message to log.

#>

function logError([string] $message) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message $message  -ErrorAction SilentlyContinue
}

<#

.SYNOPSIS
The main function.

.DESCRIPTION
Rename the passed in virtual machine on this server. Force refresh if Britannica enabled

.PARAMETER vmId
    The id of the requested virtual machine.

.PARAMETER newName
    The new name for the passed in virtual machine.  This name does not have to be unique.

#>

function main([string]$vmId, [string]$newName) {
    $err = $null

    $vm = Get-RBACVM -id $vmId -ErrorAction SilentlyContinue -ErrorVariable +err
    if ($vm -and -not($err)) {
        $vm | Rename-VM -NewName $newName -ErrorAction SilentlyContinue -ErrorVariable +err

        if (-not ($err)) {
            if (isBritannicaEnabled) {
                $result = refreshVm $vmId
            }
        }
        else {
            logError "[$ScriptName]: Could not rename virtual machine $vmid. Error: $err"
    
            Write-Error @($err)[0]
        }

        # Get a new VM instance with the new name
        return Get-RBACVM -Id $vmId | Microsoft.PowerShell.Utility\Select-Object `
            Name, `
            CPUUsage, `
            MemoryAssigned, `
            MemoryDemand, `
            State, `
            Status, `
            CreationTime, `
            Uptime, `
            Version, `
            IsDeleted, `
            DynamicMemoryEnabled, `
            MemoryMaximum, `
            MemoryMinimum, `
            MemoryStartup, `
            ProcessorCount, `
            Generation, `
            ComputerName,
        @{Name = $IdPropertyName; Expression = { [System.Guid]::Parse($_.id.ToString().ToLower()) } }  # Ensure the ID GUID is lower case...
    }
    
    logError "[$ScriptName]: Could not find virtual machine $vmid. Error: $err"

    Write-Error @($err)[0]

    return @{ }
}

<#

.SYNOPSIS
Determines if Britannica (sddc management resources) are available on the cluster

.DESCRIPTION

Use the existance of the cim namespace root/sddc/Management and class name to determine if Britannica
is supported or not.

#>

function isBritannicaEnabled() {
    $isPresent = (Get-CimInstance -Namespace $BritannicaNamespace -ClassName SDDC_VirtualMachine -ErrorAction SilentlyContinue)

    if (!$isPresent) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
            -Message "[$ScriptName]: The Britannica namespace $BritannicaNamespace was not found.  This may be expected depending on the cluster configuration"  -ErrorAction SilentlyContinue
    }

    return !!$isPresent
}

<#

.SYNOPSIS
Refresh virtual machine match given $vmId

.DESCRIPTION
Find vm match given $vmId from Britannica, then force refresh it

#>
function refreshVm([string] $vmId) {
    $err = $null

    $vm = Get-CimInstance -Namespace $BritannicaNamespace -ClassName SDDC_VirtualMachine | `
        Microsoft.PowerShell.Core\Where-Object { $_.Id.ToLower() -eq $vmId.ToLower() } -ErrorAction SilentlyContinue -ErrorVariable +err

    if ($vm -and -not($err)) {
        $result = Invoke-CimMethod -CimInstance $vm -MethodName $RefreshMethodName -Arguments @{ "RefreshType" = $VmRefreshValue } -ErrorAction SilentlyContinue -ErrorVariable +err

        if ($err) {
            logError "[$ScriptName]: Failed to refresh the virtual machine with Id $vmId. Error: $err"
            
            return $false
        }

        return $true
    }

    logError "[$ScriptName]: Failed to find the virtual machine with Id $vmId. Error: $err"

    return $false
}

###############################################################################
# Script execution starts here
###############################################################################

if (-not($env:pester)) {
    setupScriptEnv

    try {
        Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

        $module = Get-Module -Name Hyper-V -ErrorAction SilentlyContinue
        if ($module) {
            return main $vmId $newName
        }

        logError "[$ScriptName]: The required PowerShell module (Hyper-V) was not found."

        return @{ }
    }
    finally {
        cleanupScriptEnv
    }
}
}
## [END] Rename-WACVMVirtualMachine ##
function Rename-WACVMVirtualMachineCheckpoint {
<#

.SYNOPSIS
Rename a virtual machine checkpoint (snapshot).

.DESCRIPTION
Renames the passed in virtual machine checkpoint to the passed in name on this server
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER snapshotId
    The id of the virtual machine checkpoint (snapshot).

.PARAMETER newSnapShotName
    The new name for the passed in virtual machine checkpoint (snapshot).

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $snapshotId,
    [Parameter(Mandatory = $true)]
    [String]
    $newSnapShotName
)  

Set-StrictMode -Version 5.0;
Import-Module Hyper-V;

Get-VmSnapshot -Id $snapshotId | Rename-VMSnapshot -NewName $newSnapShotName

}
## [END] Rename-WACVMVirtualMachineCheckpoint ##
function Rename-WACVMVirtualSwitch {
<#

.SYNOPSIS
Rename a virtual switch.

.DESCRIPTION
Renames the passed in virtual switch to the passed in name on this server
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER vsId
    The id of the virtual switch.

.PARAMETER newName
    The new name for the passed in virtual switch

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $vsId,
    [Parameter(Mandatory = $true)]
    [String]
    $newName
)  

Set-StrictMode -Version 5.0;
Import-Module Hyper-V;

get-vmswitch -id $vsId | rename-vmswitch -NewName $newName

}
## [END] Rename-WACVMVirtualSwitch ##
function Reset-WACVMVirtualMachine {
<#

.SYNOPSIS
Resets (restarts) the passed in virtual machines.

.DESCRIPTION
Resets (restarts) the passed in virtual machines on this server
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER vmIds
    The ids of the requested virtual machines.

#>

param (
    [Parameter(Mandatory = $true)]
    [String[]]
    $vmIds
)

Set-StrictMode -Version 5.0
Import-Module -Name Hyper-V -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue
Set-Variable -Name VmRefreshValue -Option Constant -Value 0 -ErrorAction SilentlyContinue

<#

.SYNOPSIS
The main function.

.DESCRIPTION
Reset the virtual machines whose Ids are passed in and report the progress.

.PARAMETER vmIds
The list of VM Ids.

#>

function main([string[]]$vmIds) {
    $virtualMachineCount = 0
    $virtualMachineSuccesses = New-Object System.Collections.ArrayList
    $virtualMachineFailures = ""

    ForEach($vmId in $vmIds)
    {
        $percentComplete = $virtualMachineCount++/$vmIds.Count * 100

        $vm = Get-RBACVM -id $vmId -ErrorVariable getVmError -ErrorAction SilentlyContinue
        if ($getVmError)
        {
            $errorMessage = $getVmError[0].Exception.Message
            Write-Progress -PercentComplete $percentComplete -Activity ($errorMessage)
            $virtualMachineFailures += $errorMessage + " "
        }
        else
        {
            $vmName = $vm.Name

            Write-Progress -PercentComplete $percentComplete -Activity ($strings.ResetVirtualMachineStartingMessage -f $vmName)

            restart-vm -force $vm -ErrorVariable operationError -ErrorAction SilentlyContinue
            if ($operationError)
            {
                $errorMessage = $strings.ResetVirtualMachineFailureMessage -f $vmName, $operationError[0].Exception.Message
                Write-Progress -PercentComplete $percentComplete -Activity ($errorMessage)
                $virtualMachineFailures += $errorMessage + " "
            } else 
            {
                Write-Progress -PercentComplete $percentComplete -Activity ($strings.ResetVirtualMachineSuccessMessage -f $vmName)

                $virtualMachineSuccesses.Add($vmName) > $null
            }
        }
    }

    if (isBritannicaEnabled) {
        refreshVms
    }

    if ($virtualMachineFailures)
    {
        if ($virtualMachineSuccesses.Count -gt 0)
        {
            # Prepend success 
            $virtualMachineFailures = $strings.ResetVirtualMachineOperationMessage -f ($virtualMachineSuccesses -join ", "), $virtualMachineFailures
        }

        throw $virtualMachineFailures
    }
}

<#

.SYNOPSIS
Determines if Britannica (sddc management resources) are available on the cluster

.DESCRIPTION

Use the existance of the cim namespace root/sddc/Management and class name to determine if Britannica
is supported or not.

#>
function isBritannicaEnabled() {
    return !!(Get-CimInstance -Namespace "root\SDDC\Management" -ClassName SDDC_VirtualMachine -ErrorAction SilentlyContinue)
}

<#

.SYNOPSIS
Refresh virtual machines match given $vmIds

.DESCRIPTION
Find vm match given $vmIds from Britannica, then force refresh them

#>
function refreshVms() {
    $vms = Get-CimInstance -Namespace "root\SDDC\Management" -ClassName SDDC_VirtualMachine | `
    Microsoft.PowerShell.Core\Where-Object {$_.Id.ToLower() -in $vmIds.ToLower()} -ErrorAction SilentlyContinue

    foreach ($vm in $vms) {
      refreshVm $vm
    }
}

<#

.SYNOPSIS
Refresh given virtual machine

.DESCRIPTION
Force refresh given virtual machine from Britannica

.Parameter vm
    The vm object to refresh
#>
function refreshVm($vm) {
    if ($vm) {
      Invoke-CimMethod -CimInstance $vm -MethodName "Refresh" -Arguments @{RefreshType=$VmRefreshValue} -ErrorVariable +err
    }
}

###############################################################################
# Script execution starts here
###############################################################################

main $vmIds

}
## [END] Reset-WACVMVirtualMachine ##
function Restore-WACVMVirtualMachineCheckpoint {
<#

.SYNOPSIS
Restore the passed in snapshot to its associated virtual machine.

.DESCRIPTION
Applies the passed in snapshot to the passed in virtual machine.  Since the virtual machine cannot be running when the snapshot
is applied, this script will stop the virtual machine before applying the snapshot, and will start it when that is complete.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER vmId
    The Id of the requested virtual machine.

.PARAMETER snapshotId
    The Id of the checkpoint (snapshot) to apply to the virtual machine.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $vmId,
    [Parameter(Mandatory = $true)]
    [String]
    $snapshotId
)

Set-StrictMode -Version 5.0;
Import-Module Hyper-V;

$vm = Get-RBACVM -Id $vmId
$originalState = $vm.State

if ($originalState -ne "Off" -and $originalState -ne "Saved")
{
	$vm | Stop-Vm -Save
}

get-vmsnapshot -Id $snapshotId | restore-VMSnapshot -Confirm:$false

if ($originalState -eq "Running")
{
	$vm | Start-VM
}
}
## [END] Restore-WACVMVirtualMachineCheckpoint ##
function Resume-WACVMVirtualMachine {
<#

.SYNOPSIS
Resumes (un-pauses) the passed in virtual machines.

.DESCRIPTION
Resumes (un-pauses) the passed in virtual machines on this server
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER vmIds
    The ids of the requested virtual machines.

#>

param (
    [Parameter(Mandatory = $true)]
    [String[]]
    $vmIds
)

Set-StrictMode -Version 5.0
Import-Module -Name Hyper-V -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue
Set-Variable -Name VmRefreshValue -Option Constant -Value 0 -ErrorAction SilentlyContinue

<#

.SYNOPSIS
The main function.

.DESCRIPTION
Resume the virtual machines whose Ids are passed in and report the progress.

.PARAMETER vmIds
The list of VM Ids.

#>

function main([string[]]$vmIds) {
    $virtualMachineCount = 0
    $virtualMachineSuccesses = New-Object System.Collections.ArrayList
    $virtualMachineFailures = ""

    ForEach($vmId in $vmIds)
    {
        $percentComplete = $virtualMachineCount++/$vmIds.Count * 100

        $vm = Get-RBACVM -id $vmId -ErrorVariable getVmError -ErrorAction SilentlyContinue
        if ($getVmError)
        {
            $errorMessage = $getVmError[0].Exception.Message
            Write-Progress -PercentComplete $percentComplete -Activity ($errorMessage)
            $virtualMachineFailures += $errorMessage + " "
        }
        else
        {
            $vmName = $vm.Name

            Write-Progress -PercentComplete $percentComplete -Activity ($strings.ResumeVirtualMachineStartingMessage -f $vmName)

            Resume-vm $vm -ErrorVariable operationError -ErrorAction SilentlyContinue
            if ($operationError)
            {
                $errorMessage = $strings.ResumeVirtualMachineFailureMessage -f $vmName, $operationError[0].Exception.Message
                Write-Progress -PercentComplete $percentComplete -Activity ($errorMessage)
                $virtualMachineFailures += $errorMessage + " "
            } else 
            {
                Write-Progress -PercentComplete $percentComplete -Activity ($strings.ResumeVirtualMachineSuccessMessage -f $vmName)

                $virtualMachineSuccesses.Add($vmName) > $null
            }
        }
    }

    if (isBritannicaEnabled) {
        refreshVms
    }

    if ($virtualMachineFailures)
    {
        if ($virtualMachineSuccesses.Count -gt 0)
        {
            # Prepend success 
            $virtualMachineFailures = $strings.ResumeVirtualMachineOperationMessage -f ($virtualMachineSuccesses -join ", "), $virtualMachineFailures
        }

        throw $virtualMachineFailures
    }
}

<#

.SYNOPSIS
Determines if Britannica (sddc management resources) are available on the cluster

.DESCRIPTION

Use the existance of the cim namespace root/sddc/Management and class name to determine if Britannica
is supported or not.

#>
function isBritannicaEnabled() {
    return !!(Get-CimInstance -Namespace "root\SDDC\Management" -ClassName SDDC_VirtualMachine -ErrorAction SilentlyContinue)
}

<#

.SYNOPSIS
Refresh virtual machines match given $vmIds

.DESCRIPTION
Find vm match given $vmIds from Britannica, then force refresh them

#>
function refreshVms() {
    $vms = Get-CimInstance -Namespace "root\SDDC\Management" -ClassName SDDC_VirtualMachine | `
    Microsoft.PowerShell.Core\Where-Object {$_.Id.ToLower() -in $vmIds.ToLower()} -ErrorAction SilentlyContinue

    foreach ($vm in $vms) {
      refreshVm $vm
    }
}

<#

.SYNOPSIS
Refresh given virtual machine

.DESCRIPTION
Force refresh given virtual machine from Britannica

.Parameter vm
    The vm object to refresh
#>
function refreshVm($vm) {
    if ($vm) {
      Invoke-CimMethod -CimInstance $vm -MethodName "Refresh" -Arguments @{RefreshType=$VmRefreshValue} -ErrorVariable +err
    }
}

###############################################################################
# Script execution starts here
###############################################################################

main $vmIds

}
## [END] Resume-WACVMVirtualMachine ##
function Save-WACVMVirtualMachine {
<#

.SYNOPSIS
Saves the passed in virtual machines and stops it.

.DESCRIPTION
Saves the passed in virtual machines and stops it on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER vmIds
    The ids of the requested virtual machines.

#>

param (
    [Parameter(Mandatory = $true)]
    [String[]]
    $vmIds
)

Set-StrictMode -Version 5.0
Import-Module -Name Hyper-V -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue
Set-Variable -Name VmRefreshValue -Option Constant -Value 0 -ErrorAction SilentlyContinue

<#

.SYNOPSIS
The main function.

.DESCRIPTION
Save the virtual machines whose Ids are passed in and report the progress.

.PARAMETER vmIds
The list of VM Ids.

#>

function main([string[]]$vmIds) {
    $virtualMachineCount = 0
    $virtualMachineSuccesses = New-Object System.Collections.ArrayList
    $virtualMachineFailures = ""

    ForEach($vmId in $vmIds)
    {
        $percentComplete = $virtualMachineCount++/$vmIds.Count * 100

        $vm = Get-RBACVM -id $vmId -ErrorVariable getVmError -ErrorAction SilentlyContinue
        if ($getVmError)
        {
            $errorMessage = $getVmError[0].Exception.Message
            Write-Progress -PercentComplete $percentComplete -Activity ($errorMessage)
            $virtualMachineFailures += $errorMessage + " "
        }
        else
        {
            $vmName = $vm.Name

            Write-Progress -PercentComplete $percentComplete -Activity ($strings.SaveVirtualMachineStartingMessage -f $vmName)

            stop-vm -Save $vm -ErrorVariable operationError -ErrorAction SilentlyContinue
            if ($operationError)
            {
                $errorMessage = $strings.SaveVirtualMachineFailureMessage -f $vmName, $operationError[0].Exception.Message
                Write-Progress -PercentComplete $percentComplete -Activity ($errorMessage)
                $virtualMachineFailures += $errorMessage + " "
            } else 
            {
                Write-Progress -PercentComplete $percentComplete -Activity ($strings.SaveVirtualMachineSuccessMessage -f $vmName)

                $virtualMachineSuccesses.Add($vmName) > $null
            }
        }
    }

    if (isBritannicaEnabled) {
        refreshVms
    }
      
    if ($virtualMachineFailures)
    {
        if ($virtualMachineSuccesses.Count -gt 0)
        {
            # Prepend success 
            $virtualMachineFailures = $strings.SaveVirtualMachineOperationMessage -f ($virtualMachineSuccesses -join ", "), $virtualMachineFailures
        }

        throw $virtualMachineFailures
    }
}

<#

.SYNOPSIS
Determines if Britannica (sddc management resources) are available on the cluster

.DESCRIPTION

Use the existance of the cim namespace root/sddc/Management and class name to determine if Britannica
is supported or not.

#>
function isBritannicaEnabled() {
    return !!(Get-CimInstance -Namespace "root\SDDC\Management" -ClassName SDDC_VirtualMachine -ErrorAction SilentlyContinue)
}

<#

.SYNOPSIS
Refresh virtual machines match given $vmIds

.DESCRIPTION
Find vm match given $vmIds from Britannica, then force refresh them

#>
function refreshVms() {
    $vms = Get-CimInstance -Namespace "root\SDDC\Management" -ClassName SDDC_VirtualMachine | `
    Microsoft.PowerShell.Core\Where-Object {$_.Id.ToLower() -in $vmIds.ToLower()} -ErrorAction SilentlyContinue

    foreach ($vm in $vms) {
      refreshVm $vm
    }
}

<#

.SYNOPSIS
Refresh given virtual machine

.DESCRIPTION
Force refresh given virtual machine from Britannica

.Parameter vm
    The vm object to refresh
#>
function refreshVm($vm) {
    if ($vm) {
      Invoke-CimMethod -CimInstance $vm -MethodName "Refresh" -Arguments @{RefreshType=$VmRefreshValue} -ErrorVariable +err
    }
}

###############################################################################
# Script execution starts here
###############################################################################

main $vmIds

}
## [END] Save-WACVMVirtualMachine ##
function Set-WACVMHyperVClusterHostsGeneralSettings {
<#

.SYNOPSIS
Sets the Hyper-V Host General settings for all nodes of the cluster on this server.

.DESCRIPTION
Sets the Hyper-V Host General settings for all nodes of the cluster on this server.  The script
must be ran in a CredSSP enabled PowerShell session.

.ROLE
Hyper-V-Administrators

.PARAMETER virtualHardDiskPath
The new path to where this host should store the virtual hard disks

.PARAMETER virtualMachinePath
The new path to where this host should store virtual machines

.PARAMETER schedulerType
The new SMT scheduler type

#>

param (
    [Parameter(Mandatory = $false)]
    [AllowNull()][String]
    $virtualHardDiskPath,
    [Parameter(Mandatory = $false)]
    [AllowNull()][String]
    $virtualMachinePath,
    [Parameter(Mandatory = $false)]
    [AllowNull()][int]
    $schedulerType
    )

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue
Import-Module FailoverClusters -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Microsoft.FailoverClusters.PowerShell.ClusterNodeState

.DESCRIPTION
The state of a cluster node.

#>

enum ClusterNodeState {
    Up = 0
    Down = 1
    Paused = 2
    Joining = 3
    Unknown = -1
}

<#

.SYNOPSIS
HypervisorSchedulerType

.DESCRIPTION
The Hypervisor scheduler type that is in effect on this host server.

#>

enum HypervisorSchedulerType {
    Unknown = 0
    ClassicSmtDisabled = 1
    Classic = 2
    Core = 3
    Root = 4
}

<#

.SYNOPSIS
Setup the script runtime environment.

.DESCRIPTION
Setup the script runtime environment.

#>

function setupScriptEnv() {
    Set-Variable -Name HypervisorEventChannelName -Option ReadOnly -Value "Microsoft-Windows-Hyper-V-Hypervisor" -Scope Script
    Set-Variable -Name VirtualMachinePathPropertyName -Option ReadOnly -Value "VirtualMachinePath" -Scope Script
    Set-Variable -Name VirtualHardDiskPathPropertyName -Option ReadOnly -Value "VirtualHardDiskPath" -Scope Script
    Set-Variable -Name ClassicSmtDisabled -Option ReadOnly -Value "0x1" -Scope Script
    Set-Variable -Name Classic -Option ReadOnly -Value "0x2" -Scope Script
    Set-Variable -Name Core -Option ReadOnly -Value "0x3" -Scope Script
    Set-Variable -Name Root -Option ReadOnly -Value "0x4" -Scope Script
    Set-Variable -Name SchedulerTypePropertyName -Option ReadOnly -Value "schedulerType" -Scope Script
    Set-Variable -Name LegacyNetworkAdapter -Option ReadOnly -Value "LegacyNetworkAdapter" -Scope Script
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Set-HyperVClusterHostsGeneralSettings.ps1" -Scope Script
    Set-Variable -Name HyperVModuleName -Option ReadOnly -Value "Hyper-V" -Scope Script
    Set-Variable -Name FailoverClustersModuleName -Option ReadOnly -Value "FailoverClusters" -Scope Script
}

<#

.SYNOPSIS
Cleanup the script runtime environment.

.DESCRIPTION
Cleanup the script runtime environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name HypervisorEventChannelName -Scope Script -Force
    Remove-Variable -Name VirtualMachinePathPropertyName -Scope Script -Force
    Remove-Variable -Name VirtualHardDiskPathPropertyName -Scope Script -Force
    Remove-Variable -Name ClassicSmtDisabled -Scope Script -Force
    Remove-Variable -Name Classic -Scope Script -Force
    Remove-Variable -Name Core -Scope Script -Force
    Remove-Variable -Name Root -Scope Script -Force
    Remove-Variable -Name SchedulerTypePropertyName -Scope Script -Force
    Remove-Variable -Name LegacyNetworkAdapter -Scope Script -Force
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name HyperVModuleName -Scope Script -Force
    Remove-Variable -Name FailoverClustersModuleName -Scope Script -Force
}

<#

.SYNOPSIS
Get the fully qualified domain name for the passed in server name from DNS.

.DESCRIPTION
Get the fully qualified domain name for the passed in server name from DNS.

#>

function GetServerFqdn([string]$netBIOSName) {
    return ([System.Net.DNS]::GetHostByName($netBIOSName).HostName)
}

<#

.SYNOPSIS
Get the Hypervisor scheduler type for this server.

.DESCRIPTION
Convert the event string value into an enum that is the current Hypervisor scheduler type.

The message looks like this:

 "Hypervisor scheduler type is 0x1."

 Since the hex value is all we care about this localized message should not be a problem...

#>

function getSchedulerType {
    $event = Get-WinEvent -FilterHashTable @{ProviderName=$HypervisorEventChannelName; ID=2} -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object -First 1 Message

    # $event.message may not exist on downlevel servers
    if ($null -ne $event -AND $null -ne $event.message) {
        if ($event.message -match $ClassicSmtDisabled) {
            return [HypervisorSchedulerType]::ClassicSmtDisabled
        }

        if ($event.message -match $Classic) {
            return [HypervisorSchedulerType]::Classic
        }

        if ($event.message -match $Core) {
            return [HypervisorSchedulerType]::Core
        }

        if ($event.message -match $Root) {
            return [HypervisorSchedulerType]::Root
        }
    }

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Warning `
    -Message "[$ScriptName]: Unable to determine the Hypervisor scheduler type." -ErrorAction SilentlyContinue

    return [HypervisorSchedulerType]::Unknown
}

<#

.SYNOPSIS
Get the Hyper-V host settings for this server.

.DESCRIPTION
Get the current Hyper-V host settings and return them.

.PARAMETER schedulerType
The SMT scheduler type to return.  Could be the new one that was set, but not in affect pending a reboot,
or the current scheduler type.

#>

function getHostSettings([HypervisorSchedulerType]$schedulerType) {
    return Get-VMHost | Microsoft.PowerShell.Utility\Select-Object `
        $VirtualHardDiskPathPropertyName, `
        $VirtualMachinePathPropertyName, `
        @{Name=$SchedulerTypePropertyName; Expression={$schedulerType}}
}

<#

.SYNOPSIS
Set the Hyper-V host path settings.

.DESCRIPTION
Set the optional path settings for this Hyper-V host.  This is an advanced
function and must so remain.

.PARAMETER virtualHardDiskPath
The new path to where this host should store the virtual hard disks.

.PARAMETER virtualMachinePath
The new path to where this host should store virtual machines.

#>

function Set-HostSettings {
    [CmdletBinding()]
    Param (
        [string]$virtualHardDiskPath,
        [string]$virtualMachinePath
    )

    Set-Variable -Name VirtualMachinePathPropertyName -Option ReadOnly -Value "VirtualMachinePath" -Scope Local
    Set-Variable -Name VirtualHardDiskPathPropertyName -Option Constant -Value "VirtualHardDiskPath" -Scope Local

    $args = @{}

    if ($virtualHardDiskPath) {
        $args += @{$VirtualMachinePathPropertyName = $virtualHardDiskPath};
    }

    if ($virtualMachinePath) {
        $args += @{$VirtualHardDiskPathPropertyName = $virtualMachinePath};
    }

    if ($args.Count -gt 0) {
        Set-VMHost @args
    }
}

<#

.SYNOPSIS
Set the new scheduler type for this host server.

.DESCRIPTION
Set the SMT scheduler type for this host system.  This is an advanced
function and must so remain.

.PARAMETER schedulerType
The new SMT scheduler type to set.

#>

function Set-SchedulerType {
    [CmdletBinding()]
    param(
        [int]$schedulerType,
        [string]$hypervisorSchedulerTypeNotSupported
    )

    Set-Variable -Name BcdEditCommand -Option ReadOnly -Value "bcdedit.exe" -Scope Local
    Set-Variable -Name BcdEditArguments -Option ReadOnly -Value "/set hypervisorschedulertype {0}" -Scope Local
    Set-Variable -Name System32 -Option ReadOnly -Value "System32" -Scope Local
    Set-Variable -Name Server2016BuildNumber -Option ReadOnly -Value 14393 -Scope Local
    Set-Variable -Name CoreSchedulerArgumentName -Option ReadOnly -Value "Core" -Scope Local
    Set-Variable -Name ClassicSchedulerArgumentName -Option ReadOnly -Value "Classic" -Scope Local
    Set-Variable -Name SchedulerTypeCore -Option ReadOnly -Value 3 -Scope Local

    $build = [System.Environment]::OSVersion.Version.Build

    # If the server version is not greater than Windows Server 2016 then we cannot
    # set the scheduler type.
    if (-not ($build -ge $Server2016BuildNumber)) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Cannot set the Hypervisor scheduler type on Windows Servers less than Windows Server 2106." -ErrorAction SilentlyContinue

        Write-Error $hypervisorSchedulerTypeNotSupported

        return
    }

    [string] $argument = if ($schedulerType -eq $SchedulerTypeCore) {$CoreSchedulerArgumentName} else {$ClassicSchedulerArgumentName}
    $arguments = $bcdEditArguments -f $argument
    $command = "{0}\{1}\{2}" -f $env:WINDIR, $System32, $BcdEditCommand

    $output = Invoke-Expression "& $command $arguments" -ErrorAction SilentlyContinue

    if ($LastExitCode -ne 0) {
        Write-Error $output[0]

        return
    }
}

<#

.SYNOPSIS
Main

.DESCRIPTION
An explicit main function to save the settings.

.PARAMETER virtualHardDiskPath
The new path to where this host should store the virtual hard disks.

.PARAMETER virtualMachinePath
The new path to where this host should store virtual machines.

.PARAMETER schedulerType
The new SMT scheduler type

#>

function main(
    [AllowNull()][string]$virtualHardDiskPath,
    [AllowNull()][string]$virtualMachinePath,
    [AllowNull()][int]$schedulerType
) {
    $err = $null
    
    $cluster = Get-Cluster -ErrorAction SilentlyContinue -ErrorVariable +err
    if (-not($cluster) -or $err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: A cluster was not found on this server. Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return @{}
    }
    
    $clusterNodes = $cluster | Get-ClusterNode -ErrorAction SilentlyContinue -ErrorVariable +err
    if (-not($clusterNodes) -or $err) {
        $clusterName = $cluster.Name

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Counld not get the nodes cluster of cluster $clusterName. Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return @{}
    }

    $servers = @("LocalHost")
    $thisServer = $env:computername

    foreach($clusterNode in $clusterNodes) {
        $serverName = GetServerFqdn $clusterNode.Name

        # Skip this node since it was already add as "LocalHost"
        if ($thisServer -eq $clusterNode.Name) {
            continue
        }

        if ($clusterNode.state -eq [ClusterNodeState]::Up) {
            $servers += $serverName
        } else {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Hyper-V Host Settings could not be saved to cluster node $serverName because the cluster node is not running." -ErrorAction SilentlyContinue
        }
    }

    $output = Invoke-Command -ScriptBlock ${function:Set-HostSettings} -ComputerName $servers `
        -ArgumentList $virtualHardDiskPath, $virtualMachinePath -ErrorAction SilentlyContinue -ErrorVariable +err

    if ($err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Hyper-V Host Settings paths could not be saved to the cluster nodes. Error: $err" -ErrorAction SilentlyContinue

        foreach($e in @($err)) {
            Write-Error $e
        }
    }

    $output = Invoke-Command -ScriptBlock ${function:Set-SchedulerType} -ComputerName $servers `
        -ArgumentList $schedulerType, $strings.HypervisorSchedulerTypeNotSupported -ErrorAction SilentlyContinue -ErrorVariable +err

    if ($err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Hyper-V Host Settings scheduler type could not be saved to the cluster nodes. Error: $err" -ErrorAction SilentlyContinue

        foreach($e in @($err)) {
            Write-Error $e
        }
    }

    # Return the host settings model from this server.
    return getHostSettings (getSchedulerType)
}

###############################################################################
# Script execution starts here...
###############################################################################

if (-not ($env:pester)) {
    setupScriptEnv

    try {
        $failedModuleName = $null

        Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

        $module = Get-Module -Name $HyperVModuleName -ErrorAction SilentlyContinue -ErrorVariable +err
        if ($module) {
            $module = Get-Module -Name $FailoverClustersModuleName -ErrorAction SilentlyContinue -ErrorVariable +err
            if ($module) {
                return main $virtualHardDiskPath $virtualMachinePath $schedulerType
            } else {
                $failedModuleName = $FailoverClustersModuleName
            }
        } else {
            $failedModuleName = $HyperVModuleName
        }

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: The required PowerShell module ($failedModuleName) was not found." -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return @{}
    } finally {
        cleanupScriptEnv
    }
}

}
## [END] Set-WACVMHyperVClusterHostsGeneralSettings ##
function Set-WACVMHyperVEnhancedSessionModeSettings {
<#

.SYNOPSIS
Sets a computer's Hyper-V Host Enhanced Session Mode settings.

.DESCRIPTION
Sets a computer's Hyper-V Host Enhanced Session Mode settings.

.ROLE
Hyper-V-Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [bool]
    $enableEnhancedSessionMode
    )

Set-StrictMode -Version 5.0
Import-Module Hyper-V

# Create arguments
$args = @{'EnableEnhancedSessionMode' = $enableEnhancedSessionMode};

Set-VMHost @args

Get-VMHost | Microsoft.PowerShell.Utility\Select-Object `
    EnableEnhancedSessionMode

}
## [END] Set-WACVMHyperVEnhancedSessionModeSettings ##
function Set-WACVMHyperVHostGeneralSettings {
<#

.SYNOPSIS
Sets a computer's Hyper-V Host General settings.

.DESCRIPTION
Sets a computer's Hyper-V Host General settings.

.ROLE
Hyper-V-Administrators

.PARAMETER virtualHardDiskPath
The new path to where this host should store the virtual hard disks

.PARAMETER virtualMachinePath
The new path to where this host should store virtual machines

.PARAMETER schedulerType
The new SMT scheduler type

.PARAMETER rebootConfirmed
The user has consented to performing a server reboot.

#>

param (
    [Parameter(Mandatory = $false)]
    [AllowNull()][String]
    $virtualHardDiskPath,
    [Parameter(Mandatory = $false)]
    [AllowNull()][String]
    $virtualMachinePath,
    [Parameter(Mandatory = $false)]
    [AllowNull()][int]
    $schedulerType,
    [Parameter(Mandatory = $false)]
    [AllowNull()][bool]
    $rebootConfirmed
    )

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

<#

.SYNOPSIS
WindowsServerVersion

.DESCRIPTION
This enum is used for various Windows Server versions.

#>
enum WindowsServerVersion
{
    Unknown
    Server2008R2
    Server2012
    Server2012R2
    Server2016
    Server2019
}

<#

.SYNOPSIS
HypervisorSchedulerType

.DESCRIPTION
The Hypervisor scheduler type that is in effect on this host server.

#>

enum HypervisorSchedulerType {
    Unknown = 0
    ClassicSmtDisabled = 1
    Classic = 2
    Core = 3
    Root = 4
}

###############################################################################
# Constants
###############################################################################

Set-Variable -Name HypervisorEventChannelName -Option Constant -Value "Microsoft-Windows-Hyper-V-Hypervisor" -ErrorAction SilentlyContinue
Set-Variable -Name VirtualMachinePathPropertyName -Option Constant -Value "VirtualMachinePath" -ErrorAction SilentlyContinue
Set-Variable -Name VirtualHardDiskPathPropertyName -Option Constant -Value "VirtualHardDiskPath" -ErrorAction SilentlyContinue
Set-Variable -Name ClassicSmtDisabled -Option Constant -Value "0x1" -ErrorAction SilentlyContinue
Set-Variable -Name Classic -Option Constant -Value "0x2" -ErrorAction SilentlyContinue
Set-Variable -Name Core -Option Constant -Value "0x3" -ErrorAction SilentlyContinue
Set-Variable -Name Root -Option Constant -Value "0x4" -ErrorAction SilentlyContinue
Set-Variable -Name SchedulerTypePropertyName -Option Constant -Value "schedulerType" -ErrorAction SilentlyContinue
Set-Variable -Name CoreSchedulerArgumentName -Option Constant -Value "Core" -ErrorAction SilentlyContinue
Set-Variable -Name ClassicSchedulerArgumentName -Option Constant -Value "Classic" -ErrorAction SilentlyContinue
Set-Variable -Name Server2008R2BuildNumber -Option Constant -Value 7600 -ErrorAction SilentlyContinue
Set-Variable -Name Server2012BuildNumber -Option Constant -Value 9200 -ErrorAction SilentlyContinue
Set-Variable -Name Server2012R2BuildNumber -Option Constant -Value 9600 -ErrorAction SilentlyContinue
Set-Variable -Name Server2016BuildNumber -Option Constant -Value 14393 -ErrorAction SilentlyContinue
Set-Variable -Name Server2019BuildNumber -Option Constant -Value 17763  -ErrorAction SilentlyContinue
Set-Variable -Name BcdEditCommand -Option Constant -Value "bcdedit.exe" -ErrorAction SilentlyContinue
Set-Variable -Name BcdEditArguments -Option Constant -Value "/set hypervisorschedulertype {0}" -ErrorAction SilentlyContinue
Set-Variable -Name System32 -Option Constant -Value "System32" -ErrorAction SilentlyContinue
Set-Variable -Name LegacyNetworkAdapter -Option Constant -Value "LegacyNetworkAdapter" -ErrorAction SilentlyContinue
Set-Variable -Name LogName -Option Constant -Value "Microsoft-ServerManagementExperience" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SMEScripts" -ErrorAction SilentlyContinue
Set-Variable -Name ScriptName -Option Constant -Value "Set-HyperVHostGeneralSettings.ps1" -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Get the the build number for the OS installed on this server.

.DESCRIPTION
Get the the build number for the OS installed on this server.

#>

function getBuildNumber {
    return [System.Environment]::OSVersion.Version.Build
}

<#

.SYNOPSIS
Get the Windows Server version for the OS installed on this server.

.DESCRIPTION
Get the Windows Server version for the OS installed on this server.

#>

function getServerVersion {
    $build = getBuildNumber

    if ($build -eq $Server2008R2BuildNumber) {
        return [WindowsServerVersion]::Server2008R2
    }

    if ($build -eq $Server2012BuildNumber) {
        return [WindowsServerVersion]::Server2012
    }

    if ($build -eq $Server2012R2BuildNumber) {
        return [WindowsServerVersion]::Server2012R2
    }

    if ($build -eq $Server2016BuildNumber) {
        return [WindowsServerVersion]::Server2016
    }

    #TODO: This isn't right.  Need to update with 2019 build number once known.
    if ($build -ge $Server2019BuildNumber) {
        return [WindowsServerVersion]::Server2019
    }

    return [WindowsServerVersion]::Unknown
}

<#

.SYNOPSIS
Get the Hypervisor scheduler type for this server.

.DESCRIPTION
Convert the event string value into an enum that is the current Hypervisor scheduler type.

The message looks like this:

 "Hypervisor scheduler type is 0x1."

 Since the hex value is all we care about this localized message should not be a problem...

#>

function getSchedulerType {
    $event = Get-WinEvent -FilterHashTable @{ProviderName=$HypervisorEventChannelName; ID=2} -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object -First 1 Message

    # $event.message may not exist on downlevel servers
    if ($null -ne $event -AND $null -ne $event.message) {
        if ($event.message -match $ClassicSmtDisabled) {
            return [HypervisorSchedulerType]::ClassicSmtDisabled
        }

        if ($event.message -match $Classic) {
            return [HypervisorSchedulerType]::Classic
        }

        if ($event.message -match $Core) {
            return [HypervisorSchedulerType]::Core
        }

        if ($event.message -match $Root) {
            return [HypervisorSchedulerType]::Root
        }
    }

    return [HypervisorSchedulerType]::Unknown
}

<#

.SYNOPSIS
Set the Hyper-V host path settings.

.DESCRIPTION
Set the optional path settings for this Hyper-V host.

.PARAMETER virtualHardDiskPath
The new path to where this host should store the virtual hard disks.

.PARAMETER virtualMachinePath
The new path to where this host should store virtual machines.

#>

function setHostSettings([AllowNull()][string]$virtualHardDiskPath, [AllowNull()][string]$virtualMachinePath) {
    $args = @{}

    if ($virtualHardDiskPath) {
        $args += @{'VirtualHardDiskPath' = $virtualHardDiskPath};
    }

    if ($virtualMachinePath) {
        $args += @{'VirtualMachinePath' = $virtualMachinePath};
    }

    if ($args.Count -gt 0) {
        Set-VMHost @args
    }
}

<#

.SYNOPSIS
Get the Hyper-V host settings for this server.

.DESCRIPTION
Get the current Hyper-V host settings and return them.

.PARAMETER schedulerType
The SMT scheduler type to return.  Could be the new one that was set, but not in affect pending a reboot,
or the current scheduler type.

#>

function getHostSettings([HypervisorSchedulerType]$schedulerType) {
    return Get-VMHost | Microsoft.PowerShell.Utility\Select-Object `
        $VirtualHardDiskPathPropertyName, `
        $VirtualMachinePathPropertyName, `
        @{N=$SchedulerTypePropertyName; E={$schedulerType}}
}

<#

.SYNOPSIS
Set the new scheduler type for this host server.

.DESCRIPTION
Set the SMT scheduler type for this host system.

.PARAMETER schedulerType
The new SMT scheduler type to set.

.PARAMETER rebootConfirmed
The user has consented to performing a server reboot.

#>

function setSchedulerType([HypervisorSchedulerType]$schedulerType, [bool]$rebootConfirmed) {
    $serverVersion = getServerVersion

    # If the server version is not greater than Windows Server 2016 then we cannot
    # set the scheduler type.
    if (-not ($serverVersion -ge [WindowsServerVersion]::Server2016)) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Cannot set the Hypervisor scheduler type on Windows Servers less than Windows Server 2106." -ErrorAction SilentlyContinue

        Write-Error $strings.HypervisorSchedulerTypeNotSupported

        return
    }

    [string] $argument = if ($schedulerType -eq [HypervisorSchedulerType]::Core) {$CoreSchedulerArgumentName} else {$ClassicSchedulerArgumentName}
    $arguments = $bcdEditArguments -f $argument
    $command = "{0}\{1}\{2}" -f $env:WINDIR, $System32, $BcdEditCommand

    $output = Invoke-Expression "& $command $arguments" -ErrorAction SilentlyContinue

    if ($LastExitCode -ne 0) {
        Write-Error $output[0]

        return
    }

    if ($rebootConfirmed) {
        Restart-Computer -Force
    }
}

<#

.SYNOPSIS
Main

.DESCRIPTION
An explicit main function to fetch the settings.

.PARAMETER virtualHardDiskPath
The new path to where this host should store the virtual hard disks.

.PARAMETER virtualMachinePath
The new path to where this host should store virtual machines.

.PARAMETER schedulerType
The new SMT scheduler type.

.PARAMETER rebootConfirmed
The user has consented to performing a server reboot.

#>

function main(
    [AllowNull()][string]$virtualHardDiskPath,
    [AllowNull()][string]$virtualMachinePath,
    [AllowNull()][HypervisorSchedulerType]$schedulerType,
    [AllowNull()][bool]$rebootConfirmed) {
    setHostSettings $virtualHardDiskPath $virtualMachinePath

    $currentSchedulerType = getSchedulerType

    if ($schedulerType) {
        if ($schedulerType -ne $currentSchedulerType) {
            setSchedulerType $schedulerType $rebootConfirmed $rebootConfirmed

            return getHostSettings $schedulerType
        }
    }

    return getHostSettings $currentSchedulerType
}

###############################################################################
# Script execution starts here...
###############################################################################

if (-not ($env:pester)) {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    $module = Get-Module -Name Hyper-V -ErrorAction SilentlyContinue
    if ($module) {
        return main $virtualHardDiskPath $virtualMachinePath $schedulerType $rebootConfirmed
    }
}

return $null
}
## [END] Set-WACVMHyperVHostGeneralSettings ##
function Set-WACVMHyperVHostLiveMigrationSettings {
<#

.SYNOPSIS
Sets a computer's Hyper-V Host Live Migration settings.

.DESCRIPTION
Sets a computer's Hyper-V Host Live Migration settings.

.ROLE
Hyper-V-Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [bool]
    $virtualMachineMigrationEnabled,
    [Parameter(Mandatory = $true)]
    [int]
    $maximumVirtualMachineMigrations,
    [Parameter(Mandatory = $true)]
    [int]
    $virtualMachineMigrationPerformanceOption,
    [Parameter(Mandatory = $true)]
    [int]
    $virtualMachineMigrationAuthenticationType,
    [Parameter(Mandatory = $true)]
    [bool]
    $useAnyNetworkForMigration
    )

Set-StrictMode -Version 5.0

Import-Module Hyper-V -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.  Create read only (constant) variables
that add context to the said constants.

#>

function setupScriptEnv() {
##SkipCheck=true##
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Set-HyperVHostLiveMigrationSettings.ps1" -Scope Script
    Set-Variable -Name MaximumVirtualMachineMigrationsArgumentName -Option ReadOnly -Value "MaximumVirtualMachineMigrations" -Scope Script
    Set-Variable -Name VirtualMachineMigrationAuthenticationTypeArgumentName -Option ReadOnly -Value "VirtualMachineMigrationAuthenticationType" -Scope Script
    Set-Variable -Name UseAnyNetworkForMigrationArgumentName -Option ReadOnly -Value "UseAnyNetworkForMigration" -Scope Script
    Set-Variable -Name VirtualMachineMigrationPerformanceOptionArgumentName -Option ReadOnly -Value "VirtualMachineMigrationPerformanceOption" -Scope Script
    Set-Variable -Name VirtualMachineMigrationEnabledPropertyName -Option ReadOnly -Value "VirtualMachineMigrationEnabled" -Scope Script
##SkipCheck=false##
}

<#

.SYNOPSIS
Cleanup the script environment.

.DESCRIPTION
Cleanup the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name MaximumVirtualMachineMigrationsArgumentName -Scope Script -Force
    Remove-Variable -Name VirtualMachineMigrationAuthenticationTypeArgumentName -Scope Script -Force
    Remove-Variable -Name UseAnyNetworkForMigrationArgumentName -Scope Script -Force
    Remove-Variable -Name VirtualMachineMigrationPerformanceOptionArgumentName -Scope Script -Force
    Remove-Variable -Name VirtualMachineMigrationEnabledPropertyName -Scope Script -Force
}    

function main(
    [bool] $virtualMachineMigrationEnabled,
    [int] $maximumVirtualMachineMigrations,
    [int] $virtualMachineMigrationPerformanceOption,
    [int] $virtualMachineMigrationAuthenticationType,
    [bool] $useAnyNetworkForMigration
) {
    if ($virtualMachineMigrationEnabled) {
        $isServer2012 = [Environment]::OSVersion.Version.Major -eq 6 -and [Environment]::OSVersion.Version.Minor -eq 2;
        
        Enable-VMMigration -ErrorAction SilentlyContinue -ErrorVariable +err

        if ($err) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: There was an error enabling live migration.  Error: $err" -ErrorAction SilentlyContinue

            Write-Error @($err)[0]

            return @{}
        }

        # Create arguments
        $args = @{
            $MaximumVirtualMachineMigrationsArgumentName = $maximumVirtualMachineMigrations;
            $VirtualMachineMigrationAuthenticationTypeArgumentName = $virtualMachineMigrationAuthenticationType;
            $UseAnyNetworkForMigrationArgumentName = $useAnyNetworkForMigration;
        }

        if (!$isServer2012) {
            $args += @{ $VirtualMachineMigrationPerformanceOptionArgumentName = $virtualMachineMigrationPerformanceOption; }
        }

        Set-VMHost @args -ErrorAction SilentlyContinue -ErrorVariable +err

        if ($err) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: There was an error saving the VM Host settings.  Error: $err" -ErrorAction SilentlyContinue

            Write-Error @($err)[0]
            
            return @{}
        }
    } else {
        Disable-VMMigration -ErrorAction SilentlyContinue -ErrorVariable +err

        if ($err) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: There was an error disabling live migration.  Error: $err" -ErrorAction SilentlyContinue

            Write-Error @($err)[0]

            return @{}
        }
    }

    return Get-VMHost | Microsoft.PowerShell.Utility\Select-Object `
        $MaximumVirtualMachineMigrationsArgumentName, `
        $VirtualMachineMigrationAuthenticationTypeArgumentName, `
        $VirtualMachineMigrationEnabledPropertyName, `
        $VirtualMachineMigrationPerformanceOptionArgumentName,
        $UseAnyNetworkForMigrationArgumentName
}

###############################################################################
# Script execution starts here
###############################################################################

if (-not ($env:pester)) {
    setupScriptEnv

    try {
        Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

        $hyperVModule = Get-Module -Name Hyper-V -ErrorAction SilentlyContinue

        if (-not($hyperVModule)) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: The required PowerShell module (Hyper-V) was not found." -ErrorAction SilentlyContinue
        
            Write-Error $strings.HyperVModuleRequired
            
            return @{}
        }

        return main $virtualMachineMigrationEnabled $maximumVirtualMachineMigrations $virtualMachineMigrationPerformanceOption `
            $virtualMachineMigrationAuthenticationType $useAnyNetworkForMigration
    
    } finally {
        cleanupScriptEnv
    }
}

}
## [END] Set-WACVMHyperVHostLiveMigrationSettings ##
function Set-WACVMHyperVHostNumaSpanningSettings {
<#

.SYNOPSIS
Sets a computer's Hyper-V Host settings.

.DESCRIPTION
Sets a computer's Hyper-V Host settings.

.ROLE
Hyper-V-Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [bool]
    $numaSpanningEnabled
    )

Set-StrictMode -Version 5.0
Import-Module Hyper-V

# Create arguments
$args = @{'NumaSpanningEnabled' = $numaSpanningEnabled};

Set-VMHost @args

Get-VMHost | Microsoft.PowerShell.Utility\Select-Object `
    NumaSpanningEnabled

}
## [END] Set-WACVMHyperVHostNumaSpanningSettings ##
function Set-WACVMHyperVHostStorageMigrationSettings {
<#

.SYNOPSIS
Sets a computer's Hyper-V Host Storage Migration settings.

.DESCRIPTION
Sets a computer's Hyper-V Host Storage Migrtion settings.

.ROLE
Hyper-V-Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [int]
    $maximumStorageMigrations
    )

Set-StrictMode -Version 5.0
Import-Module Hyper-V

# Create arguments
$args = @{'MaximumStorageMigrations' = $maximumStorageMigrations; };

Set-VMHost @args

Get-VMHost | Microsoft.PowerShell.Utility\Select-Object `
    MaximumStorageMigrations

}
## [END] Set-WACVMHyperVHostStorageMigrationSettings ##
function Set-WACVMNetworkInterfaces {
<#

.SYNOPSIS
Sets the network interface settings for the passed in virtual machine.

.DESCRIPTION
Sets the network interface settings for the passed in adapter objects.

.ROLE
Hyper-V-Administrators

.PARAMETER vmId
    The Id of the requested virtual machine.

.PARAMETER vmName
    The Name of the requested virtual machine.

.PARAMETER adaptersToCreate
    Optional array of virtual network adapters to add tothe passed in virtual machine.

.PARAMETER adaptersToEdit
    Optional array of virtual network adapters to change on the passed in virtual machine.

.PARAMETER ncUri
    NC uri used for SDN connections.

.PARAMETER useSecurityTags
    Indicates whether security tags should be attempted to be added to nic properties

.PARAMETER useDefaultNetworkPolicies
    Indicates whether the cluster is using DNP, and if DNP conventions should be used for things like port profiles

.PARAMETER newAdapterIds
    The list of IDs of newly created VM Network Adapters - these correspond to the adaptersToCreate 1:1

.PARAMETER editPNics
    The list of objects with information about the physical adapters - these correspond to the adaptersToEdit 1:1

#>

param (
  [Parameter(Mandatory = $true)]
  [string]
  $vmId,
  [Parameter(Mandatory = $false)]
  [string]
  $vmName,
  [Parameter(Mandatory = $false)]
  [ValidateNotNull()]
  [object[]]
  $adaptersToCreate = @(),
  [Parameter(Mandatory = $false)]
  [ValidateNotNull()]
  [object[]]
  $adaptersToEdit = @(),
  [Parameter(Mandatory = $true)]
  [string]
  $ncUri,
  [Parameter(Mandatory = $false)]
  [boolean]
  $useSecurityTags = $false,
  [Parameter(Mandatory = $false)]
  [boolean]
  $useDefaultNetworkPolicies = $false,
  [Parameter(Mandatory = $false)]
  [string[]]
  $newAdapterIds,
  [Parameter(Mandatory = $false)]
  [object[]]
  $editPNics
)

<#

.SYNOPSIS
Types of SDN network connections

.DESCRIPTION
This enum is used to determine what type of SDN connection we are creating.

#>
enum SdnNetworkType {
  None = 0
  Vlan = 1
  Vnet = 2
  Lnet = 3
}

Import-Module NetworkController -ErrorAction SilentlyContinue

Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option ReadOnly -Value "SMEGateway" -Scope Script -ErrorAction SilentlyContinue
Set-Variable -Name ScriptName -Option ReadOnly -Value "Set-NetworkInterfaces.ps1" -Scope Script -ErrorAction SilentlyContinue
Set-Variable -Name PortProfileFeatureId -Option ReadOnly -Value "9940cd46-8b06-43bb-b9d5-93d50381fd56" -Scope Script -ErrorAction SilentlyContinue
Set-Variable -Name PortProfileNetCfgInstanceId -Option ReadOnly -Value "{56785678-a0e5-4a26-bc9b-c0cba27311a3}" -Scope Script -ErrorAction SilentlyContinue
Set-Variable -Name NetworkControllerVendorId -Option ReadOnly -Value "{1FA41B39-B444-4E43-B35A-E1F7985FD548}" -Scope Script -ErrorAction SilentlyContinue
Set-Variable -Name NetworkControllerVendorName -Option ReadOnly -Value "NetworkController" -Scope Script -ErrorAction SilentlyContinue
Set-Variable -Name NetworkControllerCdnLabelName -Option ReadOnly -Value "TestCdn" -Scope Script -ErrorAction SilentlyContinue
Set-Variable -Name NetworkControllerCdnLabelId -Option ReadOnly -Value 1111 -Scope Script -ErrorAction SilentlyContinue
Set-Variable -Name NetworkControllerProfileName -Option ReadOnly -Value "Testprofile" -Scope Script -ErrorAction SilentlyContinue
Set-Variable -Name PortProfileSDNNetwork -Option ReadOnly -Value 1 -Scope Script -ErrorAction SilentlyContinue
Set-Variable -Name PortProfileVlan -Option ReadOnly -Value 2 -Scope Script -ErrorAction SilentlyContinue
Set-Variable -Name PortProfileUntaggedLnet -Option ReadOnly -Value 6 -Scope Script -ErrorAction SilentlyContinue
Set-Variable -Name DefaultMac -Option ReadOnly -Value "000000000000" -Scope Script -ErrorAction SilentlyContinue
Set-Variable -Name IPAllocationDynamic -Option ReadOnly -Value "Dynamic" -Scope Script -ErrorAction SilentlyContinue
Set-Variable -Name IPAllocationStatic -Option ReadOnly -Value "Static" -Scope Script -ErrorAction SilentlyContinue
Set-Variable -Name IPAllocationUnmanaged -Option ReadOnly -Value "Unmanaged" -Scope Script -ErrorAction SilentlyContinue
Set-Variable -Name SleepSeconds -Option ReadOnly -Value 2 -Scope Script -ErrorAction SilentlyContinue

function cleanupScriptEnv() {
  Remove-Variable -Name LogName -Scope Script -Force
  Remove-Variable -Name LogSource -Scope Script -Force
  Remove-Variable -Name ScriptName -Scope Script -Force
  Remove-Variable -Name PortProfileFeatureId -Scope Script -Force
  Remove-Variable -Name PortProfileNetCfgInstanceId -Scope Script -Force
  Remove-Variable -Name NetworkControllerVendorId -Scope Script -Force
  Remove-Variable -Name NetworkControllerVendorName -Scope Script -Force
  Remove-Variable -Name NetworkControllerCdnLabelName -Scope Script -Force
  Remove-Variable -Name NetworkControllerCdnLabelId -Scope Script -Force
  Remove-Variable -Name NetworkControllerProfileName -Scope Script -Force
  Remove-Variable -Name PortProfileSDNNetwork -Scope Script -Force
  Remove-Variable -Name PortProfileVlan -Scope Script -Force
  Remove-Variable -Name PortProfileUntaggedLnet -Scope Script -Force
  Remove-Variable -Name DefaultMac -Scope Script -Force
  Remove-Variable -Name IPAllocationDynamic -Scope Script -Force
  Remove-Variable -Name IPAllocationStatic -Scope Script -Force
  Remove-Variable -Name IPAllocationUnmanaged -Scope Script -Force
  Remove-Variable -Name SleepSeconds -Scope Script -Force
}

# SDN function used to generate a new, unused resource ID.
function generateUnusedResourceId($vmName) {
  $count = 0
  $baseValue = "$($vmName)_Net_Adapter".Replace(' ', '_')
  $existingResources = $script:ncNics
  $newResourceId = "$($baseValue)_$($count)"

  while ($null -ne ($existingResources | Where-Object { $_.ResourceId -ieq $newResourceId })) {
    $newResourceId = "$($baseValue)_$($count)"
    $count += 1
  }

  return $newResourceId
}

function setSecurityTagsIfAvailable($securityTags, $nicProps) {
  if ($useSecurityTags) {
    $nicProps.SecurityTags = @()
    if ($null -ne $securityTags) {
      foreach ($tag in $securityTags) {
        $newTag = New-Object Microsoft.Windows.NetworkController.SecurityTag -Property @{ResourceRef = $tag.resourceRef }
        $nicProps.SecurityTags += $newTag
      }
    }
  }

  return $nicProps
}

function sdnGetLogicalSubnet($adapterSettings) {
  if (-not (($null -ne $adapterSettings.sdnOptions) -and ($adapterSettings.sdnOptions.sdnNetworkType -eq [SdnNetworkType]::Lnet))) {
    return $null
  }
  $splitLsubnet = $adapterSettings.sdnOptions.logicalSubnet.ResourceRef -split '/'

  $lsubnet = Get-NetworkControllerLogicalSubnet -ConnectionUri $ncUri -ResourceId $splitLsubnet[4] -LogicalNetworkId $splitLsubnet[2]
  return $lSubnet
}

function LnetVlanValue($adapter) {
  $lSubnet = sdnGetLogicalSubnet -adapter $adapter
  if ($null -eq $lSubnet) {
    return $null
  }
  return $lSubnet.properties.vlanId
}

function isUnmanagedLnet($adapter) {
  $lSubnet = sdnGetLogicalSubnet -adapter $adapter
  if ($null -eq $lSubnet) {
    return $false
  }
  return ($null -eq $lsubnet.Properties.AddressPrefix -or "" -eq $lsubnet.Properties.AddressPrefix)
}

function resolvePnicToNcNic(
  [string] $adapterId,
  [string] $profileId,
  [string] $macAddress
) {
  $ncNic = $null

  foreach ($nic in $script:ncNics) {
    if ("{$($nic.InstanceId)}" -eq $profileId) {
      $ncNic = $nic
      break
    }

    if ($macAddress -ne $DefaultMac -and $nic.Properties.psobject.properties.name -contains "PrivateMacAddress" -and $nic.Properties.PrivateMacAddress -eq $macAddress) {
      $ncNic = $nic
      break
    }

    $tags = $nic.Tags
    if ($null -ne $tags -and $tags.psobject.properties.name -contains "adapterId" -and $nic.Tags.adapterId.ToLower() -eq $adapterId.ToLower()) {
      $ncNic = $nic
      break
    }
  }

  $ncNic
}

# create a new NC nic
# returns the mac address, instance id of the nic.
function createNetworkControllerNetworkInterface($adapterToCreate, $vmId, $vmName) {
  $nicProps = New-Object Microsoft.Windows.NetworkController.NetworkInterfaceProperties

  # if the user has a set mac address, then we use it. Else, we use dyanmic allocation and
  # allow NC to create one. this also requires us to set the adapter if necessary
  if ($adapterToCreate.macAddress -ieq $DefaultMac) {
    $nicProps.PrivateMacAllocationMethod = $IPAllocationDynamic
  }
  else {
    $nicProps.PrivateMacAllocationMethod = $IPAllocationStatic
    $nicProps.PrivateMacAddress = $adapterToCreate.macAddress
  }

  # set isPrimary, if necessary
  if ($adapterToCreate.sdnOptions.shouldSetNetworkInterfaceIsPrimary) {
    $nicProps.IsPrimary = $True
  }

  $options = $adapterToCreate.sdnOptions

  if ($options.psobject.Properties.name -contains "securityTags") {
    $nicProps = setSecurityTagsIfAvailable $options.securityTags $nicProps
  }

  # create the ipconfigurations
  $nicProps.IpConfigurations = @()
  if (($options.psobject.Properties.name -contains "virtualIpConfigurations") -and ($options.virtualIpConfigurations.length -gt 0)) {
    foreach ($ipConfigMap in $adapterToCreate.sdnOptions.virtualIpConfigurations) {
      $ipConfig = $ipConfigMap.ipConfiguration
      $ipAddress = $ipConfigMap.ipAddress
      $publicIp = $ipConfigMap.publicIp
      $ipConfig = New-Object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfiguration
      # this is fine ONLY for new ipconfigs. In other cases, we need to make sure the name doesnt exist already
      $ipConfig.ResourceId = "$($ipAddress)".Replace('.', '_')
      $ipConfigProps = New-Object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfigurationProperties
      $ipConfigProps.Subnet = New-Object Microsoft.Windows.NetworkController.Subnet
      if ($adapterToCreate.sdnOptions.sdnNetworkType -eq [SdnNetworkType]::Vnet) {
        $ipConfigProps.Subnet.ResourceRef = $adapterToCreate.sdnOptions.virtualSubnet.ResourceRef
      }
      else {
        $ipConfigProps.Subnet.ResourceRef = $adapterToCreate.sdnOptions.logicalSubnet.ResourceRef
      }

      $acl = (tryGetAcl $adapterToCreate)
      if ($null -ne $acl -and $acl.psobject.Properties.name -contains "ResourceRef") {
        $ipConfigProps.AccessControlList = New-Object Microsoft.Windows.NetworkController.AccessControlList
        $ipConfigProps.AccessControlList.ResourceRef = $acl.ResourceRef
      }
      $isUnmanaged = isUnmanagedLnet $adapterToCreate
      if ($isUnmanaged) {
        $ipConfigProps.PrivateIPAddress = ""
        $ipConfigProps.PrivateIPAllocationMethod = $IPAllocationUnmanaged
        $ipConfigProps.PublicIPAddress = $null
      }
      else {
        $ipConfigProps.PrivateIPAddress = $ipAddress
        $ipConfigProps.PrivateIPAllocationMethod = $IPAllocationStatic

        if ($null -ne $publicIp) {
          $ipConfigProps.PublicIPAddress = $publicIp
        }
      }
      $ipConfig.Properties = $ipConfigProps
      $nicProps.IpConfigurations += $ipConfig
    }
  }
  else {
    $ipConfig = New-Object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfiguration
    $ipConfig.ResourceId = generateUnusedResourceId $vmName
    $ipConfigProps = New-Object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfigurationProperties
    $ipConfigProps.Subnet = New-Object Microsoft.Windows.NetworkController.Subnet
    if ($adapterToCreate.sdnOptions.sdnNetworkType -eq [SdnNetworkType]::Vnet) {
      $ipConfigProps.Subnet.ResourceRef = $adapterToCreate.sdnOptions.virtualSubnet.ResourceRef
    }
    else {
      $ipConfigProps.Subnet.ResourceRef = $adapterToCreate.sdnOptions.logicalSubnet.ResourceRef
    }
    $acl = (tryGetAcl $adapterToCreate)
    if ($null -ne $acl -and $acl.psobject.Properties.name -contains "ResourceRef") {
      $ipConfigProps.AccessControlList = New-Object Microsoft.Windows.NetworkController.AccessControlList
      $ipConfigProps.AccessControlList.ResourceRef = $acl.ResourceRef
    }
    $isUnmanaged = isUnmanagedLnet $adapterToCreate
    if ($isUnmanaged) {
      $ipConfigProps.privateIPAllocationMethod = $IPAllocationUnmanaged
    }

    $ipConfig.Properties = $ipConfigProps
    $nicProps.IpConfigurations += $ipConfig
  }

  # create the NIC and set the port profile id
  $ncNic = $null

  $newResourceId = generateUnusedResourceId $vmName
  $tags = New-Object psobject -Property @{
    'vmId'      = $vmId
    'adapterId' = $adapterToCreate.id.Substring($adapterToCreate.Id.IndexOf('\') + 1)
  }
  $ncNic = New-NetworkControllerNetworkInterface -ConnectionUri $ncUri -ResourceId $newResourceId -Properties $nicProps -Tags $tags -Force -PassInnerException

  while ($ncNic.Properties.ProvisioningState -ne "Succeeded" -and $ncNic.Properties.ProvisioningState -ne "Failed") {
    Start-Sleep -Seconds $SleepSeconds
    $ncNic = Get-NetworkControllerNetworkInterface -ConnectionUri $ncUri -ResourceId $newResourceId
  }

  $script:ncNics = Get-NetworkControllerNetworkInterface -ConnectionUri $ncUri

  return $ncNic
}

function portProfileValues($adapterSettings, $nicInstanceId, $nicMacAddress) {
  $sdnNetworkType = $adapterSettings.sdnOptions.sdnNetworkType
  $acl = (tryGetAcl $adapterSettings)

  $profileId = $null
  $profileData = $null

  #If we're using default network policies, things are a little more complicated
  if ($useDefaultNetworkPolicies -and ($sdnNetworkType -eq [SdnNetworkType]::Lnet)) {
    $isUnmanagedLnet = isUnmanagedLnet $adapterSettings
    if ($isUnmanagedLnet) {
      if ($null -eq $acl) {
        $profileId = "{$([System.Guid]::Empty)}"
        $profileData = $PortProfileVlan #2
      }
      else {
        $profileId = "{$nicInstanceId}"
        $profileData = $PortProfileUntaggedLnet #6
      }
    }
    else {
      $profileId = "{$nicInstanceId}"
      $profileData = $PortProfileSDNNetwork #1
    }
  }
  # If VNET or if a prefixed Lnet, populate profileId and set data type to 1
  elseif (($sdnNetworkType -eq [SdnNetworkType]::Vnet) -or ($sdnNetworkType -eq [SdnNetworkType]::Lnet)) {
    $profileId = "{$nicInstanceId}"
    $profileData = $PortProfileSDNNetwork #1
  }

  return [PSCustomObject]@{
    vmId        = $vmId
    adapterId   = $adapterSettings.Id
    profileId   = $profileId
    profileData = $profileData
    macAddress  = $nicMacAddress
  }
}

# SDN error messages are sometimes formatted such that we can extract out a nice error message. If possible, do so.
# If not, simply return the original error message
function processSDNErrorMessage($err) {
  $errMsg = $err

  if ($null -ne $err.Exception.InnerException.Message) {
    $errMsg = $err.Exception.InnerException.Message
  }
  elseif ($null -ne $err.Exception.InnerException) {
    $errMsg = $err.Exception.InnerException
  }
  elseif ($null -ne $err.Exception.Message) {
    $errMsg = $err.Exception.Message
  }
  elseif ($null -ne $err.Exception) {
    $errMsg = $err.Exception
  }

  Write-Error $errMsg
}

function hasObjectField($object, $field) {
  return ($null -ne $object -and ($null -ne (Get-Member -InputObject $object -Name $field -MemberType Properties)) -and ($null -ne $object.$field))
}

function tryGetAcl($adapterSettings) {
  if ($null -ne (Get-Member -InputObject $adapterSettings.sdnOptions -Name "accessControlList" -MemberType Properties)) {
    return $adapterSettings.sdnOptions.accessControlList
  }
  return $null
}

function updateReturnObject($returnObject, $nic, $adapter) {
  $vlanAdapters = $returnObject.vlanAdapters
  $untaggedAdapters = $returnObject.untaggedAdapters
  $portProfiles = $returnObject.portProfiles

  if ($null -ne $nic) {
    $portProfile = portProfileValues $adapter $nic.InstanceId $nic.Properties.PrivateMacAddress
    $portProfiles += $portProfile

    if (($portProfile.profileData -eq $PortProfileSDNNetwork) -or ($portProfile.profileData -eq $PortProfileUntaggedLnet)) {
      $untaggedAdapters += $adapter.Id
    }

    if ($portProfile.profileData -eq $PortProfileVlan) {
      $vlanId = LnetVlanValue $adapter
      if ($null -ne $vlanId -and 0 -ne $vlanId) {
        $vlanAdapters += [PSCustomObject]@{
          adapterId = $adapter.Id
          vlanId    = $vlanId
        }
      }
      else {
        $untaggedAdapters += $adapter.Id
      }
    }
  }

  return @{
    vlanAdapters     = $vlanAdapters
    untaggedAdapters = $untaggedAdapters
    portProfiles     = $portProfiles
  }
}

function main(
  $vmId, $vmName, $adaptersToCreate, $adaptersToEdit, $ncUri, $useSecurityTags, $useDefaultNetworkPolicies, $newAdapterIds, $editPNics
) {
  $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Continue

  $logString = @{
    vmId             = $vmId
    vmName           = $vmName
    adaptersToCreate = $adaptersToCreate
    adaptersToEdit   = $adaptersToEdit
    ncUri            = $ncUri
    useSecurityTags  = $useSecurityTags
    useDNP           = $useDefaultNetworkPolicies
    newAdapterIds    = $newAdapterIds
    editPNics        = $editPNics
  } | ConvertTo-Json

  Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
    -Message "Logging the parameters of [$ScriptName]: $logString" -ErrorAction SilentlyContinue

  # fetch the nc nics
  $script:ncNics = Get-NetworkControllerNetworkInterface -ConnectionUri $ncUri

  $vlanAdapters = @() #List of objects with an adapterId and the value of the vlan field
  $untaggedAdapters = @() #List of adapters ID containing Adapters to set with Set-VMNetworkAdapterVlan -VMNetworkAdapter $adapter -Untagged
  $portProfiles = @() #List of objects to feed into Set-VMAdapterSDNSettings

  $returnObject = @{
    vlanAdapters     = $vlanAdapters
    untaggedAdapters = $untaggedAdapters
    portProfiles     = $portProfiles
  }

  $nicsWithPipsToEdit = @()

  # Edit the existing adapters...
  $editIndex = 0
  foreach ($adapterToEdit in $adaptersToEdit) {
    # if we are actually editing, and we have a virtual network type, configure the NC objects as appropriate
    if (($adapterToEdit.sdnOptions.sdnNetworkType -eq [SdnNetworkType]::Vnet) -or ($adapterToEdit.sdnOptions.sdnNetworkType -eq [SdnNetworkType]::Lnet)) {
      # check to see if a appropriate nc nic object exists
      $adapterToEdit.Id = $editPNics[$editIndex].Id
      $profileId = $editPNics[$editIndex].profileId
      $macAddress = $editPNics[$editIndex].macAddress
      $editIndex++

      $adapterId = $adapterToEdit.Id.Substring($adapterToEdit.Id.IndexOf('\') + 1)
      $ncNic = resolvePnicToNcNic $adapterId $profileId $macAddress

      if ($null -ne $ncNic) {
        # Else, we have an existing nic object
        $ipConfigsToAdd = @()
        $options = $adapterToEdit.sdnOptions
        if ($adapterToEdit.sdnOptions.virtualIpConfigurations.length -gt 0) {
          # identify the existing ip configs and update the ip address only.
          foreach ($ipConfigMap in $adapterToEdit.sdnOptions.virtualIpConfigurations) {
            # fetch existing ip configs
            $ipConfigToEdit = $ipConfigMap.ipConfiguration
            $newIpAddress = $ipConfigMap.ipAddress
            $newPublicIp = $ipConfigMap.publicIp
            $existingIpConfig = $null

            if (hasObjectField $ipConfigToEdit "instanceId") {
              $existingIpConfig = $ncNic.Properties.IpConfigurations | Where-Object { $_.InstanceId -ieq $ipConfigToEdit.instanceId }
            }

            # If an existing ip config exists, set the ip and subnet resource ref and continue
            if ($null -ne $existingIpConfig) {
              $resourceId = $existingIpConfig.ResourceId
              $existingIpConfig = New-Object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfiguration
              $existingIpConfig.ResourceId = $resourceId
              $ipConfig = $existingIpConfig
            }
            else {
              # Else, we need to create a new ip config
              $newIpConfig = New-Object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfiguration
              $newIpConfig.ResourceId = "$($newIpAddress)".Replace('.', '_')
              $ipConfig = $newIpConfig
            }
            $ipConfigProps = New-Object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfigurationProperties
            $ipConfigProps.Subnet = New-Object Microsoft.Windows.NetworkController.Subnet
            if ($adapterToEdit.sdnOptions.sdnNetworkType -eq [SdnNetworkType]::Vnet) {
              $ipConfigProps.Subnet.ResourceRef = $adapterToEdit.sdnOptions.virtualSubnet.ResourceRef
            }
            else {
              $ipConfigProps.Subnet.ResourceRef = $adapterToEdit.sdnOptions.logicalSubnet.ResourceRef
            }
            $acl = (tryGetAcl $adapterToEdit)
            if ($null -ne $acl -and $acl.psobject.Properties.name -contains "ResourceRef") {
              $ipConfigProps.AccessControlList = New-Object Microsoft.Windows.NetworkController.AccessControlList
              $ipConfigProps.AccessControlList.ResourceRef = $acl.ResourceRef
            }
            if ($null -ne $newIpAddress) {
              $ipConfigProps.PublicIPAddress = $null
              $isUnmanaged = isUnmanagedLnet $adapterToEdit
              if ($isUnmanaged) {
                $ipConfigProps.PrivateIPAddress = ""
                $ipConfigProps.PrivateIPAllocationMethod = $IPAllocationUnmanaged
              }
              else {
                $ipConfigProps.PrivateIPAddress = $newIpAddress
                $ipConfigProps.PrivateIPAllocationMethod = $IPAllocationStatic
                # check if we want to keep this existing pip
                if ($null -ne $existingIpConfig -and $existingIpConfig.Properties.PublicIPAddress -eq $newPublicIp) {
                  $ipConfigProps.PublicIPAddress = $newPublicIp
                }
                elseif ($null -ne $newPublicIp) {
                  # if we want to change the existing pip or add a new one, do that later so this pip and remaining pips can be refreshed
                  $nicsWithPipsToEdit += [PSCustomObject]@{
                    nicId      = $ncNic.ResourceId
                    ipConfigId = $ipConfig.ResourceId
                    pip        = $newPublicIp
                    adapterId  = $adapterIdps
                  }
                }
              }
            }
            $ipConfig.Properties = $ipConfigProps
            $ipConfigsToAdd += $ipConfig
          }
        }
        else {
          # We don't have any virtual IP configs, so create one without any IP addresses
          $ncNic.Properties.IpConfigurations = @()
          $newIpConfig = New-Object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfiguration
          $newIpConfig.ResourceId = generateUnusedResourceId $vmName
          $newIpConfigProps = New-Object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfigurationProperties
          $newIpConfigProps.Subnet = New-Object Microsoft.Windows.NetworkController.Subnet
          if ($adapterToEdit.sdnOptions.sdnNetworkType -eq [SdnNetworkType]::Vnet) {
            $newIpConfigProps.Subnet.ResourceRef = $adapterToEdit.sdnOptions.virtualSubnet.ResourceRef
          }
          else {
            $newIpConfigProps.Subnet.ResourceRef = $adapterToEdit.sdnOptions.logicalSubnet.ResourceRef
          }
          if ($options.psobject.Properties.name -contains "accessControlList") {
            $acl = (tryGetAcl $adapterToEdit)
            if ($null -ne $acl -and $acl.psobject.Properties.name -contains "ResourceRef") {
              $newIpConfigProps.AccessControlList = New-Object Microsoft.Windows.NetworkController.AccessControlList
              $newIpConfigProps.AccessControlList.ResourceRef = $acl.ResourceRef
            }
          }
          $isUnmanaged = isUnmanagedLnet $adapterToEdit
          if ($isUnmanaged) {
            $newIpConfigProps.PrivateIPAddress = ""
            $newIpConfigProps.PrivateIPAllocationMethod = $IPAllocationUnmanaged
          }
          $newIpConfig.Properties = $newIpConfigProps
          $ipConfigsToAdd += $newIpConfig
        }

        # check to see what we need to update our mac address to. We need to update both NC and hyper-v objects.
        $returnObject = updateReturnObject -returnObject $returnObject -nic $ncNic -adapter $adapterToEdit

        if ($adapterToEdit.macAddress -ne $ncNic.Properties.PrivateMacAddress) {
          $ncNic.Properties.PrivateMacAddress = $adapterToEdit.macAddress
        }

        if ($adapterToEdit.sdnOptions.psobject.Properties.name -contains "securityTags") {
          $ncNic.Properties = setSecurityTagsIfAvailable $adapterToEdit.sdnOptions.securityTags $ncNic.Properties
        }

        $ncNic.Properties.IpConfigurations = $ipConfigsToAdd
        try {
          $tags = New-Object PSObject -Property @{
            'vmId'      = $vmId
            'adapterId' = $adapterId
          }

          $ncNic = New-NetworkControllerNetworkInterface -ConnectionUri $ncUri -ResourceId $ncNic.ResourceId -Properties $ncNic.Properties -Tags $tags -Force -PassInnerException

          while ($ncNic.Properties.ProvisioningState -ne "Succeeded" -and $ncNic.Properties.ProvisioningState -ne "Failed") {
            Start-Sleep -Seconds $SleepSeconds
            $ncNic = Get-NetworkControllerNetworkInterface -ConnectionUri $ncUri -ResourceId $ncNic.ResourceId
          }
        }
        catch {
          processSDNErrorMessage $_
        }
      }
      # if no existing NC object was found, we need to create one. this will also create appropriate IP Configs
      else {
        $ncNic = createNetworkControllerNetworkInterface $adapterToEdit $vmId $vmName
        $returnObject = updateReturnObject -returnObject $returnObject -nic $ncNic -adapter $adapterToEdit
      }
    }
  }

  # Edit the existing adapters with public ips
  foreach ($nicWithPipsToEdit in $nicsWithPipsToEdit) {
    $nicProps = (Get-NetworkControllerNetworkInterface -ResourceId $nicWithPipsToEdit.nicId -ConnectionUri $ncUri).Properties
    $currentIpConfig = $nicProps.IpConfigurations | Where-Object { $_.ResourceId -eq $nicWithPipsToEdit.ipConfigId }
    $currentIpConfig.Properties.PublicIPAddress = $nicWithPipsToEdit.pip

    try {
      $tags = New-Object PSObject -Property @{
        'vmId'      = $vmId
        'adapterId' = $nicWithPipsToEdit.adapterId
      }

      $ncNic = New-NetworkControllerNetworkInterface -ConnectionUri $ncUri -ResourceId $nicWithPipsToEdit.nicId -Properties $nicProps -Tags $tags -Force -PassInnerException

      while ($ncNic.Properties.ProvisioningState -ne "Succeeded" -and $ncNic.Properties.ProvisioningState -ne "Failed") {
        Start-Sleep -Seconds $SleepSeconds
        $ncNic = Get-NetworkControllerNetworkInterface -ConnectionUri $ncUri -ResourceId $ncNic.ResourceId
      }
    }
    catch {
      processSDNErrorMessage $_
    }
  }

  # Process the adapters to be added...
  $createIndex = 0
  foreach ($adapterToCreate in $adaptersToCreate) {
    $nic = $null

    $adapterToCreate.Id = $newAdapterIds[$createIndex]
    $createIndex++

    # if SDN is enabled, and the nic type is VNet/Lnet, create the NC nic object
    if (($adapterToCreate.sdnOptions.sdnNetworkType -eq [SdnNetworkType]::Vnet) -or ($adapterToCreate.sdnOptions.sdnNetworkType -eq [SdnNetworkType]::Lnet)) {
      $nic = createNetworkControllerNetworkInterface $adapterToCreate $vmId $vmName
      $returnObject = updateReturnObject -returnObject $returnObject -nic $nic -adapter $adapterToCreate
    }
  }

  return $returnObject
}

if (-not ($env:pester)) {
  $module = Get-Module -Name NetworkController -ErrorAction SilentlyContinue

  if ($module) {
    $returnValue = main $vmId $vmName $adaptersToCreate $adaptersToEdit $ncUri $useSecurityTags $useDefaultNetworkPolicies $newAdapterIds $editPNics

    cleanupScriptEnv
    return $returnValue
  }

  Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
    -Message "[$ScriptName]: Cannot continue because required Network Controller PowerShell module was not found." -ErrorAction SilentlyContinue

  cleanupScriptEnv

  return Get-RBACVM -Id $vmId | Get-VMNetworkAdapter | Microsoft.PowerShell.Utility\Select-Object `
    name, `
    id, `
    vmname, `
    vmid, `
    SwitchName, `
    SwitchId, `
    IPAddresses, `
    MacAddress, `
    DynamicMacAddressEnabled, `
    MacAddressSpoofing, `
    Status, `
    isLegacy, `
    connected, `
  @{Label = "MinimumBandwidthAbsolute"; Expression = { if ($_.BandwidthSetting) { $_.BandwidthSetting.MinimumBandwidthAbsolute } else { 0 } } }, `
  @{Label = "MaximumBandwidth"; Expression = { if ($_.BandwidthSetting) { $_.BandwidthSetting.MaximumBandwidth } else { 0 } } }, `
  @{Label = "IsolationMode"; Expression = { $_.IsolationSetting.IsolationMode } }, `
  @{Label = "VlanMode"; Expression = { $_.VlanSetting.OperationMode } }, `
  @{Label = "accessVlanId"; Expression = { $_.VlanSetting.AccessVlanId } }
}


}
## [END] Set-WACVMNetworkInterfaces ##
function Set-WACVMSwitchEmbeddedTeamingGeneralSettings {
<#

.SYNOPSIS
Sets the general settings for the passed in switch embedded teaming (SET).

.DESCRIPTION
Sets the general settings for the passed in switch embedded teaming (SET) on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER switchId
    The Id of the requested virtual switch.

.PARAMETER switchName
    The name of the virtual machine switch.  Can be a new name to which the switch should be renamed.

.PARAMETER netAdapterNames
    The optional array of the names of the network adapter to assign to this switch.  When there is more 
    than one adapter provided a Switch Embedded Teaming (SET) switch will be created.  This parameter is not required
    for Private or Internal virtual switch types.

.PARAMETER switchType
    The switch type.  
        [Microsoft.HyperV.PowerShell.VMSwitchType]::Private (0)
        [Microsoft.HyperV.PowerShell.VMSwitchType]::Internal (1)
        [Microsoft.HyperV.PowerShell.VMSwitchType]::External (2)

.PARAMETER allowManagementOs
    Optionally allow the host operating system to use the virtual switch as a network adapter.

.PARAMETER notes
    Optional notes to apply to this virtual switch.

.PARAMETER loadBalancingAlgorithm
    Optional load balancing algoritm for SET switches.
        hyperVPort = 4,
        dynamic = 5

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $switchId,
    [Parameter(Mandatory = $true)]
    [string]
    $switchName,
    [Parameter(Mandatory = $false)]
    [AllowNull()][string[]]
    $networkAdapterNames,
    [Parameter(Mandatory = $false)]
    [AllowNull()][System.Nullable[boolean]]
    $allowManagementOs,
    [Parameter(Mandatory = $false)]
    [AllowNull()][string]
    $notes,
    [Parameter(Mandatory = $false)]
    [AllowNull()][System.Nullable[int]]
    $loadBalancingAlgorithm
)

Set-StrictMode -Version 5.0;
Import-Module Hyper-V;

$switch = get-vmswitch -Id $switchId;

$switch | rename-vmswitch -NewName $switchName;

$args = @{'Name' = $switchName; };

if ($notes) {
    $args += @{'Notes' = $notes; };
}

if ($allowManagementOs) {
    $args += @{'AllowManagementOS' = $allowManagementOs; };
} else {
    $args += @{'AllowManagementOS' = $false; };
}

set-vmswitch @args;

$args = @{ 'Name' = $switch.Name; };

if ($loadBalancingAlgorithm) {
    $args += @{'LoadBalancingAlgorithm' = $loadBalancingAlgorithm; };
}

if ($networkAdapterNames) {
    $args += @{ 'NetAdapterName' = $networkAdapterNames; };
}

Set-VMSwitchTeam @args;

}
## [END] Set-WACVMSwitchEmbeddedTeamingGeneralSettings ##
function Set-WACVMVMAdapterSDNSettings {
<#

.SYNOPSIS
Set up port profiles for a new virtual machine.

.DESCRIPTION
Create a new virtual machine's port profiles setup.

.ROLE
Hyper-V-Administrators

.PARAMETER profileSettings
an array of objects containing the vmId, adapterId, profileData and profileSettings of the adapter to edit

.PARAMETER vmId
The ID of the vm that contains the relevant adapters in other paramters. Only 1 VM can be changes at a time

.PARAMETER vlanAdapters
Array of objects containing the adapter ID and the int value of the VLAN it should be attached to

.PARAMETER untaggedAdapters
Array of strings of adapter IDs that need to be set to an untagged isolation mode
#>

param(
  [Parameter(Mandatory = $true)]
  [string]
  $vmId,
  [Parameter(Mandatory = $false)]
  [object[]]
  $profileSettings = @(),
  [Parameter(Mandatory = $false)]
  [object[]]
  $vlanAdapters = @(),
  [Parameter(Mandatory = $false)]
  [ValidateNotNull()]
  [string[]]
  $untaggedAdapters = @()
)

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue

function setupScriptEnv() {
  Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
  Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
  Set-Variable -Name ScriptName -Option ReadOnly -Value "Set-VMAdapterSDNSettings.ps1" -Scope Script
  Set-Variable -Name PortProfileFeatureId -Option ReadOnly -Value "9940cd46-8b06-43bb-b9d5-93d50381fd56" -Scope Script
  Set-Variable -Name PortProfileNetCfgInstanceId -Option ReadOnly -Value "{56785678-a0e5-4a26-bc9b-c0cba27311a3}" -Scope Script
  Set-Variable -Name NetworkControllerVendorId -Option ReadOnly -Value "{1FA41B39-B444-4E43-B35A-E1F7985FD548}" -Scope Script
  Set-Variable -Name NetworkControllerVendorName -Option ReadOnly -Value "NetworkController" -Scope Script
  Set-Variable -Name NetworkControllerCdnLabelName -Option ReadOnly -Value "TestCdn" -Scope Script
  Set-Variable -Name NetworkControllerCdnLabelId -Option ReadOnly -Value 1111 -Scope Script
  Set-Variable -Name NetworkControllerProfileName -Option ReadOnly -Value "Testprofile" -Scope Script
  Set-Variable -Name DefaultMac -Option ReadOnly -Value "000000000000" -Scope Script
  Set-Variable -Name RunningState -Option ReadOnly -Value 2 -Scope Script
}

function cleanupScriptEnv() {
  Remove-Variable -Name LogName -Scope Script -Force
  Remove-Variable -Name LogSource -Scope Script -Force
  Remove-Variable -Name ScriptName -Scope Script -Force
  Remove-Variable -Name PortProfileFeatureId -Scope Script -Force
  Remove-Variable -Name PortProfileNetCfgInstanceId -Scope Script -Force
  Remove-Variable -Name NetworkControllerVendorId -Scope Script -Force
  Remove-Variable -Name NetworkControllerVendorName -Scope Script -Force
  Remove-Variable -Name NetworkControllerCdnLabelName -Scope Script -Force
  Remove-Variable -Name NetworkControllerCdnLabelId -Scope Script -Force
  Remove-Variable -Name NetworkControllerProfileName -Scope Script -Force
  Remove-Variable -Name DefaultMac -Scope Script -Force
  Remove-Variable -Name RunningState -Scope Script -Force
}

function configureAdapter([string] $vmId, [string] $adapterId, [string] $profileId, [string]$profileData, [string]$macAddress) {
    $vm = Get-RBACVM -Id $vmId
    $vmNic = $vm | Get-VMNetworkAdapter | Where-Object {$_.id -eq $adapterId}

    if ($null -ne $macAddress -and "" -ne $macAddress -and $DefaultMac -ne $macAddress -and $vm.State -ne $RunningState) {
        Set-VMNetworkAdapter -StaticMacAddress $macAddress -VMNetworkAdapter $vmNic
    }

    $currentFeature = Get-VMSwitchExtensionPortFeature -FeatureId $PortProfileFeatureId -VMNetworkAdapter $vmNic

    if (-not ($currentFeature)) {
        $feature = Get-VMSystemSwitchExtensionPortFeature -FeatureId $PortProfileFeatureId
        # leave the following untouched. All of the IDs are hardcoded properly
        $feature.SettingData.NetCfgInstanceId = $PortProfileNetCfgInstanceId
        $feature.SettingData.CdnLabelstring = $NetworkControllerCdnLabelName
        $feature.SettingData.CdnLabelId = $NetworkControllerCdnLabelId
        $feature.SettingData.ProfileName = $NetworkControllerProfileName
        $feature.SettingData.VendorId = $NetworkControllerVendorId
        $feature.SettingData.VendorName = $NetworkControllerVendorName
        $feature.SettingData.ProfileId = $profileId
        $feature.SettingData.ProfileData = $profileData

        Add-VMSwitchExtensionPortFeature -VMSwitchExtensionFeature $feature -VMNetworkAdapter $vmNic
    } else {
        $currentFeature.SettingData.ProfileId = $profileId
        $currentFeature.SettingData.ProfileData = $profileData

        Set-VMSwitchExtensionPortFeature -VMSwitchExtensionFeature $currentFeature -VMNetworkAdapter $vmNic
    }
}

function main(
    [string]$vmId,
    [object[]]$profileSettings,
    [object[]]$vlanAdapters,
    [string[]]$untaggedAdapters
) {
  $logString = @{
    vmId = $vmId
    profileSettings = $profileSettings
    vlanAdapters = $vlanAdapters
    untaggedAdapters = $untaggedAdapters
  } | ConvertTo-Json

  Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
  -Message "Logging the parameters of [$ScriptName]: $logString" -ErrorAction SilentlyContinue

    $vm = Get-RBACVM -id $vmId

    if (-not $vm) {
      return
    }

    $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Continue

    $alladapters = @(Get-VMNetworkAdapter -VM $vm)
    $adaptersIdMap = @{};

    # Fill the adapter to id map.
    foreach ($adapter in $alladapters) {
        $adaptersIdMap.Add($adapter.Id, $adapter)
    }

    foreach ($vlanAdapter in $vlanAdapters) {
        $adapter = $adaptersIdMap[$vlanAdapter.adapterId]
        Set-VMNetworkAdapterIsolation -VMNetworkAdapter $adapter -IsolationMode ([Microsoft.HyperV.PowerShell.VMNetworkAdapterIsolationMode]::None)
        Set-VMNetworkAdapterVlan -VMNetworkAdapter $adapter -Access -VlanId $vlanAdapter.vlanId
    }

    foreach ($untaggedAdapter in $untaggedAdapters) {
        $adapter = $adaptersIdMap[$untaggedAdapter]
        Set-VMNetworkAdapterVlan -VMNetworkAdapter $adapter -Untagged
    }

    foreach ($profileSetting in $profileSettings) {
        configureAdapter $profileSetting.vmId $profileSetting.adapterId $profileSetting.profileId $profileSetting.profileData $profileSetting.macAddress
    }

    $vm | Get-VMNetworkAdapter | Microsoft.PowerShell.Utility\Select-Object `
      name, `
      id, `
      vmname, `
      vmid, `
      SwitchName, `
      SwitchId, `
      IPAddresses, `
      MacAddress, `
      DynamicMacAddressEnabled, `
      MacAddressSpoofing, `
      Status, `
      isLegacy, `
      connected, `
      @{Label="MinimumBandwidthAbsolute";Expression={if ($_.BandwidthSetting) {$_.BandwidthSetting.MinimumBandwidthAbsolute} else {0}}}, `
      @{Label="MaximumBandwidth";Expression={if ($_.BandwidthSetting) {$_.BandwidthSetting.MaximumBandwidth} else {0}}}, `
      @{Label="IsolationMode";Expression={$_.IsolationSetting.IsolationMode}}, `
      @{Label="VlanMode";Expression={$_.VlanSetting.OperationMode}}, `
      @{Label="accessVlanId";Expression={$_.VlanSetting.AccessVlanId}}
}

###############################################################################
# Script execution starts here...
###############################################################################

if (-not ($env:pester)) {
    setupScriptEnv

    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    $module = Get-Module -Name Hyper-V -ErrorAction SilentlyContinue
    $returnValue = $null
    if ($module) {
        $returnValue = main $vmId $profileSettings $vlanAdapters $untaggedAdapters
    }

    if ($null -eq $returnValue) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Cannot continue because required Hyper-V PowerShell module was not found." -ErrorAction SilentlyContinue
    }

    cleanupScriptEnv

    $returnValue
}

}
## [END] Set-WACVMVMAdapterSDNSettings ##
function Set-WACVMVirtualMachineBootOrderSettings {
<#

.SYNOPSIS
Sets the boot order settings for the passed in virtual machine.

.DESCRIPTION
Sets the boot order settings for the passed in virtual machine on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER vmId
    The Id of the requested virtual machine.

.PARAMETER gen1StartupOrder
    The optional Generation 1 VM Startup Order settings. This is an array of all the elementes of the
    Microsoft.HyperV.PowerShell.BootDevice enum values.

.PARAMETER gen2BootOrderDevicesId
    The optionGeneration 2 VM Boot Order settings. This is an array of strings with the IDs of the 
    devices to boot from.

#>

 param (
    [Parameter(Mandatory = $true)]
    [string]
    $vmId,
    [Parameter(Mandatory = $false)]
    [object[]]
    $gen1StartupOrder,
    [Parameter(Mandatory = $false)]
    [object[]]
    $gen2BootOrderDevicesId
)

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

###############################################################################
# Constants
###############################################################################

Set-Variable -Name LogName -Option Constant -Value "Microsoft-ServerManagementExperience" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SMEScripts" -ErrorAction SilentlyContinue
Set-Variable -Name ScriptName -Option Constant -Value "Set-VirtualMachineBootOrderSettings.ps1" -ErrorAction SilentlyContinue

function main([string]$vmId, [object[]]$gen1StartupOrder, [object[]]$gen2BootOrderDevicesId) {
    $vm = Get-RBACVM -id $vmId

    if ($gen1StartupOrder -ne $()) {
        Set-VMBios -VM $vm -StartupOrder $gen1StartupOrder
    } else {
        $fwSettings = @(Get-VMFirmware -VM $vm)
        $devices = @(Get-VMHardDiskDrive -VM $vm)
        $devices += Get-VMDvdDrive -VM $vm
        $devices += Get-VMNetworkAdapter -VM $vm
        $devicesIdMap = @{}
        $fwSettings.BootOrder | Where-Object {$_.BootType -eq 'File'} | ForEach-Object { $devicesIdMap.Add($_.FirmwarePath, $_) }

        foreach ($device in $devices) {
            $devicesIdMap.Add($device.Id, $device)
        }

        $bootOrder = @()
        foreach ($deviceId in $gen2BootOrderDevicesId) {
            $device = $devicesIdMap[$deviceId]

            if ($device) {
                $bootOrder += $device
            } else {
              Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: Unable to find device with Id $deviceId in virtual machine $($vm.Name) (vmId = $vmId)" -ErrorAction SilentlyContinue

              $msg = $strings.DeviceIdNotFound -f $deviceId, $vm.Name, $vmId
              Write-Error $msg
            }
        }

        Set-VMFirmware -VM $vm -BootOrder $bootOrder
    }
}

Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

$module = Get-Module -Name Hyper-V -ErrorAction SilentlyContinue
if ($module) {
    return main $vmId $gen1StartupOrder $gen2BootOrderDevicesId
}

return $null

}
## [END] Set-WACVMVirtualMachineBootOrderSettings ##
function Set-WACVMVirtualMachineCheckpointsSettings {
<#

.SYNOPSIS
Sets the checkpoints settings for the passed in virtual machine.

.DESCRIPTION
Sets the checkpoints settings for the passed in virtual machine on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER vmId
    The Id of the requested virtual machine.

.PARAMETER snapshotFileLocation
    The path to where the checkpoints (snapshots) of this virtual machine will be stored.

.PARAMETER checkpointType
    The type checkpoints to create -- Standard or Production.

.PARAMETER automaticCheckpoints
    Should checkpoints be taked automatically?

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $vmId,
    [Parameter(Mandatory = $true)]
    [String]
    $snapshotFileLocation,
    [Parameter(Mandatory = $false)]
    [AllowNull()][System.Nullable[int]]
    $checkpointType,
    [Parameter(Mandatory = $false)]
    [AllowNull()][System.Nullable[boolean]]
    $automaticCheckpoints
)  

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue

function SaveCheckpointSettings(
    $vmId,
    $snapshotFileLocation,
    $checkpointType,
    $automaticCheckpoints
) {
    Set-Variable checkpointTypeDisabled -Option Constant -Value 2

    $vm = Get-RBACVM -id $vmId
    $args = @{VM = $vm}

    # Is checkpointType supported?
    if ($checkpointType) {
        $args += @{'CheckpointType' = $checkpointType}

        # If the user want to disable checkpoints for this vm then there is no need to set the other parameters.
        if ($checkpointType -eq $checkpointTypeDisabled) {
            $snapshotFileLocation = $null
            $automaticCheckpoints = $null
        }
    } 

    if ($snapshotFileLocation) {
        $args += @{'SnapshotFileLocation' = $snapshotFileLocation}
    }

    # Since false is a valid response then an explict null check is required.
    if ($automaticCheckpoints -ne $null) {
        $args += @{'AutomaticCheckpointsEnabled' = $automaticCheckpoints}
    }

    if ($vm.isClustered) {
        $args += @{'AllowUnverifiedPaths' = $null}
    }

    Set-VM @args -ErrorAction SilentlyContinue
}

# Ensure this is cleared
$error.Clear()

# Whilst saving the checkpoints  settings one, or more, of the Hyper-V cmdlets called will call Update-ClusterVirtualMachineConfiguration
# under the covers.  The issue is that cmdlet was never written to work in a remote PS session.  And, the Hyper-V cmdlets
# pass the cluster name instead of the more appropriate "." (this server).  This means that when the VM and the cluster name
# reside on different cluster nodes a double hop is introduced. Since it is not feasible to fix the 
# Update-ClusterVirtualMachineConfiguration cmdlet, the following work around is the best solution available.
#
# The work around is to retry the Update-ClusterVirtualMachineConfiguration cmdlet anytime there is a message in $error
# from that cmdlet.  This retry is done using the cluster name "." -- shorthand for "this server".

# Save the settings
SaveCheckpointSettings $vmId $snapshotFileLocation $checkpointType $automaticCheckpoints

# Were there any errors?
if ($error.Count -gt 0) {
    $retry = $false

    # Must check each error looking for any Update-ClusterVirtualMachineConfiguration errors
    foreach($err in $error) {
        # If the error has an exception use the exception
        if ($err.PSObject.Properties.Match("Exception")) {
            $ex = $err.Exception
        } else {
            # If the error is an ErrorRecord reach down and get the exception
            if ($err.PSObject.Properties.Match("ErrorRecord")) {
                $ex = $err.ErrorRecord.Exception
            }
        }

        # Did the exception message come from Update-ClusterVirtualMachineConfiguration?  If it did check the server for being
        # a cluster node
        if ($ex -and $ex.Message -match "Update-ClusterVirtualMachineConfiguration") {
            $hostName = hostname
            $node = Get-ClusterNode -Name $hostName.ToString() -ErrorAction SilentlyContinue

            # If this server is a cluster node then set the flag and break
            if ($node -and $node.State -eq "Up") {
                $retry = $true
                break
            }
        }
    }

    # Are we going to retry the Update-ClusterVirtualMachineConfiguration cmdlet?
    if ($retry) {
        # Clear the errors so that any new Update-ClusterVirtualMachineConfiguration failures are reported
        $error.Clear()

        # Retry the cmdlet using the local host -- in case the previous failure was a double hop failure
        # Any new errors will be sent back to the UI
        #
        # Note: Warnings from this cmdlet are not being sent back to the UI -- and they should be since 
        # they most likely detail that the VM is not properly configured for hosting in a cluster.
        Update-ClusterVirtualMachineConfiguration -Cluster "." -VmId $vmId
    }
}

if ($error.Count -gt 0) {
    throw $error
}

}
## [END] Set-WACVMVirtualMachineCheckpointsSettings ##
function Set-WACVMVirtualMachineDisksSettings {
<#

.SYNOPSIS
Sets the hard disks for the passed in virtual machine.

.DESCRIPTION
Sets the hard disks for the passed in virtual machine on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER vmId
    The Id of the requested virtual machine.

.PARAMETER disksToDelete

.PARAMETER disksToCreate

.PARAMETER disksToEdit

.PARAMETER dvdsToDelete

.PARAMETER dvdsToCreate

.PARAMETER dvdsToEdit

#>

param (
  [Parameter(Mandatory = $true)]
  [String]
  $vmId,
  [Parameter(Mandatory = $false)]
  [object[]]
  $disksToDelete,
  [Parameter(Mandatory = $false)]
  [object[]]
  $disksToCreate,
  [Parameter(Mandatory = $false)]
  [object[]]
  $disksToEdit,
  [Parameter(Mandatory = $false)]
  [object[]]
  $dvdsToDelete,
  [Parameter(Mandatory = $false)]
  [object[]]
  $dvdsToCreate,
  [Parameter(Mandatory = $false)]
  [object[]]
  $dvdsToEdit
)

$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue
Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

###############################################################################
# Constants
###############################################################################

function setupScriptEnv() {
  Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
  Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
  Set-Variable -Name ScriptName -Option ReadOnly -Value Set-VirtualMachineDisksSettings.ps1 -Scope Script
  Set-Variable -Name VHDDefaultSize -Option ReadOnly -Value 127GB -Scope Script
  Set-Variable -Name DiskSizePropertyName -Option ReadOnly -Value "Size" -Scope Script
  Set-Variable -Name DiskVhdFormatPropertyName -Option ReadOnly -Value "VhdFormat" -Scope Script
}

function cleanupScriptEnv() {
  Remove-Variable -Name LogName -Scope Script -Force
  Remove-Variable -Name LogSource -Scope Script -Force
  Remove-Variable -Name ScriptName -Scope Script -Force
  Remove-Variable -Name VHDDefaultSize -Scope Script -Force
  Remove-Variable -Name DiskSizePropertyName -Scope Script -Force
  Remove-Variable -Name DiskVhdFormatPropertyName -Scope Script -Force
}

function getSize($path) {
  $vhd = Get-VHD -Path $path
  return $vhd.Size
}

function getVhdFormat($path) {
  $vhd = Get-VHD -Path $path
  return $vhd.VhdFormat
}

function SaveDiskSettings(
  $vmId,
  $disksToDelete,
  $disksToCreate,
  $disksToEdit,
  $dvdsToDelete,
  $dvdsToCreate,
  $dvdsToEdit
) {
  $vm = Get-RBACVM -id $vmId

  if (-not $vm) {
    return
  }

  $alldisks = Get-VMHardDiskDrive -VM $vm
  $alldvds = Get-VMDvdDrive -VM $vm

  # delete disks
  foreach ($diskToDelete in $disksToDelete) {
    $disk = $alldisks | Where-Object { $_.Id.ToString() -ieq $diskToDelete.Id }
    if (-not $disk) {
      Write-Warning $strings.VirtualMachineDiskDeleteDiskNotFound if $diskToDelete.Id, $vm.Name
      continue
    }

    Remove-VMHardDiskDrive -VMHardDiskDrive $disk -ErrorAction SilentlyContinue
  }

  foreach ($dvdToDelete in $dvdsToDelete) {
    $dvd = $alldvds | Where-Object { $_.Id.ToString() -ieq $dvdToDelete.Id }
    if (-not $dvd) {
      Write-Warning $strings.VirtualMachineDvdDeleteDiskNotFound -f $dvdToDelete.Id, $vm.Name
      continue
    }

    Remove-VMDvdDrive -VMDvdDrive $dvd -ErrorAction SilentlyContinue
  }

  # edit existing disks
  foreach ($diskToEdit in $disksToEdit) {
    $disk = $alldisks | Where-Object { $_.Id.ToString() -ieq $diskToEdit.Id }
    if (-not $disk) {
      Write-Warning $strings.VirtualMachineDiskEditDiskNotFound -f $diskToEdit.Id, $vm.Name
      continue
    }

    if ($diskToEdit.Path) {
      $diskToEdit.Path = $diskToEdit.Path.Trim()
    }

    if (-not $diskToEdit.Path) {
      Write-Warning $strings.VirtualMachineDiskPathNotFound -f $diskToEdit.Id, $vm.Name
    }
    else {
      Set-VMHardDiskDrive -VMHardDiskDrive $disk -Path $diskToEdit.path -ErrorAction SilentlyContinue
      if (-not $diskToEdit.editVhdData.data.isDataAvailable) {
        # just an expansion - user changed the size without using the edit dialog
        if (!!$diskToEdit.currentDiskSizeInGB) {
          $diskSize = $diskToEdit.currentDiskSizeInGB * 1024 * 1024 * 1024
          if ($diskSize -gt (getSize $diskToEdit.Path)) {
            Resize-VHD -Path $diskToEdit.path -SizeBytes $diskSize
          }
        }
      }
      else {
        $editAction = $diskToEdit.editVhdData.data.editAction
        $diskPath = $diskToEdit.Path
        $attachVhd = $diskToEdit.editVhdData.data.attachVhd

        # compact disk
        if ($editAction -eq 0) {
          Optimize-VHD -Path $diskPath -Mode Full
        }

        # convert disk
        if ($editAction -eq 1) {
          $convertActionData = $diskToEdit.editVhdData.data.convertActionData
          $newVhdName = $convertActionData.newVhdName
          $newVhdPath = $convertActionData.newVhdPath
          $vhdFormat = $convertActionData.vhdFormat
          $vhdType = $convertActionData.vhdType
          $newVhdFormat = "vhdx"
          if ($vhdFormat -eq 2 ) {
            $newVhdFormat = "vhd"
          }
          $destinationPath = "$newVhdPath\$newVhdName.$newVhdFormat"

          # fixed
          if ($vhdType -eq 2) {
            Convert-VHD -Path $diskPath -DestinationPath $destinationPath -VHDType Fixed
          }

          # dynamic
          if ($vhdType -eq 3) {
            Convert-VHD -Path $diskPath -DestinationPath $destinationPath -VHDType Dynamic
          }

          # differencing
          if ($vhdType -eq 4) {
            $parentVhdPath = $convertActionData.parentVhdPath
            Convert-VHD -Path $diskPath -DestinationPath $destinationPath -VHDType Differencing -ParentPath $parentVhdPath
          }

          if ($attachVhd) {
            # create the drive with the VHD
            Add-VMHardDiskDrive -VM $vm -Path $destinationPath -ErrorAction SilentlyContinue
          }

        }

        # resize or expand disk
        if ($editAction -eq 2 -or $editAction -eq 3 ) {
          if ($editAction -eq 2) {
            $resizeActionData = $diskToEdit.editVhdData.data.expandActionData
          }else{
            $resizeActionData = $diskToEdit.editVhdData.data.resizeActionData
          }

          $sizeUnits = $resizeActionData.sizeUnits
          $newSize = $resizeActionData.newSize * 1024 * 1024 * 1024
          if ($sizeUnits -eq "TB") {
            $newSize = $newSize * 1024
          }
          Resize-VHD -Path $diskPath -SizeBytes $newSize
        }

        # merge disk
        if ($editAction -eq 4) {
          $mergeActionData = $diskToEdit.editVhdData.data.mergeActionData
          $mergeOption = $mergeActionData.mergeOption
          $vhd = Get-VHD -Path $diskPath

          # merge to parent
          if ($mergeOption -eq 0) {
            $destinationPath = $vhd.ParentPath
            # first remove $vm snapshots
            Get-VMSnapshot $vm | Remove-VMSnapshot -confirm:$false
            Merge-VHD -Path $diskPath -DestinationPath $destinationPath
          }
          # merge to new vhd
          else {
            $newVhdName = $mergeActionData.newVhdName
            $newVhdPath = $mergeActionData.newVhdPath
            $vhdType = $mergeActionData.vhdType
            $newVhdFormat = $mergeActionData.newVhdFormat

            $vhdFormat = "vhdx"
            if ($newVhdFormat -eq 2 ) {
              $vhdFormat = "vhd"
            }

            $destinationPath = "$newVhdPath\$newVhdName.$vhdFormat"

            if ($vhdType -eq 2) {
              Convert-VHD -Path $diskPath -DestinationPath $destinationPath -VHDType Fixed
            }
            if ($vhdType -eq 3) {
              Convert-VHD -Path $diskPath -DestinationPath $destinationPath -VHDType Dynamic
            }
            if ($attachVhd) {
              # create the drive with the VHD
              Add-VMHardDiskDrive -VM $vm -Path $destinationPath -ErrorAction SilentlyContinue
            }
          }
        }
      }
    }
  }

  foreach ($dvdToEdit in $dvdsToEdit) {
    $dvd = $alldvds | Where-Object { $_.Id.ToString() -ieq $dvdToEdit.Id }
    $err = $null
    if (-not $dvd) {
      Write-Warning $strings.VirtualMachineDvdEditDiskNotFound -f $dvdToEdit.Id, $vm.Name
      continue
    }

    if ($dvdToEdit.Path) {
      $dvdToEdit.Path = $dvdToEdit.Path.Trim()
    }

    if ($dvdToEdit.IsEjectableDisk) {
      $dvdToEdit.Path = $null
    }
    if (-not $dvdToEdit.Path) {
      $dvdToEdit.Path = $null
    }
    Set-VMDvdDrive -VMDvdDrive $dvd -Path $dvdToEdit.path -ErrorAction SilentlyContinue -ErrorVariable +err

    if (!!$err) {
      Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: There was an error setting the virtual machine DVD Drive $vmId. Error: $err" -ErrorAction SilentlyContinue

      Write-Error @($err)[0]

      return $null
    }
  }

  # find an IDE controller to add the disk to. Booting from SCSI is only supported in generation 2 VMs.
  # for GEn1 VMs, we use IDE, for Gen2, use SCSI, (GEn 2 machines don't support IDE bus).
  # IDE is the preferred controller for Gen1 VMs so we just need to create scsi controllers if the IDE controller is busy
  # If a controller doesn't exist, then create the controller, if all the controllers are busy, then use SCSI.
  # a VM can have 4 scsi  controllers and 64 devices per controller so we will fill them as needed
  # DVDs are only supported in IDE controllers for Gen1
  function CreateControllerIfNeeded ($drive) {
    # $vm.VirtualMachineSubType is not available in 2012R2
    # $isGen1 = $vm.VirtualMachineSubType -eq [Microsoft.HyperV.PowerShell.VirtualMachineSubType]::Generation1
    $isServer2012 = [Environment]::OSVersion.Version.Major -eq 6 -and [Environment]::OSVersion.Version.Minor -eq 2

    # VM.Generation property was added in Windows Server 2012 R2.  For Windows Server 2012 it is safe to assume the
    # generation is 1...
    if ($isServer2012) {
      $isGen1 = $true
    }
    else {
      $isGen1 = $vm.Generation -eq 1
    }

    $checkScsiControllers = $true
    if ($isGen1) {
      # There are always 2 IDE controllers with two locations each, so if one is free we are good for this disk
      $ideControllers = @(Get-VMIdeController -VM $vm)
      $drives = 0

      foreach ($ideController in $ideControllers) {
        $drives += $ideController.Drives.Count
      }

      # Do we have room for another IDE controller?
      if ($drives -lt 4) {
        # we need to check the scsi controllers
        $checkScsiControllers = $false
      }
    }

    # Add a SCSI controller if necessary
    if ($checkScsiControllers) {
      $scsiControllers = @(Get-VMScsiController -VM $vm)
      if (-not $scsiControllers) {
        Add-VMScsiController -VM $vm -ErrorAction SilentlyContinue
      }
      else {
        $addController = $true
        foreach ($controller in $scsiControllers) {
          if ($controller.Drives.Length -lt 64) {
            $addController = $false
            break
          }
        }

        if ($addController) {
          Add-VMScsiController -VM $vm -ErrorAction SilentlyContinue
        }
      }
    }
  }

  if ($disksToCreate) {
    # $vm.VirtualMachineSubType is not available in 2012R2
    # $isGen1 = $vm.VirtualMachineSubType -eq [Microsoft.HyperV.PowerShell.VirtualMachineSubType]::Generation1
    $isServer2012 = [Environment]::OSVersion.Version.Major -eq 6 -and [Environment]::OSVersion.Version.Minor -eq 2

    # VM.Generation property was added in Windows Server 2012 R2.  For Windows Server 2012 it is safe to assume the
    # generation is 1...
    if ($isServer2012) {
      $isGen1 = $true
    }
    else {
      $isGen1 = $vm.Generation -eq 1
    }

    foreach ($diskToCreate in $disksToCreate) {
      CreateControllerIfNeeded $diskToCreate

      if ($diskToCreate.isNewDiskEmpty) {
        $fullPathToVhd = ""
        $vhdPath = $diskToCreate.newVhdData.data.vhdPath.Trim()
        $vhdName = $diskToCreate.newVhdData.data.vhdName.Trim()
        $vhdType = $diskToCreate.newVhdData.data.vhdType

        $vhdPath = Join-Path $vhdPath "$vhdName.vhdx"

        # fixed disk
        if ($vhdType -eq 2) {
          $vhdCreateOption = $diskToCreate.newVhdData.data.vhdCreateOption

          # empty vhd
          if ($vhdCreateOption -eq 0) {
            $vhdSize = $diskToCreate.newVhdData.data.vhdSize * 1024 * 1024 * 1024
            $vhd = New-VHD -Path $vhdPath -SizeBytes $vhdSize -Fixed
          }

          # copy a physical hard disk
          if ($vhdCreateOption -eq 1) {
            $physicalHardDiskToCopyFrom = $diskToCreate.newVhdData.data.physicalHardDiskToCopyFrom.number
            $vhd = New-VHD -Path $vhdPath -SourceDisk $physicalHardDiskToCopyFrom  -Fixed
          }

          # copy a virtual hard disk
          if ($vhdCreateOption -eq 2) {
            $virtualDiskPathToCopyFrom = $diskToCreate.newVhdData.data.virtualDiskPathToCopyFrom.trim()
            Convert-VHD -Path $virtualDiskPathToCopyFrom -DestinationPath $vhdPath  -VHDType Fixed
            $vhd = Get-VHD $vhdPath
          }
        }

        # dynamic disk
        if ($vhdType -eq 3) {
          $vhdCreateOption = $diskToCreate.newVhdData.data.vhdCreateOption

          # empty vhd
          if ($vhdCreateOption -eq 0) {
            $vhdSize = $diskToCreate.newVhdData.data.vhdSize * 1024 * 1024 * 1024
            $vhd = New-VHD -Path $vhdPath -SizeBytes $vhdSize -Dynamic
          }

          # copy a physical hard disk
          if ($vhdCreateOption -eq 1) {
            $physicalHardDiskToCopyFrom = $diskToCreate.newVhdData.data.physicalHardDiskToCopyFrom.number
            $vhd = New-VHD -Path $vhdPath -SourceDisk $physicalHardDiskToCopyFrom  -Dynamic
          }

          # copy a virtual hard disk
          if ($vhdCreateOption -eq 2) {
            $virtualDiskPathToCopyFrom = $diskToCreate.newVhdData.data.virtualDiskPathToCopyFrom.trim()
            Convert-VHD -Path $virtualDiskPathToCopyFrom -DestinationPath $vhdPath  -VHDType Dynamic
            $vhd = Get-VHD $vhdPath
          }
        }

        # differencing disk
        if ($vhdType -eq 4) {
          $parentVhdPath = $diskToCreate.newVhdData.data.parentVhdPath.trim()
          $vhd = New-VHD -ParentPath $parentVhdPath -Path $vhdPath -Differencing
        }

        $fullPathToVhd = $vhd.Path
      }
      else {
        $fullPathToVhd = $diskToCreate.Path.trim()
      }

      # create the drive with the VHD
      Add-VMHardDiskDrive -VM $vm -Path $fullPathToVhd -ErrorAction SilentlyContinue
    }
  }

  if ($dvdsToCreate) {
    foreach ($dvdToCreate in $dvdsToCreate) {
      CreateControllerIfNeeded $dvdToCreate

      if ($dvdToCreate.Path) {
        $dvdToCreate.Path = $dvdToCreate.Path.Trim()
      }

      $fullPathToIso = $dvdToCreate.Path

      # create the drive with the ISO
      Add-VMDvdDrive -VM $vm -Path $fullPathToIso -ErrorAction SilentlyContinue
    }
  }
}

# The following must be kept in sync with Get-VirtualMachineDiskSettings
function GetDiskSettings($vmId) {
  $defaultPath = ""
  $vm = Get-RBACVM -id $vmId
  $disks = @($vm | Get-VMHardDiskDrive | Microsoft.PowerShell.Utility\Select-Object vmname, vmid, IsDeleted, name, id, controllerType, controllerLocation, controllerNumber, path, @{l = $DiskVhdFormatPropertyName; e = { getVhdFormat $_.path } }, @{l = $DiskSizePropertyName; e = { getSize $_.path } })
  $dvds = @($vm | Get-VMDvdDrive | Microsoft.PowerShell.Utility\Select-Object vmname, vmid, IsDeleted, name, id, controllerType, controllerLocation, controllerNumber, path)

  foreach ($disk in $disks) {
    $path = $disk.path.substring(0, $disk.path.lastIndexOf('\') + 1)
    Write-Host $path
    if ($path -and (Test-Path $path)) {
      $defaultPath = $path
      break
    }
  }

  if (-not $defaultPath -and $vm.Path -and (Test-Path $vm.Path)) {
    $defaultPath = $vm.Path + '\Virtual Hard Disks'
    if (-not (Test-Path $defaultPath)) {
      $defaultPath = $vm.Path
    }
  }

  if (-not $defaultPath -or -not (Test-Path $defaultPath)) {
    $defaultPath = (Get-VMHost).VirtualHardDiskPath
  }

  $result = @{}

  $result.defaultPath = $defaultPath
  $result.disks = $disks
  $result.dvds = $dvds

  return $result
}

function main(
  $vmId,
  $disksToDelete,
  $disksToCreate,
  $disksToEdit,
  $dvdsToDelete,
  $dvdsToCreate,
  $dvdsToEdit
) {
  # Ensure this is cleared
  $error.Clear()

  # Save the settings
  SaveDiskSettings $vmId $disksToDelete $disksToCreate $disksToEdit $dvdsToDelete $dvdsToCreate $dvdsToEdit

  # Whilst saving the disk settings one, or more, of the Hyper-V cmdlets called will call Update-ClusterVirtualMachineConfiguration
  # under the covers.  The issue is that cmdlet was never written to work in a remote PS session.  And, the Hyper-V cmdlets
  # pass the cluster name instead of the more appropriate "." (this server).  This means that when the VM and the cluster name
  # reside on different cluster nodes a double hop is introduced. Since it is not feasible to fix the
  # Update-ClusterVirtualMachineConfiguration cmdlet, the following work around is the best solution available.
  #
  # The work around is to retry the Update-ClusterVirtualMachineConfiguration cmdlet anytime there is a message in $error
  # from that cmdlet.  This retry is done using the cluster name "." -- shorthand for "this server".

  # Were there any errors?
  if ($error.Count -gt 0) {
    $retry = $false

    # Must check each error looking for any Update-ClusterVirtualMachineConfiguration errors
    foreach ($err in $error) {
      # If the error has an exception use the exception
      if ($err.PSObject.Properties.Match("Exception")) {
        $ex = $err.Exception
      }
      else {
        # If the error is an ErrorRecord reach down and get the exception
        if ($err.PSObject.Properties.Match("ErrorRecord")) {
          $ex = $err.ErrorRecord.Exception
        }
      }

      # Did the exception message come from Update-ClusterVirtualMachineConfiguration?  If it did check the server for being
      # a cluster node
      if ($ex -and $ex.Message -match "Update-ClusterVirtualMachineConfiguration") {
        $hostName = hostname
        $node = Get-ClusterNode -Name $hostName.ToString() -ErrorAction SilentlyContinue

        # If this server is a cluster node then set the flag and break
        if ($node -and $node.State -eq "Up") {
          $retry = $true
          break
        }
      }
    }

    # Are we going to retry the Update-ClusterVirtualMachineConfiguration cmdlet?
    if ($retry) {
      # Clear the errors so that any new Update-ClusterVirtualMachineConfiguration failures are reported
      $error.Clear()

      # Retry the cmdlet using the local host -- in case the previous failure was a double hop failure
      # Any new errors will be sent back to the UI
      #
      # Note: Warnings from this cmdlet are not being sent back to the UI -- and they should be since
      # they most likely detail that the VM is not properly configured for hosting in a cluster.
      Update-ClusterVirtualMachineConfiguration -Cluster "." -VmId $vmId
    }
  }

  GetDiskSettings $vmId

  if ($error.Count -gt 0) {
    throw $error
  }
}

###############################################################################
# Script execution starts here...
###############################################################################

if (-not ($env:pester)) {
  setupScriptEnv

  try {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    $hyperVModule = Get-Module -Name Hyper-V -ErrorAction SilentlyContinue

    if (-not($hyperVModule)) {
      Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: The required PowerShell module (Hyper-V) was not found." -ErrorAction SilentlyContinue

      Write-Error $strings.HyperVModuleRequired

      return $null
    }

    return main $vmId $disksToDelete $disksToCreate $disksToEdit $dvdsToDelete $dvdsToCreate $dvdsToEdit

  }
  finally {
    cleanupScriptEnv
  }
}

}
## [END] Set-WACVMVirtualMachineDisksSettings ##
function Set-WACVMVirtualMachineIntegrationServices {
<#

.SYNOPSIS
Enable/Disable integration services

.DESCRIPTION
Sets the boolean value for the respective integration service components as provided.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER vmId
The Id of the requested virtual machine.

.PARAMETER toEnable
The services to enable

.PARAMETER toDisable
The services to disable

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $vmId,
    [Parameter(Mandatory = $false)]
    [String[]]
    $toEnable,
    [Parameter(Mandatory = $false)]
    [String[]]
    $toDisable
)

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue
Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

###############################################################################
# Constants
###############################################################################

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value Set-VirtualMachineIntegrationServices.ps1 -Scope Script
}

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
}

function main(
  $vmId,
  $toEnable,
  $toDisable) {
    $vm = Get-RBACVM -id $vmId -ErrorAction SilentlyContinue
    if (-not $vm) {
      return
    }

    foreach ($serviceToEnable in $toEnable) {
      $vm |  Enable-VMIntegrationService -Name $serviceToEnable
    }

    foreach ($serviceToDisable in $toDisable) {
      $vm |  Disable-VMIntegrationService -Name $serviceToDisable
    }

    return $vm | Get-VMIntegrationService | `
    Microsoft.PowerShell.Utility\Select-Object vmname, vmid, IsDeleted, Name, Enabled, PrimaryStatusDescription, SecondaryStatusDescription
}

###############################################################################
# Script execution starts here...
###############################################################################

if (-not($env:pester)) {
  setupScriptEnv

  try {
      Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

      $hyperVModule = Get-Module -Name Hyper-V -ErrorAction SilentlyContinue

      if (-not($hyperVModule)) {
          Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
              -Message "[$ScriptName]: The required PowerShell module (Hyper-V) was not found." -ErrorAction SilentlyContinue

          Write-Error $strings.HyperVModuleRequired

          return $null
      }

      return main $vmId $toEnable $toDisable

  } finally {
      cleanupScriptEnv
  }
}

}
## [END] Set-WACVMVirtualMachineIntegrationServices ##
function Set-WACVMVirtualMachineKvpHostOnlyProperty {
<#

.SYNOPSIS
Set the Key Value Exchange HostOnlyProperty property on the passed in virtual machines.

.DESCRIPTION
Set the Key Value Exchange property for the passed in virtual machine on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER vmIds
  	The Ids of the virtual machines.

.PARAMETER propertyName
	The name of the property to add to the HostOnlyItems of the passed in virtual machines (by Id)

.PARAMETER propertyValue
	The value of the property to add to the HostOnlyItems of the passed in virtual machines (by Id)

#>

param (
    [Parameter(Mandatory = $true)]
    [Object[]] $models
)

Set-StrictMode -Version 5.0

Import-Module CimCmdlets -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.  Create read only (constant) variables
that add context to the said constants.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScript" -Scope Script
	Set-Variable -Name ScriptName -Option ReadOnly -Value "Set-VirtualMachineKvpHostOnlyProperty.ps1" -Scope Script
	Set-Variable -Name VirtualizationNamespace -Option ReadOnly -Value "root\virtualization\v2" -Scope Script
	Set-Variable -Name MsvmComputerSystemClassName -Option ReadOnly -Value "Msvm_ComputerSystem" -Scope Script
	Set-Variable -Name MsvmSystemDeviceClassName -Option ReadOnly -Value "Msvm_SystemDevice" -Scope Script
	Set-Variable -Name HostOnlyItemsSourceValue -Option ReadOnly -Value 4 -Scope Script
	Set-Variable -Name DataPropertyName -Option ReadOnly -Value "Data" -Scope Script
	Set-Variable -Name MsvmVirtualSystemManagementServiceClassName -Option ReadOnly -Value "Msvm_VirtualSystemManagementService" -Scope Script
	Set-Variable -Name MsvmElementSettingDataClassName -Option ReadOnly -Value "Msvm_ElementSettingData" -Scope Script
	Set-Variable -Name MsvmKvpExchangeComponentSettingDataClassName -Option ReadOnly -Value "Msvm_KvpExchangeComponentSettingData" -Scope Script
	Set-Variable -Name MsvmKvpExchangeDataItemClassName -Option ReadOnly -Value "Msvm_KvpExchangeDataItem" -Scope Script
	Set-Variable -Name LocalHost -Option ReadOnly -Value "LocalHost" -Scope Script
	Set-Variable -Name NamePropertyName -Option ReadOnly -Value "Name" -Scope Script
	Set-Variable -Name SourcePropertyName -Option ReadOnly -Value "Source" -Scope Script
	Set-Variable -Name DataItemsParameterName -Option ReadOnly -Value "DataItems" -Scope Script
	Set-Variable -Name AddKvpItemsMethodName -Option ReadOnly -Value "AddKvpItems" -Scope Script
	Set-Variable -Name TargetSystemParameterName -Option ReadOnly -Value "TargetSystem" -Scope Script
	Set-Variable -Name ErrorPropertyValue -Option ReadOnly -Value "Error" -Scope Script
	Set-Variable -Name StatusPropertyName -Option ReadOnly -Value "Status" -Scope Script
	Set-Variable -Name ErrorDescriptionPropertyName -Option ReadOnly -Value "ErrorDescription" -Scope Script
	Set-Variable -Name ModifyKvpItemsMethodName -Option ReadOnly -Value "ModifyKvpItems" -Scope Script
	Set-Variable -Name HostOnlyItemsPropertyName -Option ReadOnly -Value "HostOnlyItems" -Scope Script
    Set-Variable -Name MsvmVirtualSystemSettingDataComponentClassName -Option ReadOnly -Value "Msvm_VirtualSystemSettingDataComponent" -Scope Script
    Set-Variable -Name MsvmVirtualSystemSettingDataClassName -Option ReadOnly -Value "Msvm_VirtualSystemSettingData" -Scope Script
    Set-Variable -Name MsvmSettingsDefineStateClassName -Option ReadOnly -Value "Msvm_SettingsDefineState" -Scope Script
}

<#

.SYNOPSIS
Cleanup the script environment.

.DESCRIPTION
Cleanup the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name VirtualizationNamespace -Scope Script -Force
    Remove-Variable -Name MsvmComputerSystemClassName -Scope Script -Force
	Remove-Variable -Name MsvmSystemDeviceClassName -Scope Script -Force
	Remove-Variable -Name HostOnlyItemsSourceValue -Scope Script -Force
	Remove-Variable -Name DataPropertyName -Scope Script -Force
	Remove-Variable -Name MsvmVirtualSystemManagementServiceClassName -Scope Script -Force
	Remove-Variable -Name MsvmElementSettingDataClassName -Scope Script -Force
	Remove-Variable -Name MsvmKvpExchangeComponentSettingDataClassName -Scope Script -Force
	Remove-Variable -Name MsvmKvpExchangeDataItemClassName -Scope Script -Force
	Remove-Variable -Name LocalHost -Scope Script -Force
	Remove-Variable -Name NamePropertyName -Scope Script -Force
	Remove-Variable -Name SourcePropertyName -Scope Script -Force
	Remove-Variable -Name DataItemsParameterName -Scope Script -Force
	Remove-Variable -Name AddKvpItemsMethodName -Scope Script -Force
	Remove-Variable -Name TargetSystemParameterName -Scope Script -Force
	Remove-Variable -Name ErrorPropertyValue -Scope Script -Force
	Remove-Variable -Name StatusPropertyName -Scope Script -Force
	Remove-Variable -Name ErrorDescriptionPropertyName -Scope Script -Force
	Remove-Variable -Name ModifyKvpItemsMethodName -Scope Script -Force
	Remove-Variable -Name HostOnlyItemsPropertyName -Scope Script -Force
	Remove-Variable -Name MsvmVirtualSystemSettingDataComponentClassName -Scope Script -Force
	Remove-Variable -Name MsvmVirtualSystemSettingDataClassName -Scope Script -Force
	Remove-Variable -Name MsvmSettingsDefineStateClassName -Scope Script -Force
}

<#

.SYNOPSIS
Get the VM Management Service instance for this host server.

.DESCRIPTION
Get the VM Management Service instance for this host server.

#>

function getVMMangementService() {
	$err = $null

	$managementService = Get-CimInstance -Namespace $VirtualizationNamespace -ClassName $MsvmVirtualSystemManagementServiceClassName `
		-ErrorAction SilentlyContinue -ErrorVariable +err
	if ($err) {
		Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
			-Message "[$ScriptName]: Couldn't get the virtual system managment service CIM instance. Error: $err" -ErrorAction SilentlyContinue

		Write-Error @($err)[0]

		return $null
	}

	return $managementService
}

<#

.SYNOPSIS
Get the guest CIM instance of the passed in value pair exchange.

.DESCRIPTION
Get the guest CIM instance of the passed in value pair exchange.

#>

function getGuestKvp($settingsData) {
	$err = $null

	$guestKvp = Get-CimAssociatedInstance -InputObject $settingsData -Association $MsvmVirtualSystemSettingDataComponentClassName -ResultClassName $MsvmKvpExchangeComponentSettingDataClassName `
		-ErrorAction SilentlyContinue -ErrorVariable +err
	if ($err) {
		Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
			-Message "[$ScriptName]: Couldn't get the guest KVP instance. Error: $err" -ErrorAction SilentlyContinue

		Write-Error @($err)[0]

		return $null
	}

	return $guestKvp
}

<#

.SYNOPSIS
Get the CIM instance of the passed in virtual machine's settings data.

.DESCRIPTION
Get the CIM instance of the passed in virtual machine's settings data.

#>

function getSettingsData($vm) {
	$err = $null

	$settingsData = Get-CimAssociatedInstance -InputObject $vm -Association $MsvmSettingsDefineStateClassName -ResultClassName $MsvmVirtualSystemSettingDataClassName `
		-ErrorAction SilentlyContinue -ErrorVariable +err

	if ($err) {
		$vmName = $vm.ElementName

		Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
			-Message "[$ScriptName]: Couldn't get the settings data component for virtual machine $vmName. Error: $err" -ErrorAction SilentlyContinue

		Write-Error @($err)[0]

		return $null
	}

	return $settingsData
}


<#

.SYNOPSIS
Get the CIM instance of the passed in VM Id.

.DESCRIPTION
Get the CIM instance of the passed in VM Id.

#>

function getVm([string] $vmId) {
	$err = $null

	$vm = Get-CimInstance -namespace $VirtualizationNamespace -ClassName $MsvmComputerSystemClassName -filter "$NamePropertyName = '$($vmId)'" `
		-ErrorAction SilentlyContinue -ErrorVariable +err

	if ($err) {
		Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
			-Message "[$ScriptName]: Couldn't get the CIM instance for virtual machine Id $vmId. Error: $err" -ErrorAction SilentlyContinue

		Write-Error @($err)[0]

		return $null
	}

	return $vm
}

<#

.SYNOPSIS
Get the value of the passed in property from the guest key value pair exchange hostOnlyItems.

.DESCRIPTION
Get the value of the passed in property from the guest key value pair exchange hostOnlyItems.

#>

function getHostOnlyProperty($vm, $guestKvp, [string] $propertyName) {
	try {
		return (([xml]($guestKvp.$HostOnlyItemsPropertyName | `
			Microsoft.PowerShell.Core\Where-Object {$_ -match $propertyName})).instance.property | `
			Microsoft.PowerShell.Core\Where-Object {$_.Name -eq $DataPropertyName}).Value
	} catch {
		return $null
	}
}

<#

.SYNOPSIS
Write the propertyName/propertyValue pair as HostOnlyItems

.DESCRIPTION
Write the propertyName/propertyValue pair as HostOnlyItems

#>

function writeHostOnlyProperty(
	$vm,
	$managementService,
	$guestKvp,
	$serializer,
	[string] $propertyName,
	[string] $propertyValue
) {
	$err = $null

	$vmName = $vm.ElementName
	$props = @{
		$NamePropertyName = $propertyName;
		$DataPropertyName = $propertyValue;
		$SourcePropertyName = [UInt16]$HostOnlyItemsSourceValue
	}

	$dataItem = New-CimInstance -ClassName $MsvmKvpExchangeDataItemClassName -Namespace $VirtualizationNamespace -Property $props -ClientOnly -ErrorAction SilentlyContinue -ErrorVariable +err
	if ($err -or -not($dataItem)) {

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        	-Message "[$ScriptName]: Couldn't create the CIM instance of $MsvmKvpExchangeDataItemClassName. Error: $err" -ErrorAction SilentlyContinue

		Write-Error @($err)[0]

		return
	}

	try {
		$temp = $serializer.Serialize($dataItem, [Microsoft.Management.Infrastructure.Serialization.InstanceSerializationOptions]::None)
		$param = [System.Text.Encoding]::Unicode.GetString($temp)
	} catch {
		$errMsg = $_.Exception.Message

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
			-Message "[$ScriptName]: Couldn't serialze the KVP data item. Error: $errMsg" -ErrorAction SilentlyContinue

		Write-Error $errMsg

		return
	}

	$arguments = @{
		$TargetSystemParameterName = $vm;
		$DataItemsParameterName = @($param)
	}

	# Determine if we are adding or modifying the HostOnlyItems...
	$method = $AddKvpItemsMethodName
	if ($guestKvp.$HostOnlyItemsPropertyName) {
		$tempPropertyValue = getHostOnlyProperty $vm $guestKvp $propertyName

		if ($tempPropertyValue) {
			$method = $ModifyKvpItemsMethodName
		}
	}

	$outParam = $managementService | Invoke-CimMethod -MethodName $method -Arguments $arguments -ErrorAction SilentlyContinue -ErrorVariable +err

	if ($err) {
		Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
			-Message "[$ScriptName]: Couldn't save the host only property $propertyName on virtual machine $vmName. Error: $err" -ErrorAction SilentlyContinue

		Write-Error @($err)[0]

		return
	}

	$job = Get-CimInstance -InputObject $outParam.Job -ErrorAction SilentlyContinue -ErrorVariable +err
	if ($err) {
		Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
			-Message "[$ScriptName]: Couldn't get the job when saving the HostOnlyItems KVP. Error: $err" -ErrorAction SilentlyContinue

		Write-Error @($err)[0]

		return
	}

	if ($job.$StatusPropertyName -eq $ErrorPropertyValue) {
		$err = $job.$ErrorDescriptionPropertyName

		Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
			-Message "[$ScriptName]: There was an error saving the HostOnlyItems KVP. Error: $err" -ErrorAction SilentlyContinue

		Write-Error @($err)[0]

		return
	}
}

<#

.SYNOPSIS
Main

.DESCRIPTION
An explicit main function to fetch the settings.

#>

function main([Object[]] $models) {
  $managementService = getVMMangementService
	if (-not ($managementService)) {
		return $false
	}

	try {
		$serializer = [Microsoft.Management.Infrastructure.Serialization.CimSerializer]::Create()
	} catch {
		$errMsg = $_.Exception.Message

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
			-Message "[$ScriptName]: Couldn't create the required CIM Serialzer. Error: $errMsg" -ErrorAction SilentlyContinue

		Write-Error $errMsg

		return $false
	}

	foreach ($model in $models) {
		$vm = getVm $model.vmId
		if (-not ($vm)) {
			continue
		}

        $settingsData = getSettingsData $vm
        if (-not ($settingsData)) {
            return @{}
        }
        
        $guestKvp = getGuestKvp $settingsData
        if (-not ($guestKvp)) {
            return @{}
        }
    
		writeHostOnlyProperty $vm $managementService $guestKvp $serializer $model.propertyName $model.propertyValue
	}

	return $true
}

###############################################################################
# Script execution starts here.
###############################################################################

if (-not($env:pester)) {
    setupScriptEnv

    try {
		$err = $null

        Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

        $namespace = Get-CimInstance -Namespace $VirtualizationNamespace -Class __Namespace -ErrorAction SilentlyContinue -ErrorVariable +err
        if (-not ($err)) {
            return main $models
        }

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
			-Message "[$ScriptName]: The required CIM namepace ($VirtualizationNamespace) was not found. Error: $err" -ErrorAction SilentlyContinue

		Write-Error @($err)[0]

        return @{}
    } finally {
        cleanupScriptEnv
    }
}

}
## [END] Set-WACVMVirtualMachineKvpHostOnlyProperty ##
function Set-WACVMVirtualMachineMemorySettings {
<#

.SYNOPSIS
Sets the memory settings for the passed in virtual machine.

.DESCRIPTION
Sets the memory settings for the passed in virtual machine on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER vmId
    The Id of the requested virtual machine.

.PARAMETER dynamicMemoryEnabled

.PARAMETER maximum

.PARAMETER minimum

.PARAMETER startup

.PARAMETER priority

.PARAMETER buffer

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $vmId,
    [Parameter(Mandatory = $true)]
    [bool]
    $dynamicMemoryEnabled,
    [Parameter(Mandatory = $false)]
    [long]
    $maximum,
    [Parameter(Mandatory = $false)]
    [long]
    $minimum,
    [Parameter(Mandatory = $true)]
    [long]
    $startup,
    [Parameter(Mandatory = $true)]
    [long]
    $priority,
    [Parameter(Mandatory = $false)]
    [int]
    $buffer
)

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.  Create read only (constant) variables
that add context to the said constants.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Set-VirtualMachineMemorySettings.ps1" -Scope Script
    Set-Variable -Name HyperVModuleName -Option ReadOnly -Value "Hyper-V" -Scope Script
}    

<#

.SYNOPSIS
Cleanup the script environment.

.DESCRIPTION
Cleanup the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
}

<#

.SYNOPSIS
Main

.DESCRIPTION
Saves the passed in memory settings on the virtual machine...

.PARAMETER parameters

#>
function main(
    [string] $vmId,
    [bool] $dynamicMemoryEnabled,
    [long] $maximum,
    [long] $minimum,
    [long] $startup,
    [long] $priority,
    [int] $buffer
) {
    $vm = Get-RBACVM -id $vmId -ErrorAction SilentlyContinue -ErrorVariable +err

    if (!!$err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: There was an error getting the virtual machine with Id $vmId. Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]
    
        return $null
    }

    $args = @{
        "DynamicMemoryEnabled" = $dynamicMemoryEnabled;
        "StartupBytes" =  $startup;
        "Priority" = $priority;
    }

    if ($dynamicMemoryEnabled) {
        $args += @{
            "MaximumBytes" =  $maximum;
            "MinimumBytes" = $minimum;
            "Buffer" = $buffer;
        }
    }
  
    $vm | Set-VMMemory @args -ErrorAction SilentlyContinue -ErrorVariable +err

    if (!!$err) {
        $vmName = $vm.Name

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: There was an error saving the memory settings for virtual machine $vmName. Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]
    
        return @{}
    }

    $settings = ($vm | Get-VMMemory -ErrorAction SilentlyContinue -ErrorVariable +err | `
        Microsoft.PowerShell.Utility\Select-Object VMName, VMId, DynamicMemoryEnabled, Maximum, IsDeleted, Minimum, Startup, Priority, Buffer)

    if (!!$err) {
        $vmName = $vm.Name

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: There was an error getting the memory settings for virtual machine $vmName. Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]
    
        return @{}
    }

    return $settings
}

###############################################################################
# Script execution starts here
###############################################################################

if (-not ($env:pester)) {
    setupScriptEnv

    try {
        $hyperVModule = Get-Module -Name $HyperVModuleName -ErrorAction SilentlyContinue

        if (-not($hyperVModule)) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: The required PowerShell module (Hyper-V) was not found." -ErrorAction SilentlyContinue
        
            Write-Error $strings.HyperVModuleRequired
            
            return @{}
        }

        return main $vmId $dynamicMemoryEnabled $maximum $minimum  $startup $priority $buffer
    
    } finally {
        cleanupScriptEnv
    }
}

}
## [END] Set-WACVMVirtualMachineMemorySettings ##
function Set-WACVMVirtualMachineNetworkSettings {
<#

.SYNOPSIS
Sets the network adapter settings for the passed in virtual machine.

.DESCRIPTION
Sets the network adapter settings for the passed in virtual machine on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER vmId
    The Id of the requested virtual machine.

.PARAMETER adaptersToDelete
    Optional array of virtual network adapters to delete from the passed in virtual machine.

.PARAMETER adaptersToCreate
    Optional array of virtual network adapters to add tothe passed in virtual machine.

.PARAMETER adaptersToEdit
    Optional array of virtual network adapters to change on the passed in virtual machine.
#>

param (
    [Parameter(Mandatory = $true)]
    [string]
    $vmId,
    [Parameter(Mandatory = $false)]
    [ValidateNotNull()]
    [object[]]
    $adaptersToDelete = @(),
    [Parameter(Mandatory = $false)]
    [ValidateNotNull()]
    [object[]]
    $adaptersToCreate = @(),
    [Parameter(Mandatory = $false)]
    [ValidateNotNull()]
    [object[]]
    $adaptersToEdit = @()
)

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue


###############################################################################
# Constants
###############################################################################

Set-Variable -Name LogName -Option Constant -Value "Microsoft-ServerManagementExperience" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SMEScripts" -ErrorAction SilentlyContinue
Set-Variable -Name ScriptName -Option Constant -Value "Set-VirtualMachineNetworkSettings.ps1" -ErrorAction SilentlyContinue
Set-Variable -Name PortProfileFeatureId -Option Constant -Value "9940cd46-8b06-43bb-b9d5-93d50381fd56" -ErrorAction SilentlyContinue
Set-Variable -Name PortProfileNetCfgInstanceId -Option Constant -Value "{56785678-a0e5-4a26-bc9b-c0cba27311a3}" -ErrorAction SilentlyContinue
Set-Variable -Name NetworkControllerVendorId -Option Constant -Value "{1FA41B39-B444-4E43-B35A-E1F7985FD548}" -ErrorAction SilentlyContinue
Set-Variable -Name NetworkControllerVendorName -Option Constant -Value "NetworkController" -ErrorAction SilentlyContinue
Set-Variable -Name NetworkControllerCdnLabelName -Option Constant -Value "TestCdn" -ErrorAction SilentlyContinue
Set-Variable -Name NetworkControllerCdnLabelId -Option Constant -Value 1111 -ErrorAction SilentlyContinue
Set-Variable -Name NetworkControllerProfileName -Option Constant -Value "Testprofile" -ErrorAction SilentlyContinue
Set-Variable -Name PortProfileVlan -Option Constant -Value 2 -ErrorAction SilentlyContinue
Set-Variable -Name PortProfileDefault -Option Constant -Value 0 -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Types of SDN network connections

.DESCRIPTION
This enum is used to determine what type of SDN connection we are creating.

#>
enum SdnNetworkType {
  None = 0
  Vlan = 1
  Vnet = 2
  Lnet = 3
}

function portProfileValues($feature, $adapterSettings) {
  $feature.SettingData.ProfileId = "{$([System.Guid]::Empty)}"

  if ($adapterSettings.sdnOptions.sdnNetworkType -eq [SdnNetworkType]::Vlan) {
      # else, we are setting vlan type, and guid should be empty and data type should be 2
      $feature.SettingData.ProfileData = $PortProfileVlan
  }
  else {
      $feature.SettingData.ProfileData = $PortProfileDefault
  }

  return $feature
}

function getPortProfileId($adapter) {
  try {
    $currentFeature = Get-VMSwitchExtensionPortFeature -FeatureId $PortProfileFeatureId -VMNetworkAdapter $adapter

    if ($null -ne $currentFeature) {
      return $currentFeature.SettingData.ProfileId
    } else {
      return $null
    }
  } catch {
    # This means there wasn't a port to reference
    return $null
  }
}

function setPortProfileId($adapter, $adapterToCreate) {

  # set port profile id
  $currentFeature = Get-VMSwitchExtensionPortFeature -FeatureId $PortProfileFeatureId -VMNetworkAdapter $adapter

  if ($null -eq $currentFeature) {
      $feature = Get-VMSystemSwitchExtensionPortFeature -FeatureId $PortProfileFeatureId
      # leave the following untouched. All of the IDs are hardcoded properly
      $feature.SettingData.NetCfgInstanceId = $PortProfileNetCfgInstanceId
      $feature.SettingData.CdnLabelstring = $NetworkControllerCdnLabelName
      $feature.SettingData.CdnLabelId = $NetworkControllerCdnLabelId
      $feature.SettingData.ProfileName = $NetworkControllerProfileName
      $feature.SettingData.VendorId = $NetworkControllerVendorId
      $feature.SettingData.VendorName = $NetworkControllerVendorName

      # Add port profile id and profileData separately to avoid repeating logic
      $feature = portProfileValues $feature $adapterToCreate
      Add-VMSwitchExtensionPortFeature -VMSwitchExtensionFeature $feature -VMNetworkAdapter $adapter
  } else {
      # Add port profile id and profileData separately to avoid repeating logic
      $currentFeature = portProfileValues $currentFeature $adapterToCreate
      Set-VMSwitchExtensionPortFeature -VMSwitchExtensionFeature $currentFeature -VMNetworkAdapter $adapter
  }
}

# Convert a WMI error into a PowerShell error that gets sent back to the client via the gateway.
function processWmiResult($result) {
    if ($Result.ReturnValue -ne 0) {
        $job = [WMI]$Result.Job;
        Write-Error $Job.ErrorDescription;
    }
}

function setNonSdnIsolation($adapter, $adapterSettings) {
  if ($adapterSettings.sdnOptions.sdnNetworkType -eq [SdnNetworkType]::Vlan) {
      switch ($adapterSettings.vlanMode) {
          ([int][Microsoft.HyperV.PowerShell.VMNetworkAdapterVlanMode]::Access) {
              Set-VMNetworkAdapterIsolation -VMNetworkAdapter $adapter -IsolationMode ([Microsoft.HyperV.PowerShell.VMNetworkAdapterIsolationMode]::None)
              set-vmnetworkadaptervlan -VMNetworkAdapter $adapter -Access -VlanId $adapterSettings.accessVlanId
          }

          ([int][Microsoft.HyperV.PowerShell.VMNetworkAdapterVlanMode]::Untagged) {
              Set-VMNetworkAdapterIsolation -VMNetworkAdapter $adapter -IsolationMode ([Microsoft.HyperV.PowerShell.VMNetworkAdapterIsolationMode]::None)
              set-vmnetworkadaptervlan -VMNetworkAdapter $adapter -Untagged
          }

          default {
              Write-Warning $strings.VirtualMachineNetworkEditAdapterVlanModeNotSupported -f $adapterSettings.id $vm.Name, $adapterSettings.vlanMode
          }
      }
      return
  } elseif ($adapterSettings.sdnOptions.sdnNetworkType -eq [SdnNetworkType]::None) {
      Set-VMNetworkAdapterIsolation -VMNetworkAdapter $adapter -IsolationMode ([Microsoft.HyperV.PowerShell.VMNetworkAdapterIsolationMode]::None)
      set-vmnetworkadaptervlan -VMNetworkAdapter $adapter -Untagged
  }
}

function main(
    [string]$vmId,
    [object[]]$adaptersToDelete,
    [object[]]$adaptersToCreate,
    [object[]]$adaptersToEdit) {
    $vm = Get-RBACVM -id $vmId

    if (-not $vm) {
        return
    }

    # removedNics and newAdapterIds are both used in potential SDN operations later
    $removedNics = [PSCustomObject]@{
      portProfiles = @()
      hypervNicMacAddresses = @()
      adapterIds = @()
    }

    $newAdapterIds = @() #list of adapterIDs - can be associated with

    $editPNics = @() #list of objects with an adapter ID, port profile ID, and mac address

    $alladapters = @(Get-VMNetworkAdapter -VM $vm)
    $adaptersIdMap = @{};

    # Fill the adapter to id map.
    foreach ($adapter in $alladapters) {
        $adaptersIdMap.Add($adapter.Id, $adapter)
    }

    # Process the adapters to delete first...
    foreach ($adapterToDelete in $adaptersToDelete) {
        $adapter = $adaptersIdMap[$adapterToDelete.Id]
        if (-not $adapter) {
            Write-Warning $strings.VirtualMachineNetworkDeleteAdapterNotFound -f $adapterToDelete.Id, $vm.Name
            continue;
        }

        # if SDN is enabled, there are NC nic objects for each hyper-v nic. Do cleanup for these.
        $removedNics.portProfiles += (getPortProfileId $adapter)
        $removedNics.adapterIds += $adapterToDelete.Id.Substring($adapterToDelete.Id.IndexOf('\') + 1)
        $removedNics.hypervNicMacAddresses += $adapterToDelete.MacAddress

        Remove-VMNetworkAdapter -VMNetworkAdapter $adapter
    }

    # Process the adapters to be added...
    foreach ($adapterToCreate in $adaptersToCreate) {
        Add-VMNetworkAdapter -VM $vm

        # add doesn't return the created adapter so we need to fetch it
        $adapter = $null
        $newAdapters = @(Get-VMNetworkAdapter -VM $vm)

        foreach ($newAdapter in $newAdapters) {
            if (-not $adaptersIdMap.ContainsKey($newAdapter.Id)) {
                $adapter = $newAdapter
                $alladapters += $adapter
                $adaptersIdMap.Add($adapter.Id, $adapter)
                $newAdapterIds += $adapter.Id
                break;
            }
        }

        if ($adapter) {
            setNonSdnIsolation -adapter $adapter -adapterSettings $adapterToCreate
            setPortProfileId $adapter $adapterToCreate

            $adapterToCreate.id = $adapter.id

            # we will set all the adavanced properties as edits with the rest of the adapters
            $adaptersToEdit += $adapterToCreate
        }
    }

    # Edit the existing adapters...
    for ($i = 0; $i -lt @($adaptersToEdit).Length; $i++) {
        $adapterToEdit = $adaptersToEdit[$i]
        $adapter = $adaptersIdMap[$adapterToEdit.Id]
        if (-not $adapter) {
            Write-Warning $strings.VirtualMachineNetworkEditAdapterNotFound -f $adapterToEdit.Id, $vm.Name
            continue;
        }

        # Set the isolation mode if specified
        setNonSdnIsolation -adapter $adapter -adapterSettings $adapterToEdit

        if ($adapterToEdit.switchId) {
            # Connect the switch if we need to
            if ($adapter.switchId -ne $adapterToEdit.switchId) {
                $vmSwitch = Get-VMSwitch -Id $adapterToEdit.switchId

                if ($vmSwitch) {
                    Connect-VMNetworkAdapter -VMNetworkAdapter $adapter -VMSwitch $vmSwitch
                }
            }
        } else {
            # Disconnect the switch if we need to
            if ($adapter) {
                Disconnect-VMNetworkAdapter -VMNetworkAdapter $adapter
            }
            continue
        }

        # AdvancedSettings
        # set-vmnetworkadapter is failing to set some values so we use WMI instead
        # Retrieve the Hyper-V Management Service, ComputerSystem class for the VM and the VM's SettingData class.

        # if the VM is not running then the mac address can be configured. 3 = Off
        if ($vm.state -eq 3) {
            $Msvm_VirtualSystemManagementService = Microsoft.PowerShell.Management\Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_VirtualSystemManagementService

            $wmiPortSettingData = Microsoft.PowerShell.Management\Get-WmiObject -Namespace root\virtualization\v2 -Class "Msvm_SyntheticEthernetPortSettingData" | Where-Object {$_.instanceID -eq $adapter.id}
            if ($adapterToEdit.dynamicMacAddressEnabled) {
                $wmiPortSettingData.StaticMacAddress = $false
                $wmiPortSettingData.Address = ""

                $result = $Msvm_VirtualSystemManagementService.ModifyResourceSettings($wmiPortSettingData.GetText(2))
                processWmiResult $result;
            } elseif ($null -ne $adapterToEdit.MacAddress) {
                # static mac address
                Set-VMNetworkAdapter $adapter -StaticMacAddress $adapterToEdit.MacAddress
            }
        }

        # other advanced settings:
        $arguments = @{MacAddressSpoofing=$adapterToEdit.macAddressSpoofing;};
        if ($adapterToEdit.maximumBandwidth -gt 0) {
            # # Sometimes the command would fail and once we investigate more maybe we need to follow the WMi to ensure it works all the time
            # $bandwidthSettingsData = Microsoft.PowerShell.Management\Get-WmiObject -Namespace root\virtualization\v2 -Class "Msvm_EthernetSwitchPortBandwidthSettingData" | where-object {$_.InstanceID.toLower().contains($adapter.Id.toLower()) }
            # # $bandwidthSettingsData = $wmiPortSettingData.GetRelated("Msvm_EthernetPortAllocationSettingData").GetRelated("Msvm_EthernetSwitchPortBandwidthSettingData")
            # TODO: if bandwidthSettingsData is null, then we need to create it
            # $bandwidthSettingsData.BurstLimit = $adapterToEdit.maximumBandwidth
            # $bandwidthSettingsData.BurstSize = $adapterToEdit.maximumBandwidth
            # $bandwidthSettingsData.Limit = $adapterToEdit.maximumBandwidth
            # $bandwidthSettingsData.Reservation = $adapterToEdit.minimumBandwidthAbsolute
            # $result = $Msvm_VirtualSystemManagementService.ModifyFeatureSettings($bandwidthSettingsData.GetText(2))
            # processWmiResult $result;
            $arguments += @{MaximumBandwidth=$adapterToEdit.maximumBandwidth}
            $arguments += @{MinimumBandwidthAbsolute=$adapterToEdit.minimumBandwidthAbsolute}
        } else {
            $arguments += @{MaximumBandwidth=0}
            $vmSwitch = Get-VMSwitch -Id $adapterToEdit.switchId
            if ($vmSwitch.BandwidthReservationMode -eq "Absolute") {
              $arguments += @{MinimumBandwidthAbsolute=0}
            }
        }

        Set-VMNetworkAdapter $adapter @arguments

        if ($adapterToEdit.sdnOptions.sdnNetworkType -ne [SdnNetworkType]::Lnet -and $adapterToEdit.sdnOptions.sdnNetworkType -ne [SdnNetworkType]::Vnet) {
            # If there is an existing nic with this mac address, remove it
            $removedNics.hypervNicMacAddresses += $adapterToEdit.MacAddress
            setPortProfileId $adapter $adapterToEdit
        }

        # Set up information to find a matching SDN NIC later
        $editPNics += [PSCustomObject]@{
          id = $adapter.Id
          profileId = (getPortProfileId $adapter)
          macAddress = $adapter.macAddress
        }
    }

    return [PSCustomObject]@{
        vmName = $vm.Name
        removedNics = $removedNics
        newAdapterIds = $newAdapterIds #list of adapterIDs - match order with adaptersToCreate
        editPNics = $editPNics
    }
}

###############################################################################
# Script execution starts here...
###############################################################################

if (-not ($env:pester)) {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    Start-Transcript -Append -IncludeInvocationHeader -Debug -Force -Confirm:$False | Out-Null

    $module = Get-Module -Name Hyper-V -ErrorAction SilentlyContinue
    if ($module) {
        $output = main $vmId $adaptersToDelete $adaptersToCreate $adaptersToEdit
        Stop-Transcript | Out-Null
        return $output
    }

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
    -Message "[$ScriptName]: Cannot continue because required Hyper-V PowerShell module was not found." -ErrorAction SilentlyContinue

    Stop-Transcript | Out-Null
}

}
## [END] Set-WACVMVirtualMachineNetworkSettings ##
function Set-WACVMVirtualMachineProcessorSettings {
<#

.SYNOPSIS
Sets the processor settings for the passed in virtual machine.

.DESCRIPTION
Sets the processor settings for the passed in virtual machine on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER vmId
    The Id of the requested virtual machine.

.PARAMETER count
    Specifies the number of virtual processors for the virtual machine.

.PARAMETER exposeVirtualizationExtensions
    Specifies whether the hypervisor should expose the presence of virtualization extensions to the virtual machine,
    which enables support for nested virtualization.

.PARAMETER smtEnabled
    Check for whether simultaneous multithreading is enabled

.PARAMETER compatibilityForMigrationEnabled
    Specifies whether the virtual processor's features are to be limited for compatibility when migrating the virtual
    machine to another host.

.PARAMETER compatibilityForMigrationMode
    Allow you to move a live VM or move a VM that is saved between nodes with different process capability sets.
    Available options are CommonClusterFeatureSet(or 1) and MinimumFeatureSet(or 0)

.PARAMETER hostMachineIsHciV2
    Check for whether the host machine is HCI version 2 i.e. 21H2
#>

param (
    [Parameter(Mandatory = $true)]
    [string]
    $vmId,
    [Parameter(Mandatory = $true)]
    [int]
    $count,
    [Parameter(Mandatory = $true)]
    [AllowNull()][System.Nullable[boolean]]
    $exposeVirtualizationExtensions,
    [Parameter(Mandatory = $true)]
    [boolean]
    $smtEnabled,
    [Parameter(Mandatory = $true)]
    [boolean]
    $compatibilityForMigrationEnabled,
    [Parameter(Mandatory = $true)]
    [int]
    $compatibilityForMigrationMode,
    [Parameter(Mandatory = $true)]
    [boolean]
    $hostMachineIsHciV2
)

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

<#

.SYNOPSIS
WindowsServerVersion

.DESCRIPTION
This enum is used for various Windows Server versions.

#>
enum WindowsServerVersion
{
    Unknown
    Server2008R2
    Server2012
    Server2012R2
    Server2016
    Server2019
}

<#

.SYNOPSIS
HypervisorSchedulerType

.DESCRIPTION
The Hypervisor scheduler type that is in effect on this host server.

#>

enum HypervisorSchedulerType {
    Unknown = 0
    ClassicSmtDisabled = 1
    Classic = 2
    Core = 3
    Root = 4
}

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.  Create read only (constant) variables
that add context to the said constants.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Set-VirtualMachineProcessorSettings.ps1" -Scope Script
    Set-Variable -Name MinimumVmVersionToInheritFromHost -Option ReadOnly -Value ([float]9.0) -Scope Script
    Set-Variable -Name ExposeVirtualizationExtensionsPropertyName -Option ReadOnly -Value "ExposeVirtualizationExtensions" -Scope Script
    Set-Variable -Name HwThreadCountPerCorePropertyName -Option ReadOnly -Value "HwThreadCountPerCore" -Scope Script
    Set-Variable -Name HypervisorEventChannelName -Option ReadOnly -Value "Microsoft-Windows-Hyper-V-Hypervisor" -Scope Script
    Set-Variable -Name Server2008R2BuildNumber -Option ReadOnly -Value 7600 -Scope Script
    Set-Variable -Name Server2012BuildNumber -Option ReadOnly -Value 9200 -Scope Script
    Set-Variable -Name Server2012R2BuildNumber -Option ReadOnly -Value 9600 -Scope Script
    Set-Variable -Name Server2016BuildNumber -Option ReadOnly -Value 14393 -Scope Script
    Set-Variable -Name Server2019BuildNumber -Option ReadOnly -Value 17763  -Scope Script
    Set-Variable -Name ClassicSmtDisabled -Option ReadOnly -Value "0x1" -Scope Script
    Set-Variable -Name Classic -Option ReadOnly -Value "0x2" -Scope Script
    Set-Variable -Name Core -Option ReadOnly -Value "0x3" -Scope Script
    Set-Variable -Name Root -Option ReadOnly -Value "0x4" -Scope Script
    Set-Variable -Name SmtEnabledPropertyName -Option ReadOnly -Value "smtEnabled" -Scope Script
    Set-Variable -Name MaxHThreadCountPerCoreForSmt -Option ReadOnly -Value 2 -Scope Script
    Set-Variable -Name DisableSmt -Option ReadOnly -Value 1 -Scope Script
    Set-Variable -Name EnableSmt -Option ReadOnly -Value 2 -Scope Script
    Set-Variable -Name InheritFromHost -Option ReadOnly -Value 0 -Scope Script
    Set-Variable -Name HyperVModuleName -Option ReadOnly -Value "Hyper-V" -Scope Script
    Set-Variable -Name 2K12MetaVersion -Option ReadOnly -Value 4.0 -Scope Script
}

<#

.SYNOPSIS
Cleanup the script environment.

.DESCRIPTION
Cleanup the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name MinimumVmVersionToInheritFromHost -Scope Script -Force
    Remove-Variable -Name ExposeVirtualizationExtensionsPropertyName -Scope Script -Force
    Remove-Variable -Name HwThreadCountPerCorePropertyName -Scope Script -Force
    Remove-Variable -Name HypervisorEventChannelName -Scope Script -Force
    Remove-Variable -Name Server2008R2BuildNumber -Scope Script -Force
    Remove-Variable -Name Server2012BuildNumber -Scope Script -Force
    Remove-Variable -Name Server2012R2BuildNumber -Scope Script -Force
    Remove-Variable -Name Server2016BuildNumber -Scope Script -Force
    Remove-Variable -Name Server2019BuildNumber -Scope Script -Force
    Remove-Variable -Name ClassicSmtDisabled -Scope Script -Force
    Remove-Variable -Name Classic -Scope Script -Force
    Remove-Variable -Name Core -Scope Script -Force
    Remove-Variable -Name Root -Scope Script -Force
    Remove-Variable -Name SmtEnabledPropertyName -Scope Script -Force
    Remove-Variable -Name MaxHThreadCountPerCoreForSmt -Scope Script -Force
    Remove-Variable -Name DisableSmt -Scope Script -Force
    Remove-Variable -Name EnableSmt -Scope Script -Force
    Remove-Variable -Name InheritFromHost -Scope Script -Force
    Remove-Variable -Name HyperVModuleName -Scope Script -Force
    Remove-Variable -Name 2K12MetaVersion -Scope Script -Force
}

<#

.SYNOPSIS
Get the Hypervisor scheduler type for this server.

.DESCRIPTION
Convert the event string value into an enum that is the current Hypervisor scheduler type.

The message looks like this:

 "Hypervisor scheduler type is 0x1."

 Since the hex value is all we care about this localized message should not be a problem...

#>

function getSchedulerType {
    $event = Get-WinEvent -FilterHashTable @{ProviderName = $HypervisorEventChannelName; ID = 2} -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object -First 1 Message

    # $event.message may not exist on downlevel servers
    if ($null -ne $event -AND $null -ne $event.message) {

        if ($event.message -match $ClassicSmtDisabled) {
            return [HypervisorSchedulerType]::ClassicSmtDisabled
        }

        if ($event.message -match $Classic) {
            return [HypervisorSchedulerType]::Classic
        }

        if ($event.message -match $Core) {
            return [HypervisorSchedulerType]::Core
        }

        if ($event.message -match $Root) {
            return [HypervisorSchedulerType]::Root
        }
    }

    return [HypervisorSchedulerType]::Unknown
}

<#

.SYNOPSIS
Get the the build number for the OS installed on this server.

.DESCRIPTION
Get the the build number for the OS installed on this server.

#>

function getBuildNumber {
    return [System.Environment]::OSVersion.Version.Build
}

<#

.SYNOPSIS
Get the Windows Server version for the OS installed on this server.

.DESCRIPTION
Get the Windows Server version for the OS installed on this server.

#>

function getServerVersion {
    $build = getBuildNumber

    if ($build -eq $Server2008R2BuildNumber) {
        return [WindowsServerVersion]::Server2008R2
    }

    if ($build -eq $Server2012BuildNumber) {
        return [WindowsServerVersion]::Server2012
    }

    if ($build -eq $Server2012R2BuildNumber) {
        return [WindowsServerVersion]::Server2012R2
    }

    if ($build -eq $Server2016BuildNumber) {
        return [WindowsServerVersion]::Server2016
    }

    #TODO: This isn't right.  Need to update with 2019 build number once known.
    if ($build -ge $Server2019BuildNumber) {
        return [WindowsServerVersion]::Server2019
    }

    return [WindowsServerVersion]::Unknown
}

<#

.SYNOPSIS
Determine if this Windows Server 2016 server has been patched.

.DESCRIPTION
Returns true if the patch for CVE-2018-3646 has been installed on this Windows 2016 server.

#>

function isServer2016Patched {
    $event = Get-WinEvent -FilterHashTable @{ProviderName = $HypervisorEventChannelName; ID = 156}  -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object -First 1

    return !!$event
}

<#

.SYNOPSIS
Compute the final value for hwThreadCountPerCore

.DESCRIPTION
Compute the value for hwThreadCountPerCore that should be persisted based upon the server version,
the current value of hwThreadCountPerCore, and if smtEnabled is true or not...

#>

function getHwThreadCountPerCore([string] $vmId, [boolean] $smtEnabled) {
    $err = $null

    $version = $2K12MetaVersion        # Server 2012 VM lack a version and 2012R2 starts at 5.

    $vm = Get-RBACVM -Id $vmId -ErrorAction SilentlyContinue -ErrorVariable +err

    if (!!$err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: There was an error getting the virtual machine with Id $vmId. Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return $null
    }

    $property = $vm | Get-VMProcessor -ErrorAction SilentlyContinue -ErrorVariable +err | Microsoft.PowerShell.Utility\Select-Object $HwThreadCountPerCorePropertyName

    if (!!$err) {
        $vmName = $vm.Name

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: There was an error getting the processor settings for virtual machine $vmName. Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return $null
    }

    $hwThreadCountPerCore = $property.$HwThreadCountPerCorePropertyName

    if ($vm.PSObject.Properties.Match('version').Count -gt 0) {
        $version = [float] $vm.version
    }

    # If the value of hwThreadCountPerCore is out of range then simply use it...
    if ($hwThreadCountPerCore -gt $MaxHThreadCountPerCoreForSmt) {
        return $hwThreadCountPerCore
    }

    $schedulerType = getSchedulerType

    # If we cannot get, or do not have, a scheduler type then return hwThreadCountPerCore
    if ($schedulerType -eq [HypervisorSchedulerType]::Unknown) {
        return $hwThreadCountPerCore
    }

    $serverVersion = getServerVersion

    if ($serverVersion -eq [WindowsServerVersion]::Server2016) {
        if (-not (isServer2016Patched)) {
            return $hwThreadCountPerCore
        }

        if ($smtEnabled) {
            return $EnableSmt
        } else {
            return $DisableSmt
        }
    }

    # Is the OS version greater then 2016?  Which really means 2019...
    if ($serverVersion -gt [WindowsServerVersion]::Server2016) {
        if ($smtEnabled) {

            if ($schedulerType -eq [HypervisorSchedulerType]::Core) {
                if ($version -ge $MinimumVmVersionToInheritFromHost) {
                    return $InheritFromHost
                } else {
                    return $EnableSmt
                }
            }

            if ($schedulerType -eq [HypervisorSchedulerType]::Classic) {
                return $EnableSmt
            }
        }

        return $DisableSmt
    }

    # Unknown, or unexpected, server version -- use the value provided
    return $hwThreadCountPerCore
}

<#

.SYNOPSIS
Get the current processor settings...

.DESCRIPTION
Get the current processor settings...  This must match the model in Get-VirtualMachineProcessorSettings.ps1

#>

function getSettings($vm, [boolean]$smtEnabled) {
    $err = $null

    $settings = $vm | Get-VMProcessor -ErrorAction SilentlyContinue -ErrorVariable +err | Microsoft.PowerShell.Utility\Select-Object `
        vmname, `
        vmid, `
        Count, `
        CompatibilityForMigrationEnabled, `
        CompatibilityForMigrationMode, `
        CompatibilityForOlderOperatingSystemsEnabled, `
        Reserve, `
        Maximum, `
        RelativeWeight, `
        $HwThreadCountPerCorePropertyName, `
        MaximumCountPerNumaNode, `
        MaximumCountPerNumaSocket, `
        IsDeleted, `
        @{ Name = $ExposeVirtualizationExtensionsPropertyName; Expression = { if ($_.PSObject.Properties.Match($ExposeVirtualizationExtensionsPropertyName).Count -gt 0) {$_.$ExposeVirtualizationExtensionsPropertyName} else {$null}} }, `
        @{ Name = $SmtEnabledPropertyName; Expression = { $smtEnabled } }

    if (!!$err) {
        $vmName = $vm.Name

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: There was an error getting the processor settings for virtual machine $vmName. Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return @{}
    }

    return $settings
}

<#

.SYNOPSIS
Main

.DESCRIPTION
An explicit main function to set the settings.

#>

function main(
  [string]$vmId,
  [int]$count,
  [AllowNull()][System.Nullable[boolean]] $exposeVirtualizationExtensions,
  [boolean] $smtEnabled,
  [boolean] $compatibilityForMigrationEnabled,
  [string] $compatibilityForMigrationMode,
  [boolean]
  $hostMachineIsHciV2) {
    $args = @{'Count'=$count}

    if ($smtEnabled) {
        $hwThreadCountPerCore = getHwThreadCountPerCore $vmId $smtEnabled

        # There was an error in getHwThreadCountPerCore -- return an empty object
        if (!!$hwThreadCountPerCore) {
            return @{}
        }

        $args += @{'HwThreadCountPerCore'=$hwThreadCountPerCore}
    }

    $err = $null

    if (!!$exposeVirtualizationExtensions) {
        $args += @{'ExposeVirtualizationExtensions' = $exposeVirtualizationExtensions}
    }

    if ($compatibilityForMigrationEnabled -and $hostMachineIsHciV2 -and $compatibilityForMigrationMode) {
      $args += @{'CompatibilityForMigrationEnabled' = $compatibilityForMigrationEnabled}
      $args += @{'CompatibilityForMigrationMode' = $compatibilityForMigrationMode}
    } else {
      $args += @{'CompatibilityForMigrationEnabled' = $compatibilityForMigrationEnabled}
    }

    $vm = Get-RBACVM -id $vmId -ErrorAction SilentlyContinue -ErrorVariable +err

    if (!!$err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: There was an error getting the virtual machine with Id $vmId. Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return @{}
    }

    $vm | Set-VMProcessor @args -ErrorAction SilentlyContinue -ErrorVariable +err

    if (!!$err) {
        $vmName = $vm.Name

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: There was an error saving the processor settings for virtual machine $vmName. Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return @{}
    }

    $settings = getSettings $vm $smtEnabled

    return $settings
}

###############################################################################
# Script execution starts here!
###############################################################################
if (-not ($env:pester)) {
    setupScriptEnv

    try {
        Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

        $hyperVModule = Get-Module -Name $HyperVModuleName -ErrorAction SilentlyContinue

        if (-not($hyperVModule)) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: The required PowerShell module (Hyper-V) was not found." -ErrorAction SilentlyContinue

            Write-Error $strings.HyperVModuleRequired

            return @{}
        }

        return main $vmId $count $exposeVirtualizationExtensions $smtEnabled $compatibilityForMigrationEnabled $compatibilityForMigrationMode $hostMachineIsHciV2
    } finally {
        cleanupScriptEnv
    }
}

}
## [END] Set-WACVMVirtualMachineProcessorSettings ##
function Set-WACVMVirtualMachineSecuritySettings {
<#

.SYNOPSIS
Sets the security settings for the passed in virtual machine.

.DESCRIPTION
Sets the security settings for the passed in virtual machine on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER vmId
The Id of the requested virtual machine.

.PARAMETER secureBoot
Specifies whether to enable secure boot. The acceptable values for this parameter are: true or false

.PARAMETER trustedPlatform
Enable/Disable TPM functionality on a virtual machine.

.PARAMETER encryptMigration
Indicates that this cmdlet enables encryption of virtual machine state and migration traffic. Boolean

.PARAMETER shielded
Configures the virtual machine as shielded. Boolean

.PARAMETER templateId
Specifies the ID of the secure boot template.

#>

param (
    [Parameter(Mandatory = $true)]
    [string]
    $vmId,
    [Parameter(Mandatory = $true)]
    [bool]
    $secureBoot,
    [Parameter(Mandatory = $true)]
    [bool]
    $trustedPlatform,
    [Parameter(Mandatory = $true)]
    [bool]
    $encryptMigration,
    [Parameter(Mandatory = $true)]
    [bool]
    $shielded,
    [Parameter(Mandatory = $false)]
    [string]
    $templateId
)

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

<#

.SYNOPSIS
A general enumeration for functions that switch on and off.

.DESCRIPTION
Maps to  Microsoft.HyperV.PowerShell.OnOffState

#>

enum OnOffState
{
    On
    Off
}

<#

.SYNOPSIS
Get the the build number for the OS installed on this server.

.DESCRIPTION
Get the the build number for the OS installed on this server.

#>

function getBuildNumber {
    return [System.Environment]::OSVersion.Version.Build
}

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.

#>

function setupScriptEnv() {
    Set-Variable -Name Server2008R2BuildNumber -Option ReadOnly -Value 7600 -Scope Script
    Set-Variable -Name Server2012BuildNumber -Option ReadOnly -Value 9200 -Scope Script
    Set-Variable -Name Server2012R2BuildNumber -Option ReadOnly -Value 9600 -Scope Script
    Set-Variable -Name Server2016BuildNumber -Option ReadOnly -Value 14393 -Scope Script
    Set-Variable -Name Server2019BuildNumber -Option ReadOnly -Value 17763  -Scope Script

    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-VirtualMachineSecuritySettings" -Scope Script
    Set-Variable -Name GenerationPropertyName -Option ReadOnly -Value "Generation" -Scope Script
    Set-Variable -Name Generation2 -Option ReadOnly -Value 2 -Scope Script
    Set-Variable -Name SecureBootPropertyName -Option ReadOnly -Value "SecureBoot" -Scope Script
    Set-Variable -Name TemplateIdPropertyName -Option ReadOnly -Value "TemplateId" -Scope Script
    Set-Variable -Name IdPropertyName -Option ReadOnly -Value "Id" -Scope Script
    Set-Variable -Name SecureBootTemplateIdPropertyName -Option ReadOnly -Value "SecureBootTemplateId" -Scope Script
    Set-Variable -Name TrustedPlatformPropertyName -Option ReadOnly -Value "TrustedPlatform" -Scope Script
    Set-Variable -Name EncryptMigrationPropertyName -Option ReadOnly -Value "EncryptMigration" -Scope Script
    Set-Variable -Name ShieldedPropertyName -Option ReadOnly -Value "Shielded" -Scope Script
    Set-Variable -Name GetVMSecurityCmdletName -Option ReadOnly -Value "Get-VMSecurity" -Scope Script
} 

<#

.SYNOPSIS
Clean up the script environment.

.DESCRIPTION
Clean up the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name Server2008R2BuildNumber -Scope Script -Force
    Remove-Variable -Name Server2012BuildNumber -Scope Script -Force
    Remove-Variable -Name Server2012R2BuildNumber -Scope Script -Force
    Remove-Variable -Name Server2016BuildNumber -Scope Script -Force
    Remove-Variable -Name Server2019BuildNumber -Scope Script -Force

    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name GenerationPropertyName -Scope Script -Force
    Remove-Variable -Name Generation2 -Scope Script -Force
    Remove-Variable -Name SecureBootPropertyName -Scope Script -Force
    Remove-Variable -Name TemplateIdPropertyName -Scope Script -Force
    Remove-Variable -Name IdPropertyName -Scope Script -Force
    Remove-Variable -Name SecureBootTemplateIdPropertyName -Scope Script -Force
    Remove-Variable -Name TrustedPlatformPropertyName -Scope Script -Force
    Remove-Variable -Name EncryptMigrationPropertyName -Scope Script -Force
    Remove-Variable -Name ShieldedPropertyName -Scope Script -Force
    Remove-Variable -Name GetVMSecurityCmdletName -Scope Script -Force
}

<#

.SYNOPSIS
Gets the firmware configuration of a virtual machine

.DESCRIPTION
Get values for:
- id (VMId)
- Secure boot status
- The ID of the secure boot template

#>
function getVMFirmware($vm) {
    $result = @{}
    $result.$IdPropertyName = $null
    $result.$SecureBootPropertyName = $null
    $result.$TemplateIdPropertyName = $null

    $fw = $vm | Get-VMFirmware -ErrorAction SilentlyContinue -ErrorVariable +err
    if ($fw) {
        $result.$IdPropertyName = $fw.VMId
        $result.$SecureBootPropertyName = $fw.$SecureBootPropertyName -eq [OnOffState]::On

        if (Get-Member -InputObject $fw -Name $SecureBootTemplateIdPropertyName -Membertype Properties) {
            $result.templateId = $fw.$SecureBootTemplateIdPropertyName
        } else {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
            -Message "[$ScriptName]: Virtual machine firmware settings for virtual machine $vm.Name did not contain $SecureBootTemplateIdPropertyName property." -ErrorAction SilentlyContinue
        }
    } else {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Could not get the virtual machine firmware settings for virtual machine $vm.Name. Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]
    }

    return $result
}

<#

.SYNOPSIS
Gets security information about a virtual machine.

.DESCRIPTION
Get status of:
- TPM (Trusted Platform Module)
- Encryption of virtual machine state and migration traffic
- Shield

#>
function getVMSecurity($vm) {
    $result = @{}

    $result.$TrustedPlatformPropertyName = $null
    $result.$EncryptMigrationPropertyName = $null
    $result.$ShieldedPropertyName = $null

    if (Get-Command $GetVMSecurityCmdletName -ErrorAction SilentlyContinue){
        $vms = $vm | Get-VMSecurity -ErrorAction SilentlyContinue -ErrorVariable +err

        if ($vms) {
            $result.$TrustedPlatformPropertyName = $vms.TpmEnabled
            $result.$EncryptMigrationPropertyName = $vms.EncryptStateAndVmMigrationTraffic
            $result.$ShieldedPropertyName = $vms.Shielded
        } else {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Could not get the virtual machine security settings for virtual machine $vm.Name. Error: $err" -ErrorAction SilentlyContinue

            Write-Error @($err)[0]
        }
    } else {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Required Hyper-V PowerShell cmdlet $GetVMSecurityCmdletName was not found." -ErrorAction SilentlyContinue
    }

    return $result
}

<#

.SYNOPSIS
Gets security settings of a virtual machine.

.DESCRIPTION
Gets security settings of a virtual machine.

#>

function getSecuritySettings($vm) {
    $result = New-Object PSObject

    if (Get-Member -InputObject $vm -Name $GenerationPropertyName -Membertype Properties) {
        if ($vm.Generation -ge $Generation2){
            $fw = getVMFirmware $vm
            $vms = getVMSecurity $vm

            $result | Add-Member -MemberType NoteProperty -Name $IdPropertyName -Value $fw.$IdPropertyName
            $result | Add-Member -MemberType NoteProperty -Name $SecureBootPropertyName -Value $fw.$SecureBootPropertyName
            $result | Add-Member -MemberType NoteProperty -Name $TemplateIdPropertyName -Value $fw.$TemplateIdPropertyName
            $result | Add-Member -MemberType NoteProperty -Name $TrustedPlatformPropertyName -Value $vms.$TrustedPlatformPropertyName
            $result | Add-Member -MemberType NoteProperty -Name $EncryptMigrationPropertyName -Value $vms.$EncryptMigrationPropertyName
            $result | Add-Member -MemberType NoteProperty -Name $ShieldedPropertyName -Value $vms.$ShieldedPropertyName
        }
    }

    return $result
}

<#

.SYNOPSIS
Convert a bool value to Microsoft.HyperV.PowerShell.OnOffState.

.DESCRIPTION
Since the Set-VMFirmware needs an On or an Off string value we must convert the model bool value...

#>

function convertToOnOffState([bool] $secureBoot) {
    if ($secureBoot) {
        return [OnOffState]::On
    }

    return [OnOffState]::Off
}

<#

.SYNOPSIS
Main function.

.DESCRIPTION
Main function.

#>

function main([string] $vmId, [bool] $secureBoot, [bool] $trustedPlatform, [bool] $encryptMigration, [bool] $shielded, [string] $templateId) {
    $err = $null

    $vm = Get-RBACVM -Id $vmId -ErrorAction SilentlyContinue -ErrorVariable +err
    if ($vm) {
        $buildNumber = getBuildNumber

        if ($buildNumber -lt $Server2012R2BuildNumber) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Virtual Machine security settings are not supported on Windows server versions prior to Windows Server 2012 R2." -ErrorAction SilentlyContinue

            Write-Error $strings.VirtualMachinesSecuritySettingsNotSupported
        }

        if ($buildNumber -eq $Server2012R2BuildNumber) {
            $onOffState = convertToOnOffState $secureBoot
            $vm | Set-VMFirmware -EnableSecureBoot $onOffState -ErrorAction SilentlyContinue -ErrorVariable +err

            if (-not ($err)) {
                return getSecuritySettings $vm
            }

            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Could not save the security settings for virtual machine $vm.Name. Error: $err" -ErrorAction SilentlyContinue

            Write-Error @($err)[0]
        }
        else {
            if ($buildNumber -ge $Server2016BuildNumber) {
                $onOffState = convertToOnOffState $secureBoot
                $vm | Set-VMFirmware -EnableSecureBoot $onOffState -SecureBootTemplateId $templateId -ErrorAction SilentlyContinue -ErrorVariable +err

                if ($trustedPlatform -Or $encryptMigration -Or $shielded) {
                    # Updating the virtual machine's key protector
                    $UntrustedGuardian = Get-HgsGuardian -Name UntrustedGuardian -ErrorAction SilentlyContinue -ErrorVariable +err
                    if (!$UntrustedGuardian){
                        # Creating new UntrustedGuardian since it did not exist
                        $UntrustedGuardian = New-HgsGuardian -Name UntrustedGuardian -GenerateCertificates -ErrorAction SilentlyContinue -ErrorVariable +err
                    }

                    $kp = New-HgsKeyProtector -Owner $UntrustedGuardian -AllowUntrustedRoot -ErrorAction SilentlyContinue -ErrorVariable +err
                    $vm | Set-VMKeyProtector -KeyProtector $kp.RawData -ErrorAction SilentlyContinue -ErrorVariable +err
                }

                if ($trustedPlatform) {
                    $vm | Enable-VMTPM -ErrorAction SilentlyContinue -ErrorVariable +err
                } else {
                    $vm | Disable-VMTPM -ErrorAction SilentlyContinue -ErrorVariable +err
                }

                $vm | Set-VMSecurityPolicy -Shielded $shielded -ErrorAction SilentlyContinue -ErrorVariable +err

                if (!$shielded) {
                    $vm | Set-VMSecurity -EncryptStateAndVmMigrationTraffic $encryptMigration -ErrorAction SilentlyContinue -ErrorVariable +err
                }

                if ($err -and $err.Length -gt 0) {
                    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                    -Message "[$ScriptName]: Could not save the security settings for virtual machine $vm.Name. Error: $err" -ErrorAction SilentlyContinue
        
                    Write-Error @($err)[0]
                }
            }
        }

        return getSecuritySettings $vm
    } else {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Could not find virutal machine with Id $vmId. Error: $err" -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return @{}
    }
}

###############################################################################
# Script execution starts here...
###############################################################################

$retValue = @{}

setupScriptEnv

try {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    $module = Get-Module -Name Hyper-V -ErrorAction SilentlyContinue -ErrorVariable +err
    if ($module) {
        $retValue = main $vmId $secureBoot  $trustedPlatform $encryptMigration $shielded $templateId
    } else {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Cannot continue because required Hyper-V PowerShell module was not found." -ErrorAction SilentlyContinue

        Write-Error @($err)[0]
    }
} finally {
    cleanupScriptEnv
}

return $retValue
}
## [END] Set-WACVMVirtualMachineSecuritySettings ##
function Set-WACVMVirtualMachineSettings {
<#

.SYNOPSIS
Sets the settings for the passed in virtual machine.

.DESCRIPTION
Sets the settings for the passed in virtual machine on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER vmId
    The Id of the requested virtual machine.

.PARAMETER newName

.PARAMETER notes

.PARAMETER automaticStartAction

.PARAMETER automaticStartDelay

.PARAMETER automaticCriticalErrorAction

.PARAMETER automaticCriticalErrorActionTimeout

.PARAMETER hwThreadCountPerCore

#>
param (
    [Parameter(Mandatory = $true)]
    [String]
    $vmId,
    [Parameter(Mandatory = $false)]
    [String]
    $newName,
    [Parameter(Mandatory = $false)]
    [String]
    $notes,
    [Parameter(Mandatory = $false)]
    [int]
    $automaticStartAction,
    [Parameter(Mandatory = $false)]
    [int]
    $automaticStartDelay,
    [Parameter(Mandatory = $false)]
    [int]
    $automaticStopAction,
    [Parameter(Mandatory = $false)]
    [AllowNull()][System.Nullable[int]]
    $automaticCriticalErrorAction,
    [Parameter(Mandatory = $false)]
    [AllowNull()][System.Nullable[int]]
    $automaticCriticalErrorActionTimeout
)

Set-StrictMode -Version 5.0

Import-Module Hyper-V

$vm = Get-RBACVM -id $vmId

$params = @{VM=$vm}

if ($newName) {
    $params += @{NewVMName=$newName;}
}

if ($notes -ne $null) {
    $params += @{Notes=$notes;}
}

if ($automaticStartAction -ne $null) {
    $params += @{AutomaticStartAction=$automaticStartAction;}
}

if ($automaticStartDelay -ne $null) {
    $params += @{AutomaticStartDelay=$automaticStartDelay;}
}

if ($automaticStopAction -ne $null) {
    $params += @{AutomaticStopAction=$automaticStopAction;}
}

if ($automaticCriticalErrorAction -ne $null) {
    $params += @{AutomaticCriticalErrorAction=$automaticCriticalErrorAction;}
}

if ($automaticCriticalErrorActionTimeout -ne $null) {
    $params += @{AutomaticCriticalErrorActionTimeout=$automaticCriticalErrorActionTimeout;}
}

Set-VM @params

# The property list here must be kept in sync with Get-VirtualMachineSettings.
Get-RBACVM -id $vmId | `
    Microsoft.PowerShell.Utility\Select-Object `
    name, `
    id, `
    SmartPagingFilePath, `
    SmartPagingFileInUse, `
    AutomaticStartAction, `
    AutomaticStartDelay, `
    AutomaticStopAction, `
    AutomaticCriticalErrorAction, `
    AutomaticCriticalErrorActionTimeout, `
    ConfigurationLocation, `
    IsDeleted, `
    Notes, `
    Generation, `
    State

}
## [END] Set-WACVMVirtualMachineSettings ##
function Set-WACVMVirtualSwitchGeneralSettings {
<#

.SYNOPSIS
Sets the general settings for the passed in virtual switch.

.DESCRIPTION
Sets the general settings for the passed in virtual switch on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER switchId
    The Id of the requested virtual switch.

.PARAMETER switchName
    The name of the virtual machine switch.  Can be a new name to which the switch should be renamed.

.PARAMETER switchType
    The switch type.  
        [Microsoft.HyperV.PowerShell.VMSwitchType]::Private (0)
        [Microsoft.HyperV.PowerShell.VMSwitchType]::Internal (1)
        [Microsoft.HyperV.PowerShell.VMSwitchType]::External (2)

.PARAMETER netAdapterName
    The optional name of network adapter to assign to this switch.

.PARAMETER allowManagementOs
    Optionally allow the host operationg system to use the virtual switch as a network adapter.

.PARAMETER notes
    Optional notes to apply to this virtual switch.

#>

param (
    [Parameter(Mandatory = $true)]
    [string]
    $switchId,
    [Parameter(Mandatory = $true)]
    [string]
    $switchName,
    [Parameter(Mandatory = $true)]
    [int]
    $switchType,
    [Parameter(Mandatory = $false)]
    [AllowNull()][string]
    $netAdapterName,
    [Parameter(Mandatory = $false)]
    [AllowNull()][System.Nullable[boolean]]
    $allowManagementOs,
    [Parameter(Mandatory = $false)]
    [AllowNull()][string]
    $notes
)

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

###############################################################################
# Constants
###############################################################################

Set-Variable -Name LogName -Option Constant -Value "Microsoft-ServerManagementExperience" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SMEScripts" -ErrorAction SilentlyContinue
Set-Variable -Name ScriptName -Option Constant -Value "Set-VirtualSwitchGeneralSettings.ps1" -ErrorAction SilentlyContinue

function main(
    [string]$switchId,
    [string]$switchName,
    [int]$switchType,
    [string]$netAdapterName,
    [System.Nullable[boolean]]$allowManagementOs,
    [string]$notes
) {
    $switch = Get-VMSwitch -Id $switchId

    $switch | Rename-VMSwitch -NewName $switchName

    $args = @{ 'Name' = $switchName; }

    if ($switchType -eq 0 -or $switchType -eq 1) {
        $args += @{ 'SwitchType' = $switchType; }
    }

    if ($switchType -eq 2) {
        if ($netAdapterName) {
            $args += @{ 'NetAdapterName' = $netAdapterName; }
        } else {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: A physical network adapter name must be supplied for an external virtual switch." -ErrorAction SilentlyContinue

            Write-Error $strings.PhysicalNetworkAdapterRequired
            
            return
        }

        if ($allowManagementOs) {
            $args += @{ 'AllowManagementOS' = $allowManagementOs; }
        } else {
            $args += @{ 'AllowManagementOS' = $false; }
        }
    }

    if ($notes) {
        $args += @{ 'Notes' = $notes; }
    }

    Set-VMSwitch @args
}

Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

$module = Get-Module -Name Hyper-V -ErrorAction SilentlyContinue
if ($module) {
    return main $switchId $switchName $switchType $netAdapterName $allowManagementOs $notes
}

return $null

}
## [END] Set-WACVMVirtualSwitchGeneralSettings ##
function Start-WACVMVirtualMachine {
<#

.SYNOPSIS
Starts the passed in virtual machines.

.DESCRIPTION
Starts the passed in list of virtual machines on this server
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER vmIds
    The ids of the requested virtual machine.

#>

param (
    [Parameter(Mandatory = $true)]
    [String[]]
    $vmIds
)

Set-StrictMode -Version 5.0
Import-Module -Name Hyper-V -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

Set-Variable -Name LogName -Option Constant -Value "Microsoft-ServerManagementExperience" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SMEScripts" -ErrorAction SilentlyContinue
Set-Variable -Name ScriptName -Option Constant -Value "Start-VirtualMachine.ps1" -ErrorAction SilentlyContinue
Set-Variable -Name VmRefreshValue -Option Constant -Value 0 -ErrorAction SilentlyContinue

# Script scope variable
$script:virtualMachineSuccesses = New-Object System.Collections.ArrayList
$script:virtualMachineFailures = ""

<#

.SYNOPSIS
The main function.

.DESCRIPTION
Start the virtual machines, and force refresh them if Briatannica feature enabled, at last handle the failure

.PARAMETER vmIds
The list of VM Ids.

#>
function main([string[]]$vmIds) {
    startVirtualMachine($vmIds)

    if (isBritannicaEnabled) {
        refreshVms
    }

    if ($script:virtualMachineFailures) {
        handleFailures
    }
}

<#

.SYNOPSIS
The start virtual machine function.

.DESCRIPTION
Start the virtual machines whose Ids are passed in and report the progress.

.PARAMETER vmIds
The list of VM Ids.

#>
function startVirtualMachine([string[]]$vmIds) {
    $virtualMachineCount = 0

    ForEach($vmId in $vmIds)
    {
        $percentComplete = $virtualMachineCount++/$vmIds.Count * 100

        $vm = Get-RBACVM -id $vmId -ErrorVariable getVmError -ErrorAction SilentlyContinue
        if ($getVmError) {
            $errorMessage = $getVmError[0].Exception.Message
            Write-Progress -PercentComplete $percentComplete -Activity ($errorMessage)
            $script:virtualMachineFailures += $errorMessage + " "
        } else {
            $vmName = $vm.Name

            Write-Progress -PercentComplete $percentComplete -Activity ($strings.StartVirtualMachineStartingMessage -f $vmName)

            Start-VM -VM $vm -ErrorVariable operationError -ErrorAction SilentlyContinue
            if ($operationError)
            {
                $errorMessage = $strings.StartVirtualMachineFailureMessage -f $vmName, $operationError[0].Exception.Message
                Write-Progress -PercentComplete $percentComplete -Activity ($errorMessage)
                $script:virtualMachineFailures += $errorMessage + " "
            } else {
                Write-Progress -PercentComplete $percentComplete -Activity ($strings.StartVirtualMachineSuccessMessage -f $vmName)

                $script:virtualMachineSuccesses.Add($vmName) > $null
            }
        }
    }
}

<#

.SYNOPSIS
Handle the failures.

.DESCRIPTION
Create error message combine both success and failure information and throw it.

#>
function handleFailures() {
    if ($script:virtualMachineSuccesses.Count -gt 0)
    {
        # Prepend success
        $script:virtualMachineFailures = $strings.StartVirtualMachineOperationMessage -f ($script:virtualMachineSuccesses -join ", "), $script:virtualMachineFailures
    }

    Write-Error $script:virtualMachineFailures
}
<#

.SYNOPSIS
Determines if Britannica (sddc management resources) are available on the cluster

.DESCRIPTION

Use the existance of the cim namespace root/sddc/Management and class name to determine if Britannica
is supported or not.

#>
function isBritannicaEnabled() {
    return !!(Get-CimInstance -Namespace "root\SDDC\Management" -ClassName SDDC_VirtualMachine -ErrorAction SilentlyContinue)
}

<#

.SYNOPSIS
Refresh virtual machines match given $vmIds

.DESCRIPTION
Find vm match given $vmIds from Britannica, then force refresh them

#>
function refreshVms() {
    $vms = Get-CimInstance -Namespace "root\SDDC\Management" -ClassName SDDC_VirtualMachine | `
    Microsoft.PowerShell.Core\Where-Object {$_.Id.ToLower() -in $vmIds.ToLower()} -ErrorAction SilentlyContinue

    foreach ($vm in $vms) {
       refreshVm $vm
    }
}

<#

.SYNOPSIS
Refresh given virtual machine

.DESCRIPTION
Force refresh given virtual machine from Britannica

.Parameter vm
    The vm object to refresh
#>
function refreshVm($vm) {
    if ($vm) {
        Invoke-CimMethod -CimInstance $vm -MethodName "Refresh" -Arguments @{RefreshType=$VmRefreshValue} -ErrorVariable +err
    }
}

###############################################################################
# Script execution starts here
###############################################################################

if (-not($env:pester)) {
    $module = Get-Module -Name Hyper-V -ErrorAction SilentlyContinue

    if ($module) {
        main $vmIds
    }

    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Warning `
        -Message "[$ScriptName]: The required PowerShell module (Hyper-V) was not found."  -ErrorAction SilentlyContinue

    return @()
}

}
## [END] Start-WACVMVirtualMachine ##
function Stop-WACVMVirtualMachineShutdown {
<#

.SYNOPSIS
Stops the passed in virtual machines.

.DESCRIPTION
Stops the passed in virtual machines on this server by shutting them down.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER vmIds
    The ids of the requested virtual machines.

#>

param (
    [Parameter(Mandatory = $true)]
    [String[]]
    $vmIds
)

Set-StrictMode -Version 5.0
Import-Module -Name Hyper-V -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue
Set-Variable -Name VmRefreshValue -Option Constant -Value 0 -ErrorAction SilentlyContinue

<#

.SYNOPSIS
The main function.

.DESCRIPTION
Shutdown the virtual machines whose Ids are passed in and report the progress.

.PARAMETER vmIds
The list of VM Ids.

#>

function main([string[]]$vmIds) {
    $virtualMachineCount = 0
    $virtualMachineSuccesses = New-Object System.Collections.ArrayList
    $virtualMachineFailures = ""

    ForEach($vmId in $vmIds)
    {
        $percentComplete = $virtualMachineCount++/$vmIds.Count * 100

        $vm = Get-RBACVM -id $vmId -ErrorVariable getVmError -ErrorAction SilentlyContinue
        if ($getVmError)
        {
            $errorMessage = $getVmError[0].Exception.Message
            Write-Progress -PercentComplete $percentComplete -Activity ($errorMessage)
            $virtualMachineFailures += $errorMessage + " "
        }
        else
        {
            $vmName = $vm.Name

            Write-Progress -PercentComplete $percentComplete -Activity ($strings.ShutdownVirtualMachineStartingMessage -f $vmName)

            Stop-VM -VM $vm -Force -ErrorVariable operationError -ErrorAction SilentlyContinue
            if ($operationError)
            {
                $errorMessage = $strings.ShutdownVirtualMachineFailureMessage -f $vmName, $operationError[0].Exception.Message
                Write-Progress -PercentComplete $percentComplete -Activity ($errorMessage)
                $virtualMachineFailures += $errorMessage + " "
            } else 
            {
                Write-Progress -PercentComplete $percentComplete -Activity ($strings.ShutdownVirtualMachineSuccessMessage -f $vmName)

                $virtualMachineSuccesses.Add($vmName) > $null
            }
        }
    }

    if (isBritannicaEnabled) {
        refreshVms
    }

    if ($virtualMachineFailures)
    {
        if ($virtualMachineSuccesses.Count -gt 0)
        {
            # Prepend success 
            $virtualMachineFailures = $strings.ShutdownVirtualMachineOperationMessage -f ($virtualMachineSuccesses -join ", "), $virtualMachineFailures
        }

        throw $virtualMachineFailures
    }
}

<#

.SYNOPSIS
Determines if Britannica (sddc management resources) are available on the cluster

.DESCRIPTION

Use the existance of the cim namespace root/sddc/Management and class name to determine if Britannica
is supported or not.

#>
function isBritannicaEnabled() {
    return !!(Get-CimInstance -Namespace "root\SDDC\Management" -ClassName SDDC_VirtualMachine -ErrorAction SilentlyContinue)
}

<#

.SYNOPSIS
Refresh virtual machines match given $vmIds

.DESCRIPTION
Find vm match given $vmIds from Britannica, then force refresh them

#>
function refreshVms() {
    $vms = Get-CimInstance -Namespace "root\SDDC\Management" -ClassName SDDC_VirtualMachine | `
    Microsoft.PowerShell.Core\Where-Object {$_.Id.ToLower() -in $vmIds.ToLower()} -ErrorAction SilentlyContinue

    foreach ($vm in $vms) {
      refreshVm $vm
    }
}

<#

.SYNOPSIS
Refresh given virtual machine

.DESCRIPTION
Force refresh given virtual machine from Britannica

.Parameter vm
    The vm object to refresh
#>
function refreshVm($vm) {
    if ($vm) {
      Invoke-CimMethod -CimInstance $vm -MethodName "Refresh" -Arguments @{RefreshType=$VmRefreshValue} -ErrorVariable +err
    }
}

###############################################################################
# Script execution starts here
###############################################################################

main $vmIds

}
## [END] Stop-WACVMVirtualMachineShutdown ##
function Stop-WACVMVirtualMachineTurnoff {
<#

.SYNOPSIS
Stops the passed in virtual machines.

.DESCRIPTION
Stops the passed in virtual machines on this server, by turning it off.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER vmIds
    The ids of the requested virtual machines.

#>

param (
    [Parameter(Mandatory = $true)]
    [String[]]
    $vmIds
)

Set-StrictMode -Version 5.0
Import-Module -Name Hyper-V -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue
Set-Variable -Name VmRefreshValue -Option Constant -Value 0 -ErrorAction SilentlyContinue

<#

.SYNOPSIS
The main function.

.DESCRIPTION
Turnoff the virtual machines whose Ids are passed in and report the progress.

.PARAMETER vmIds
The list of VM Ids.

#>

function main([string[]]$vmIds) {
    $virtualMachineCount = 0
    $virtualMachineSuccesses = New-Object System.Collections.ArrayList
    $virtualMachineFailures = ""

    ForEach($vmId in $vmIds)
    {
        $percentComplete = $virtualMachineCount++/$vmIds.Count * 100

        $vm = Get-RBACVM -id $vmId -ErrorVariable getVmError -ErrorAction SilentlyContinue
        if ($getVmError)
        {
            $errorMessage = $getVmError[0].Exception.Message
            Write-Progress -PercentComplete $percentComplete -Activity ($errorMessage)
            $virtualMachineFailures += $errorMessage + " "
        }
        else
        {
            $vmName = $vm.Name

            Write-Progress -PercentComplete $percentComplete -Activity ($strings.TurnoffVirtualMachineStartingMessage -f $vmName)

            Stop-VM -VM $vm -Turnoff -Force -ErrorVariable operationError -ErrorAction SilentlyContinue
            if ($operationError)
            {
                $errorMessage = $strings.TurnoffVirtualMachineFailureMessage -f $vmName, $operationError[0].Exception.Message
                Write-Progress -PercentComplete $percentComplete -Activity ($errorMessage)
                $virtualMachineFailures += $errorMessage + " "
            } else 
            {
                Write-Progress -PercentComplete $percentComplete -Activity ($strings.TurnoffVirtualMachineSuccessMessage -f $vmName)

                $virtualMachineSuccesses.Add($vmName) > $null
            }
        }
    }

    if (isBritannicaEnabled) {
        refreshVms
    }

    if ($virtualMachineFailures)
    {
        if ($virtualMachineSuccesses.Count -gt 0)
        {
            # Prepend success 
            $virtualMachineFailures = $strings.TurnoffVirtualMachineOperationMessage -f ($virtualMachineSuccesses -join ", "), $virtualMachineFailures
        }

        throw $virtualMachineFailures
    }
}

<#

.SYNOPSIS
Determines if Britannica (sddc management resources) are available on the cluster

.DESCRIPTION

Use the existance of the cim namespace root/sddc/Management and class name to determine if Britannica
is supported or not.

#>
function isBritannicaEnabled() {
    return !!(Get-CimInstance -Namespace "root\SDDC\Management" -ClassName SDDC_VirtualMachine -ErrorAction SilentlyContinue)
}

<#

.SYNOPSIS
Refresh virtual machines match given $vmIds

.DESCRIPTION
Find vm match given $vmIds from Britannica, then force refresh them

#>
function refreshVms() {
    $vms = Get-CimInstance -Namespace "root\SDDC\Management" -ClassName SDDC_VirtualMachine | `
    Microsoft.PowerShell.Core\Where-Object {$_.Id.ToLower() -in $vmIds.ToLower()} -ErrorAction SilentlyContinue

    foreach ($vm in $vms) {
      refreshVm $vm
    }
}

<#

.SYNOPSIS
Refresh given virtual machine

.DESCRIPTION
Force refresh given virtual machine from Britannica

.Parameter vm
    The vm object to refresh
#>
function refreshVm($vm) {
    if ($vm) {
      Invoke-CimMethod -CimInstance $vm -MethodName "Refresh" -Arguments @{RefreshType=$VmRefreshValue} -ErrorVariable +err
    }
}

###############################################################################
# Script execution starts here
###############################################################################

main $vmIds

}
## [END] Stop-WACVMVirtualMachineTurnoff ##
function Suspend-WACVMVirtualMachine {
<#

.SYNOPSIS
Pauses (suspends) the passed in virtual machines.

.DESCRIPTION
Pauses (suspends) the passed in virtual machines on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER vmIds
    The ids of the requested virtual machines.

#>

param (
    [Parameter(Mandatory = $true)]
    [String[]]
    $vmIds
)

Set-StrictMode -Version 5.0
Import-Module -Name Hyper-V -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue
Set-Variable -Name VmRefreshValue -Option Constant -Value 0 -ErrorAction SilentlyContinue

<#

.SYNOPSIS
The main function.

.DESCRIPTION
Suspend the virtual machines whose Ids are passed in and report the progress.

.PARAMETER vmIds
The list of VM Ids.

#>

function main([string[]]$vmIds) {
    $virtualMachineCount = 0
    $virtualMachineSuccesses = New-Object System.Collections.ArrayList
    $virtualMachineFailures = ""

    ForEach($vmId in $vmIds)
    {
        $percentComplete = $virtualMachineCount++/$vmIds.Count * 100

        $vm = Get-RBACVM -id $vmId -ErrorVariable getVmError -ErrorAction SilentlyContinue
        if ($getVmError)
        {
            $errorMessage = $getVmError[0].Exception.Message
            Write-Progress -PercentComplete $percentComplete -Activity ($errorMessage)
            $virtualMachineFailures += $errorMessage + " "
        }
        else
        {
            $vmName = $vm.Name

            Write-Progress -PercentComplete $percentComplete -Activity ($strings.SuspendVirtualMachineStartingMessage -f $vmName)

            suspend-vm $vm -ErrorVariable operationError -ErrorAction SilentlyContinue
            if ($operationError)
            {
                $errorMessage = $strings.SuspendVirtualMachineFailureMessage -f $vmName, $operationError[0].Exception.Message
                Write-Progress -PercentComplete $percentComplete -Activity ($errorMessage)
                $virtualMachineFailures += $errorMessage + " "
            } else 
            {
                Write-Progress -PercentComplete $percentComplete -Activity ($strings.SuspendVirtualMachineSuccessMessage -f $vmName)

                $virtualMachineSuccesses.Add($vmName) > $null
            }
        }
    }

    if (isBritannicaEnabled) {
        refreshVms
    }

    if ($virtualMachineFailures)
    {
        if ($virtualMachineSuccesses.Count -gt 0)
        {
            # Prepend success 
            $virtualMachineFailures = $strings.SuspendVirtualMachineOperationMessage -f ($virtualMachineSuccesses -join ", "), $virtualMachineFailures
        }

        throw $virtualMachineFailures
    }
}

<#

.SYNOPSIS
Determines if Britannica (sddc management resources) are available on the cluster

.DESCRIPTION

Use the existance of the cim namespace root/sddc/Management and class name to determine if Britannica
is supported or not.

#>
function isBritannicaEnabled() {
    return !!(Get-CimInstance -Namespace "root\SDDC\Management" -ClassName SDDC_VirtualMachine -ErrorAction SilentlyContinue)
}

<#

.SYNOPSIS
Refresh virtual machines match given $vmIds

.DESCRIPTION
Find vm match given $vmIds from Britannica, then force refresh them

#>
function refreshVms() {
    $vms = Get-CimInstance -Namespace "root\SDDC\Management" -ClassName SDDC_VirtualMachine | `
    Microsoft.PowerShell.Core\Where-Object {$_.Id.ToLower() -in $vmIds.ToLower()} -ErrorAction SilentlyContinue

    foreach ($vm in $vms) {
      refreshVm $vm
    }
}

<#

.SYNOPSIS
Refresh given virtual machine

.DESCRIPTION
Force refresh given virtual machine from Britannica

.Parameter vm
    The vm object to refresh
#>
function refreshVm($vm) {
    if ($vm) {
      Invoke-CimMethod -CimInstance $vm -MethodName "Refresh" -Arguments @{RefreshType=$VmRefreshValue} -ErrorVariable +err
    }
}

###############################################################################
# Script execution starts here
###############################################################################

main $vmIds

}
## [END] Suspend-WACVMVirtualMachine ##
function Update-WACVMVirtualMachineConfiguration {
<#

.SYNOPSIS
Upgrade the configuration versions for the passed in virtual machine(s)

.DESCRIPTION
Upgrade the configuration versions for the passed in virtual machine(s)
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Hyper-V-Administrators

.PARAMETER vmIds
    The list of requested virtual machine Ids.
#>

param (
    [Parameter(Mandatory = $true)]
    [String []]
    $vmIds
)

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue
Import-Module FailoverClusters -ErrorAction SilentlyContinue
Import-Module NetworkController -ErrorAction SilentlyContinue

###############################################################################
# Constants
###############################################################################

Set-Variable -Name LogName -Option Constant -Value "Microsoft-ServerManagementExperience" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SMEScripts" -ErrorAction SilentlyContinue
Set-Variable -Name ScriptName -Option Constant -Value "Update-VirtualMachineConfiguration.ps1" -ErrorAction SilentlyContinue

<#

.SYNOPSIS
    The scripts main function

.DESCRIPTION
    Upgrade the virtual machine configurations for the passed in VMs

.PARAMETER vmIds
    The list of requested virtual machine Ids.

.Outputs
    The results of the operation.
#>

function main([string []] $vmIds) {
    $err = @()

    foreach ($vmId in $vmIds) {
        $err += updateVirtualMachineConfiguration $vmId $err
    }
}


<#

.SYNOPSIS
    Update a virtual machine configuration version.

.DESCRIPTION
    Update a virtual machine configuration version.

.Parameter vmId
    The Id of the VM whose version to update.

.Parameter err
    The errors accumulated in.

.Outputs
    All of the accumulated errors.

#>

function updateVirtualMachineConfiguration(
    [string] $vmId,
    [string []] $err) {

    # The VM may have moved to another node of the cluster so some extra checking is needed.
    $vm = Get-RBACVM -Id $vmId -ErrorVariable +err -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object Name, Id, IsClustered
    if(-not $vm) {
        return $err
    }

    $removeErrors = @()

    Update-VMVersion -Name $vm.Name -Force -ErrorAction SilentlyContinue -ErrorVariable +removeErrors
    $err += $removeErrors

    return $err
}

main $vmIds

}
## [END] Update-WACVMVirtualMachineConfiguration ##
function Update-WACVMVirtualMachineFromBritannicaCache {
<#
.SYNOPSIS
Force refresh the Britannica cache for VM(s)

.DESCRIPTION
Force refresh the Britannica cache for VM(s)
Due to the automatically refresh for Britannica can be up to 5mins and this will cause the torn state between rendering state and the actual state.

.ROLE
Hyper-V-Administrators

.PARAMETER vmIds
The array of the Id(s) for the requested virtual machine(s).
#>

param (
    [Parameter(Mandatory = $true)]
    [Object[]]
    $vmIds,
    [Parameter(Mandatory = $true)]
    [bool]
    $forceUpdate
)


Set-StrictMode -Version 5.0;
Import-Module CimCmdlets -ErrorAction SilentlyContinue

<#
.SYNOPSIS
Get the VM using the Britannica cache.

.DESCRIPTION
Use the Britannica virtual machine interface to get the VM info.  This is preferred
since no double hop is needed.
#>

function getVmFromBritannica([string]$vmId) {
    $vm = Get-CimInstance -Namespace "root\SDDC\Management" -ClassName SDDC_VirtualMachine | Where-Object { $_.Id -ieq $vmId }

    if (-not ($vm)) {
        return @()
    }

    return $vm
}

<#
.SYNOPSIS
Force upate the britannica cache for VM(s)

.DESCRIPTION
Update the actual status for the VM to the Britannica cache manually
#>
function forceUpdateVmFromBritannica([Object[]]$vmIds) {
    $updated = Invoke-CimMethod -InputObject $vm -MethodName Refresh -Arguments @{ RefreshType = [UInt16]0 } -ErrorAction SilentlyContinue

    if (-not ($updated)) {
        return @()
    }

    return $updated
}

$result = New-Object System.Collections.Generic.List[System.Object]

foreach ($vmId in $vmIds) {
    if ($forceUpdate) {
        $vm = getVmFromBritannica $vmId.vmId -ErrorAction SilentlyContinue
        forceUpdateVmFromBritannica $vm

        $vm_after = getVmFromBritannica $vmId.vmId

        $result.Add($vm_after)
    } else {
        $vm = getVmFromBritannica $vmId.vmId -ErrorAction SilentlyContinue
        $result.Add($vm)
    }
}

return $result

}
## [END] Update-WACVMVirtualMachineFromBritannicaCache ##
function Add-WACVMAdministrators {
<#

.SYNOPSIS
Adds administrators

.DESCRIPTION
Adds administrators

.ROLE
Administrators

#>

Param (
    [Parameter(Mandatory=$true)]
    [String] $usersListString
)


$usersToAdd = ConvertFrom-Json $usersListString
$adminGroup = Get-LocalGroup | Where-Object SID -eq 'S-1-5-32-544'

Add-LocalGroupMember -Group $adminGroup -Member $usersToAdd

Register-DnsClient -Confirm:$false

}
## [END] Add-WACVMAdministrators ##
function Add-WACVMFolderShare {
<#

.SYNOPSIS
Gets a new share name for the folder.

.DESCRIPTION
Gets a new share name for the folder. It starts with the folder name. Then it keeps appending "2" to the name
until the name is free. Finally return the name.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER Path
    String -- The path to the folder to be shared.

.PARAMETER Name
    String -- The suggested name to be shared (the folder name).

.PARAMETER Force
    boolean -- override any confirmations

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path,    

    [Parameter(Mandatory = $true)]
    [String]
    $Name
)

Set-StrictMode -Version 5.0

while([bool](Get-SMBShare -Name $Name -ea 0)){
    $Name = $Name + '2';
}

New-SmbShare -Name "$Name" -Path "$Path"
@{ shareName = $Name }

}
## [END] Add-WACVMFolderShare ##
function Add-WACVMFolderShareNameUser {
<#

.SYNOPSIS
Adds a user to the folder share.

.DESCRIPTION
Adds a user to the folder share.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER Name
    String -- Name of the share.

.PARAMETER AccountName
    String -- The user identification (AD / Local user).

.PARAMETER AccessRight
    String -- Access rights of the user.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Name,

    [Parameter(Mandatory = $true)]
    [String]
    $AccountName,

    [Parameter(Mandatory = $true)]
    [String]
    $AccessRight
)

Set-StrictMode -Version 5.0

Grant-SmbShareAccess -Name "$Name" -AccountName "$AccountName" -AccessRight "$AccessRight" -Force


}
## [END] Add-WACVMFolderShareNameUser ##
function Add-WACVMFolderShareUser {
<#

.SYNOPSIS
Adds a user access to the folder.

.DESCRIPTION
Adds a user access to the folder.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER Path
    String -- The path to the folder.

.PARAMETER Identity
    String -- The user identification (AD / Local user).

.PARAMETER FileSystemRights
    String -- File system rights of the user.

.PARAMETER AccessControlType
    String -- Access control type of the user.    

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path,

    [Parameter(Mandatory = $true)]
    [String]
    $Identity,

    [Parameter(Mandatory = $true)]
    [String]
    $FileSystemRights,

    [ValidateSet('Deny','Allow')]
    [Parameter(Mandatory = $true)]
    [String]
    $AccessControlType
)

Set-StrictMode -Version 5.0

function Remove-UserPermission
{
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path,
    
        [Parameter(Mandatory = $true)]
        [String]
        $Identity,
        
        [ValidateSet('Deny','Allow')]
        [Parameter(Mandatory = $true)]
        [String]
        $ACT
    )

    $Acl = Get-Acl $Path
    $AccessRule = New-Object system.security.accesscontrol.filesystemaccessrule($Identity, 'ReadAndExecute','ContainerInherit, ObjectInherit', 'None', $ACT)
    $Acl.RemoveAccessRuleAll($AccessRule)
    Set-Acl $Path $Acl
}

If ($AccessControlType -eq 'Deny') {
    $FileSystemRights = 'FullControl'
    Remove-UserPermission $Path $Identity 'Allow'
} else {
    Remove-UserPermission $Path $Identity 'Deny'
}

$Acl = Get-Acl $Path
$AccessRule = New-Object system.security.accesscontrol.filesystemaccessrule($Identity, $FileSystemRights,'ContainerInherit, ObjectInherit', 'None', $AccessControlType)
$Acl.AddAccessRule($AccessRule)
Set-Acl $Path $Acl

}
## [END] Add-WACVMFolderShareUser ##
function Clear-WACVMEventLogChannel {
<#

.SYNOPSIS
Clear the event log channel specified.

.DESCRIPTION
Clear the event log channel specified.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

#>
 
Param(
    [string]$channel
)

[System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog("$channel") 
}
## [END] Clear-WACVMEventLogChannel ##
function Clear-WACVMEventLogChannelAfterExport {
<#

.SYNOPSIS
Clear the event log channel after export the event log channel file (.evtx).

.DESCRIPTION
Clear the event log channel after export the event log channel file (.evtx).
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

#>

Param(
    [string]$channel
)

$segments = $channel.Split("-")
$name = $segments[-1]

$randomString = [GUID]::NewGuid().ToString()
$ResultFile = $env:temp + "\" + $name + "_" + $randomString + ".evtx"
$ResultFile = $ResultFile -replace "/", "-"

wevtutil epl "$channel" "$ResultFile" /ow:true

[System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog("$channel") 

return $ResultFile

}
## [END] Clear-WACVMEventLogChannelAfterExport ##
function Compress-WACVMArchiveFileSystemEntity {
<#

.SYNOPSIS
Compresses the specified file system entity (files, folders) of the system.

.DESCRIPTION
Compresses the specified file system entity (files, folders) of the system on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER pathSource
    String -- The path to compress.

.PARAMETER PathDestination
    String -- The destination path to compress into.

.PARAMETER Force
    boolean -- override any confirmations

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $PathSource,    

    [Parameter(Mandatory = $true)]
    [String]
    $PathDestination,

    [Parameter(Mandatory = $false)]
    [boolean]
    $Force
)

Set-StrictMode -Version 5.0

if ($Force) {
    Compress-Archive -Path $PathSource -Force -DestinationPath $PathDestination
} else {
    Compress-Archive -Path $PathSource -DestinationPath $PathDestination
}
if ($error) {
    $code = $error[0].Exception.HResult
    @{ status = "error"; code = $code; message = $error }
} else {
    @{ status = "ok"; }
}

}
## [END] Compress-WACVMArchiveFileSystemEntity ##
function Disable-WACVMKdcProxy {
<#
.SYNOPSIS
Disables kdc proxy on the server

.DESCRIPTION
Disables kdc proxy on the server

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [string]
    $KdcPort
)

$urlLeft = "https://+:"
$urlRight = "/KdcProxy/"
$url = $urlLeft + $KdcPort + $urlRight
$deleteOutput = netsh http delete urlacl url=$url
if ($LASTEXITCODE -ne 0) {
    throw $deleteOutput
}
Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" -Name "HttpsClientAuth"
Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" -Name "DisallowUnprotectedPasswordAuth"
Stop-Service -Name kpssvc
Set-Service -Name kpssvc -StartupType Disabled
$firewallString = "KDC Proxy Server service (KPS) for SMB over QUIC"
Remove-NetFirewallRule -DisplayName $firewallString -ErrorAction SilentlyContinue
}
## [END] Disable-WACVMKdcProxy ##
function Disable-WACVMSmbOverQuic {
<#

.SYNOPSIS
Disables smb over QUIC on the server.

.DESCRIPTION
Disables smb over QUIC on the server.

.ROLE
Administrators

#>

Set-SmbServerConfiguration -EnableSMBQUIC $false -Force
}
## [END] Disable-WACVMSmbOverQuic ##
function Disconnect-WACVMAzureHybridManagement {
<#

.SYNOPSIS
Disconnects a machine from azure hybrid agent.

.DESCRIPTION
Disconnects a machine from azure hybrid agent and uninstall the hybrid instance service.
The supported Operating Systems are Windows Server 2012 R2 and above.

.ROLE
Administrators

.PARAMETER tenantId
    The GUID that identifies a tenant in AAD

.PARAMETER authToken
    The authentication token for connection

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $tenantId,
    [Parameter(Mandatory = $true)]
    [String]
    $authToken
)

Set-StrictMode -Version 5.0

<#

.SYNOPSIS
Setup script runtime environment.

.DESCRIPTION
Setup script runtime environment.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScript" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Disconnect-HybridManagement.ps1" -Scope Script
    Set-Variable -Name HybridAgentExecutable -Option ReadOnly -Value "$env:ProgramFiles\AzureConnectedMachineAgent\azcmagent.exe" -Scope Script
    Set-Variable -Name HybridAgentPackage -Option ReadOnly -Value "Azure Connected Machine Agent" -Scope Script
}

<#

.SYNOPSIS
Cleanup script runtime environment.

.DESCRIPTION
Cleanup script runtime environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name HybridAgentExecutable -Scope Script -Force
    Remove-Variable -Name HybridAgentPackage -Scope Script -Force
}

<#

.SYNOPSIS
The main function.

.DESCRIPTION
Disconnects a machine from azure hybrid agent.

#>

function main(
    [string]$tenantId,
    [string]$authToken
) {
    $err = $null
    $args = @{}

   # Disconnect Azure hybrid agent
   & $HybridAgentExecutable disconnect --access-token $authToken

   # Uninstall Azure hybrid instance metadata service
   Uninstall-Package -Name $HybridAgentPackage -ErrorAction SilentlyContinue -ErrorVariable +err

   if ($err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]:Could not uninstall the package. Error: $err"  -ErrorAction SilentlyContinue

        Write-Error @($err)[0]
        throw $err
   }

}


###############################################################################
# Script execution starts here
###############################################################################
setupScriptEnv

try {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    return main $tenantId $authToken

    return @()
} finally {
    cleanupScriptEnv
}

}
## [END] Disconnect-WACVMAzureHybridManagement ##
function Edit-WACVMFolderShareInheritanceFlag {
<#

.SYNOPSIS
Modifies all users' IsInherited flag to false

.DESCRIPTION
Modifies all users' IsInherited flag to false
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER Path
    String -- The path to the folder.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path
)

Set-StrictMode -Version 5.0

$Acl = Get-Acl $Path
$Acl.SetAccessRuleProtection($True, $True)
Set-Acl -Path $Path -AclObject $Acl

}
## [END] Edit-WACVMFolderShareInheritanceFlag ##
function Edit-WACVMFolderShareUser {
<#

.SYNOPSIS
Edits a user access to the folder.

.DESCRIPTION
Edits a user access to the folder.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER Path
    String -- The path to the folder.

.PARAMETER Identity
    String -- The user identification (AD / Local user).

.PARAMETER FileSystemRights
    String -- File system rights of the user.

.PARAMETER AccessControlType
    String -- Access control type of the user.    

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path,

    [Parameter(Mandatory = $true)]
    [String]
    $Identity,

    [Parameter(Mandatory = $true)]
    [String]
    $FileSystemRights,

    [ValidateSet('Deny','Allow')]
    [Parameter(Mandatory = $true)]
    [String]
    $AccessControlType
)

Set-StrictMode -Version 5.0

function Remove-UserPermission
{
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path,
    
        [Parameter(Mandatory = $true)]
        [String]
        $Identity,
        
        [ValidateSet('Deny','Allow')]
        [Parameter(Mandatory = $true)]
        [String]
        $ACT
    )

    $Acl = Get-Acl $Path
    $AccessRule = New-Object system.security.accesscontrol.filesystemaccessrule($Identity, 'ReadAndExecute','ContainerInherit, ObjectInherit', 'None', $ACT)
    $Acl.RemoveAccessRuleAll($AccessRule)
    Set-Acl $Path $Acl
}

If ($AccessControlType -eq 'Deny') {
    $FileSystemRights = 'FullControl'
    Remove-UserPermission $Path $Identity 'Allow'
} else {
    Remove-UserPermission $Path $Identity 'Deny'
}

$Acl = Get-Acl $Path
$AccessRule = New-Object system.security.accesscontrol.filesystemaccessrule($Identity, $FileSystemRights,'ContainerInherit, ObjectInherit', 'None', $AccessControlType)
$Acl.SetAccessRule($AccessRule)
Set-Acl $Path $Acl




}
## [END] Edit-WACVMFolderShareUser ##
function Edit-WACVMSmbFileShare {
<#

.SYNOPSIS
Edits the smb file share details on the server.

.DESCRIPTION
Edits the smb file share details on the server.

.ROLE
Administrators

#>
param (
    [Parameter(Mandatory = $true)]
    [String]
    $name,

    [Parameter(Mandatory = $false)]
    [String[]]
    $noAccess,

    [Parameter(Mandatory = $false)]
    [String[]]
    $fullAccess,

    [Parameter(Mandatory = $false)]
    [String[]]
    $changeAccess,

    [Parameter(Mandatory = $false)]
    [String[]]
    $readAccess,
    
    [Parameter(Mandatory = $false)]
    [String[]]
    $unblockAccess,

    [Parameter(Mandatory = $false)]
    [Int]
    $cachingMode,

    [Parameter(Mandatory = $false)]
    [boolean]
    $encryptData,

    # TODO: 
    # [Parameter(Mandatory = $false)]
    # [Int]
    # $folderEnumerationMode

    [Parameter(Mandatory = $false)]
    [boolean]
    $compressData,

    [Parameter(Mandatory = $false)]
    [boolean]
    $isCompressDataEnabled
)

if($fullAccess.count -gt 0){
    Grant-SmbShareAccess -Name "$name" -AccountName $fullAccess -AccessRight Full -SmbInstance Default -Force
}
if($changeAccess.count -gt 0){
    Grant-SmbShareAccess -Name "$name" -AccountName $changeAccess -AccessRight Change -SmbInstance Default -Force
}
if($readAccess.count -gt 0){
    Grant-SmbShareAccess -Name "$name" -AccountName $readAccess -AccessRight Read -SmbInstance Default -Force
}
if($noAccess.count -gt 0){
    Revoke-SmbShareAccess -Name "$name" -AccountName $noAccess -SmbInstance Default  -Force
    Block-SmbShareAccess -Name "$name" -AccountName $noAccess -SmbInstance Default -Force
}
if($unblockAccess.count -gt 0){
    Unblock-SmbShareAccess -Name "$name" -AccountName $unblockAccess -SmbInstance Default  -Force
}
if($isCompressDataEnabled){
    Set-SmbShare -Name "$name" -CompressData $compressData -Force
}

Set-SmbShare -Name "$name" -CachingMode "$cachingMode" -EncryptData  $encryptData -Force




}
## [END] Edit-WACVMSmbFileShare ##
function Edit-WACVMSmbServerCertificateMapping {
<#
.SYNOPSIS
Edit SMB Server Certificate Mapping

.DESCRIPTION
Edits smb over QUIC certificate.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER thumbprint
    String -- The thumbprint of the certifiacte selected.

.PARAMETER newSelectedDnsNames
    String[] -- The addresses newly added to the certificate mapping.

.PARAMETER unSelectedDnsNames
    String[] -- To addresses to be removed from the certificate mapping.

#>
param (
    [Parameter(Mandatory = $true)]
    [String]
    $Thumbprint,

    [Parameter(Mandatory = $false)]
    [String[]]
    $NewSelectedDnsNames,

    [Parameter(Mandatory = $false)]
    [String[]]
    $UnSelectedDnsNames,

    [Parameter(Mandatory = $true)]
    [boolean]
    $IsKdcProxyEnabled,

    [Parameter(Mandatory = $true)]
    [String]
    $KdcProxyOptionSelected,

    [Parameter(Mandatory = $true)]
    [boolean]
    $IsKdcProxyMappedForSmbOverQuic,

    [Parameter(Mandatory = $false)]
    [String]
    $KdcPort,

    [Parameter(Mandatory = $false)]
    [String]
    $CurrentkdcPort,

    [Parameter(Mandatory = $false)]
    [boolean]
    $IsSameCertificate
)

Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue
Set-Variable -Name LogName -Option Constant -Value "Microsoft-ServerManagementExperience" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SmeScripts-ConfigureKdcProxy" -ErrorAction SilentlyContinue

function writeInfoLog($logMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
        -Message $logMessage -ErrorAction SilentlyContinue
}

Set-Location Cert:\LocalMachine\My

$port = "0.0.0.0:"
$urlLeft = "https://+:"
$urlRight = "/KdcProxy"

if ($UnSelectedDnsNames.count -gt 0) {
    foreach ($unSelectedDnsName in $UnSelectedDnsNames) {
        Remove-SmbServerCertificateMapping -Name $unSelectedDnsName -Force
    }
}

if ($NewSelectedDnsNames.count -gt 0) {
    foreach ($newSelectedDnsName in $NewSelectedDnsNames) {
        New-SmbServerCertificateMapping -Name $newSelectedDnsName -Thumbprint $Thumbprint -StoreName My -Force
    }
}

function Delete-KdcSSLCert([string]$deletePort) {
    $ipport = $port+$deletePort
    $deleteCertKdc = netsh http delete sslcert ipport=$ipport
    if ($LASTEXITCODE -ne 0) {
        throw $deleteCertKdc
    }
    $message = 'Completed deleting  ssl certificate port'
    writeInfoLog $message
    return;
}

function Enable-KdcProxy {

    $ipport = $port+$KdcPort
    $ComputerName = (Get-CimInstance Win32_ComputerSystem).DNSHostName + "." + (Get-CimInstance Win32_ComputerSystem).Domain
    try {
        if(!$IsSameCertificate -or ($KdcPort -ne $CurrentkdcPort) -or (!$IsKdcProxyMappedForSmbOverQuic) ) {
            $guid = [Guid]::NewGuid()
            $netshAddCertBinding = netsh http add sslcert ipport=$ipport certhash=$Thumbprint certstorename="my" appid="{$guid}"
            if ($LASTEXITCODE -ne 0) {
              throw $netshAddCertBinding
            }
            $message = 'Completed adding ssl certificate port'
            writeInfoLog $message
        }
        if ($NewSelectedDnsNames.count -gt 0) {
            foreach ($newSelectedDnsName in $NewSelectedDnsNames) {
                if($ComputerName.trim() -ne $newSelectedDnsName.trim()){
                    $output = Echo 'Y' | netdom computername $ComputerName /add $newSelectedDnsName
                    if ($LASTEXITCODE -ne 0) {
                        throw $output
                    }
                }
                $message = 'Completed adding alternate names for the computer'
                writeInfoLog $message
            }
        }
        if (!$IsKdcProxyEnabled) {
            $url = $urlLeft + $KdcPort + $urlRight
            $netshOutput = netsh http add urlacl url=$url user="NT authority\Network Service"
            if ($LASTEXITCODE -ne 0) {
                throw $netshOutput
            }
            $message = 'Completed adding urlacl'
            writeInfoLog $message
            New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings"  -force
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" -Name "HttpsClientAuth" -Value 0x0 -type DWORD
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" -Name "DisallowUnprotectedPasswordAuth" -Value 0x0 -type DWORD
            Set-Service -Name kpssvc -StartupType Automatic
            Start-Service -Name kpssvc
        }
        $message = 'Returning from call Enable-KdcProxy'
        writeInfoLog $message
        return $true;
    }
    catch {
        throw $_
    }
}

if($IsKdcProxyEnabled -and $KdcProxyOptionSelected -eq "enabled" -and ($KdcPort -ne $CurrentkdcPort)) {
    $url = $urlLeft + $CurrentkdcPort + $urlRight
    $deleteOutput = netsh http delete urlacl url=$url
    if ($LASTEXITCODE -ne 0) {
        throw $deleteOutput
    }
    $message = 'Completed deleting urlacl'
    writeInfoLog $message
    $newUrl = $urlLeft + $KdcPort + $urlRight
    $netshOutput = netsh http add urlacl url=$newUrl user="NT authority\Network Service"
    if ($LASTEXITCODE -ne 0) {
        throw $netshOutput
    }
    $message = 'Completed adding urlacl'
    writeInfoLog $message
}

if ($KdcProxyOptionSelected -eq "enabled" -and $KdcPort -ne $null) {
    if($IsKdcProxyMappedForSmbOverQuic -and (!$IsSameCertificate -or ($KdcPort -ne $CurrentkdcPort))) {
        Delete-KdcSSLCert $CurrentkdcPort
    }
    $result = Enable-KdcProxy
    if ($result) {
        $firewallString = "KDC Proxy Server service (KPS) for SMB over QUIC"
        $firewallDesc = "The KDC Proxy Server service runs on edge servers to proxy Kerberos protocol messages to domain controllers on the corporate network. Default port is TCP/443."
        New-NetFirewallRule -DisplayName $firewallString -Description $firewallDesc -Protocol TCP -LocalPort $KdcPort -Direction Inbound -Action Allow
    }
}

if ($IsKdcProxyMappedForSmbOverQuic -and $KdcProxyOptionSelected -ne "enabled" ) {
    Delete-KdcSSLCert $CurrentKdcPort
    $firewallString = "KDC Proxy Server service (KPS) for SMB over QUIC"
    Remove-NetFirewallRule -DisplayName $firewallString
}



}
## [END] Edit-WACVMSmbServerCertificateMapping ##
function Enable-WACVMSmbOverQuic {
<#

.SYNOPSIS
Disables smb over QUIC on the server.

.DESCRIPTION
Disables smb over QUIC on the server.

.ROLE
Administrators

#>

Set-SmbServerConfiguration -EnableSMBQUIC $true -Force
}
## [END] Enable-WACVMSmbOverQuic ##
function Expand-WACVMArchiveFileSystemEntity {
<#

.SYNOPSIS
Expands the specified file system entity (files, folders) of the system.

.DESCRIPTION
Expands the specified file system entity (files, folders) of the system on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER pathSource
    String -- The path to expand.

.PARAMETER PathDestination
    String -- The destination path to expand into.

.PARAMETER Force
    boolean -- override any confirmations

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $PathSource,    

    [Parameter(Mandatory = $true)]
    [String]
    $PathDestination,

    [Parameter(Mandatory = $false)]
    [boolean]
    $Force
)

Set-StrictMode -Version 5.0

if ($Force) {
    Expand-Archive -Path $PathSource -Force -DestinationPath $PathDestination
} else {
    Expand-Archive -Path $PathSource -DestinationPath $PathDestination
}

if ($error) {
    $code = $error[0].Exception.HResult
    @{ status = "error"; code = $code; message = $error }
} else {
    @{ status = "ok"; }
}

}
## [END] Expand-WACVMArchiveFileSystemEntity ##
function Export-WACVMEventLogChannel {
<#

.SYNOPSIS
Export the event log channel file (.evtx) with filter XML.

.DESCRIPTION
Export the event log channel file (.evtx) with filter XML.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

#>

Param(
    [string]$channel,
    [string]$filterXml
)

$segments = $channel.Split("-")
$name = $segments[-1]

$randomString = [GUID]::NewGuid().ToString()
$ResultFile = $env:temp + "\" + $name + "_" + $randomString + ".evtx"
$ResultFile = $ResultFile -replace "/", "-"

wevtutil epl "$channel" "$ResultFile" /q:"$filterXml" /ow:true

return $ResultFile

}
## [END] Export-WACVMEventLogChannel ##
function Get-WACVMAzureHybridManagementConfiguration {
<#

.SYNOPSIS
Script that return the hybrid management configurations.

.DESCRIPTION
Script that return the hybrid management configurations.

.ROLE
Administrators

#>

Set-StrictMode -Version 5.0
Import-Module Microsoft.PowerShell.Management

<#

.SYNOPSIS
Setup script runtime environment.

.DESCRIPTION
Onboards a machine for hybrid management.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScript" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-HybridManagementConfiguration.ps1" -Scope Script
    Set-Variable -Name HybridAgentExecutable -Option ReadOnly -Value "$env:ProgramFiles\AzureConnectedMachineAgent\azcmagent.exe" -Scope Script
}

<#

.SYNOPSIS
Cleanup script runtime environment.

.DESCRIPTION
Cleanup script runtime environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name HybridAgentExecutable -Scope Script -Force
}

function main() {
    $config = & $HybridAgentExecutable show

    if ($config -and $config.count -gt 10) {
        @{ 
            machine = getValue($config[0]);
            resourceGroup = getValue($config[1]);
            subscriptionId = getValue($config[3]);
            tenantId = getValue($config[4])
            vmId = getValue($config[5]);
            azureRegion = getValue($config[7]);
            agentVersion = getValue($config[10]);
            agentStatus = getValue($config[12]);
            agentLastHeartbeat = getValue($config[13]);
        }
    } else {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]:Could not find the Azure hybrid agent configuration."  -ErrorAction SilentlyContinue

        Write-Error @($err)[0]
        return @()
    }
}

function getValue([string]$keyValue) {
    $splitArray = $keyValue -split " : "
    $value = $splitArray[1].trim()
    return $value
}

###############################################################################
# Script execution starts here
###############################################################################
setupScriptEnv

try {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    return main

} finally {
    cleanupScriptEnv
}
}
## [END] Get-WACVMAzureHybridManagementConfiguration ##
function Get-WACVMAzureHybridManagementOnboardState {
<#

.SYNOPSIS
Script that returns if Azure Hybrid Agent is running or not.

.DESCRIPTION
Script that returns if Azure Hybrid Agent is running or not.

.ROLE
Readers

#>

Import-Module Microsoft.PowerShell.Management

$status = Get-Service -Name himds -ErrorAction SilentlyContinue
if ($null -eq $status) {
    # which means no such service is found.
    @{ Installed = $false; Running = $false }
}
elseif ($status.Status -eq "Running") {
    @{ Installed = $true; Running = $true }
}
else {
    @{ Installed = $true; Running = $false }
}

}
## [END] Get-WACVMAzureHybridManagementOnboardState ##
function Get-WACVMBestHostNode {
<#

.SYNOPSIS
Returns the list of available cluster node names, and the best node name to host a new virtual machine.

.DESCRIPTION
Use the cluster CIM provider (MSCluster) to ask the cluster which node is the best to host a new virtual machine.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0

Import-Module CimCmdlets -ErrorAction SilentlyContinue
Import-Module FailoverClusters -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue


<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.  Create read only (constant) variables
that add context to the said constants.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name clusterCimNameSpace -Option ReadOnly -Value "root/MSCluster" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-BestHostNode.ps1" -Scope Script
    Set-Variable -Name BestNodePropertyName -Option ReadOnly -Value "BestNode" -Scope Script
    Set-Variable -Name StateUp -Option ReadOnly -Value "0" -Scope Script
}

<#

.SYNOPSIS
Cleanup the script environment.

.DESCRIPTION
Cleanup the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name clusterCimNameSpace -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name BestNodePropertyName -Scope Script -Force
    Remove-Variable -Name StateUp -Scope Script -Force
}
    
<#

.SYNOPSIS
Get the fully qualified domain name for the passed in server name from DNS.

.DESCRIPTION
Get the fully qualified domain name for the passed in server name from DNS.

#>

function GetServerFqdn([string]$netBIOSName) {
    try {
        $fqdn = [System.Net.DNS]::GetHostByName($netBIOSName).HostName

        return $fqdn.ToLower()
    } catch {
        $errMessage = $_.Exception.Message

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: There was an error looking up the FQDN for server $netBIOSName.  Error: $errMessage"  -ErrorAction SilentlyContinue

        return $netBIOSName
    }    
}

<#

.SYNOPSIS
Are the cluster PowerShell cmdlets installed on this server?

.DESCRIPTION
Are the cluster PowerShell cmdlets installed on this server?

#>

function getIsClusterCmdletsAvailable() {
    $cmdlet = Get-Command "Get-Cluster" -ErrorAction SilentlyContinue

    return !!$cmdlet
}

<#

.SYNOPSIS
is the cluster CIM (WMI) provider installed on this server?

.DESCRIPTION
Returns true when the cluster CIM provider is installed on this server.

#>

function isClusterCimProviderAvailable() {
    $namespace = Get-CimInstance -Namespace $clusterCimNamespace -ClassName __NAMESPACE -ErrorAction SilentlyContinue

    return !!$namespace
}

<#

.SYNOPSIS
Get the MSCluster Cluster Service CIM instance from this server.

.DESCRIPTION
Get the MSCluster Cluster Service CIM instance from this server.

#>

function getClusterServiceCimInstance() {
    return Get-CimInstance -Namespace $clusterCimNamespace MSCluster_ClusterService -ErrorAction SilentlyContinue
}

<#

.SYNOPSIS
Get the list of the cluster nodes that are running.

.DESCRIPTION
Returns a list of cluster node names that are running using PowerShell.

#>

function getAllUpClusterNodeNames() {
    # Constants
    Set-Variable -Name stateUp -Option Readonly -Value "up" -Scope Local

    try {
        return Get-ClusterNode | Where-Object { $_.State -eq $stateUp } | ForEach-Object { (GetServerFqdn $_.Name) }
    } finally {
        Remove-Variable -Name stateUp -Scope Local -Force
    }
}

<#

.SYNOPSIS
Get the list of the cluster nodes that are running.

.DESCRIPTION
Returns a list of cluster node names that are running using CIM.

#>

function getAllUpClusterCimNodeNames() {
##SkipCheck=true##
    $query = "select name, state from MSCluster_Node Where state = '{0}'" -f $StateUp
##SkipCheck=false##
    return Get-CimInstance -Namespace $clusterCimNamespace -Query $query | ForEach-Object { (GetServerFqdn $_.Name) }
}

<#

.SYNOPSIS
Create a new instance of the "results" PS object.

.DESCRIPTION
Create a new PS object and set the passed in nodeNames to the appropriate property.

#>

function newResult([string []] $nodeNames) {
    $result = new-object PSObject
    $result | Add-Member -Type NoteProperty -Name Nodes -Value $nodeNames

    return $result;
}

<#

.SYNOPSIS
Remove any old lingering reservation for our typical VM.

.DESCRIPTION
Remove the reservation from the passed in id.

#>

function removeReservation($clusterService, [string] $rsvId) {
    Set-Variable removeReservationMethodName -Option Constant -Value "RemoveVmReservation"

    Invoke-CimMethod -CimInstance $clusterService -MethodName $removeReservationMethodName -Arguments @{ReservationId = $rsvId} -ErrorVariable +err | Out-Null    
}

<#

.SYNOPSIS
Create a reservation for our typical VM.

.DESCRIPTION
Create a reservation for the passed in id.

#>

function createReservation($clusterService, [string] $rsvId) {
    Set-Variable -Name createReservationMethodName -Option ReadOnly -Value "CreateVmReservation" -Scope Local
    Set-Variable -Name reserveSettings -Option ReadOnly -Value @{VmMemory = 2048; VmVirtualCoreCount = 2; VmCpuReservation = 0; VmFlags = 0; TimeSpan = 2000; ReservationId = $rsvId; LocalDiskSize = 0; Version = 0} -Scope Local

    try {
        $vmReserve = Invoke-CimMethod -CimInstance $clusterService -MethodName $createReservationMethodName -ErrorAction SilentlyContinue -ErrorVariable va -Arguments $reserveSettings

        if (!!$vmReserve -and $vmReserve.ReturnValue -eq 0 -and !!$vmReserve.NodeId) {
            return $vmReserve.NodeId
        }

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Could not create a reservation for a virtual machine. Output from $createReservationMethodName is $vmReserve"  -ErrorAction SilentlyContinue

        return $null
    } finally {
        Remove-Variable -Name createReservationMethodName -Scope Local -Force
        Remove-Variable -Name reserveSettings -Scope Local -Force
    }
}

<#

.SYNOPSIS
Use the Cluster CIM provider to find the best host name for a typical VM.

.DESCRIPTION
Returns the best host node name, or null when none are found.

#>

function askClusterServiceForBestHostNode() {
    # API parameters
    Set-Variable -Name rsvId -Option ReadOnly -Value "TempVmId1" -Scope Local
    
    try {
        # If the class exist, using api to get optimal host
        $clusterService = getClusterServiceCimInstance
        if (!!$clusterService) {
            $nodeNames = @(getAllUpClusterCimNodeNames)
            $result = newResult $nodeNames
        
            # remove old reserveration if there is any
            removeReservation $clusterService $rsvId

            $id = createReservation $clusterService $rsvId

            if (!!$id) {
    ##SkipCheck=true##            
                $query = "select name, id from MSCluster_Node where id = '{0}'" -f $id
    ##SkipCheck=false##
                $bestNode = Get-CimInstance -Namespace $clusterCimNamespace -Query $query -ErrorAction SilentlyContinue

                if ($bestNode) {
                    $result | Add-Member -Type NoteProperty -Name $BestNodePropertyName -Value (GetServerFqdn $bestNode.Name)

                    return $result
                }
            } 
        }

        return $null
    } finally {
        Remove-Variable -Name rsvId -Scope Local -Force
    }
}

<#

.SYNOPSIS
Get the name of the cluster node that has the least number of VMs running on it.

.DESCRIPTION
Return the name of the cluster node that has the least number of VMs running on it.

#>

function getLeastLoadedNode() {
    # Constants
    Set-Variable -Name vmResourceTypeName -Option ReadOnly -Value "Virtual Machine" -Scope Local
    Set-Variable -Name OwnerNodePropertyName -Option ReadOnly -Value "OwnerNode" -Scope Local

    try {
        $nodeNames = @(getAllUpClusterNodeNames)
        $bestNodeName = $null;

        $result = newResult $nodeNames

        $virtualMachinesPerNode = @{}

        # initial counts as 0
        $nodeNames | ForEach-Object { $virtualMachinesPerNode[$_] = 0 }

        $ownerNodes = Get-ClusterResource | Where-Object { $_.ResourceType -eq $vmResourceTypeName } | Microsoft.PowerShell.Utility\Select-Object $OwnerNodePropertyName
        $ownerNodes | ForEach-Object { $virtualMachinesPerNode[$_.OwnerNode.Name]++ }

        # find node with minimum count
        $bestNodeName = $nodeNames[0]
        $min = $virtualMachinesPerNode[$bestNodeName]

        $nodeNames | ForEach-Object { 
            if ($virtualMachinesPerNode[$_] -lt $min) {
                $bestNodeName = $_
                $min = $virtualMachinesPerNode[$_]
            }
        }

        $result | Add-Member -Type NoteProperty -Name $BestNodePropertyName -Value (GetServerFqdn $bestNodeName)

        return $result
    } finally {
        Remove-Variable -Name vmResourceTypeName -Scope Local -Force
        Remove-Variable -Name OwnerNodePropertyName -Scope Local -Force
    }
}

<#

.SYNOPSIS
Main

.DESCRIPTION
Use the various mechanism available to determine the best host node.

#>

function main() {
    if (isClusterCimProviderAvailable) {
        $bestNode = askClusterServiceForBestHostNode
        if (!!$bestNode) {
            return $bestNode
        }
    }

    if (getIsClusterCmdletsAvailable) {
        return getLeastLoadedNode
    } else {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Warning `
            -Message "[$ScriptName]: The required PowerShell module (FailoverClusters) was not found."  -ErrorAction SilentlyContinue

        Write-Warning $strings.FailoverClustersModuleRequired
    }

    return $null    
}

###############################################################################
# Script execution begins here.
###############################################################################

if (-not ($env:pester)) {
    setupScriptEnv

    try {
        Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

        $result = main
        if (!!$result) {
            return $result
        }

        # If neither cluster CIM provider or PowerShell cmdlets are available then simply
        # return this computer's name as the best host node...
        $nodeName = GetServerFqdn $env:COMPUTERNAME

        $result = newResult @($nodeName)
        $result | Add-Member -Type NoteProperty -Name $BestNodePropertyName -Value $nodeName

        return $result
    } finally {
        cleanupScriptEnv
    }
}

}
## [END] Get-WACVMBestHostNode ##
function Get-WACVMCertificates {
<#

.SYNOPSIS
Get the certificates stored in my\store

.DESCRIPTION
Get the certificates stored in my\store

.ROLE
Readers

#>

$nearlyExpiredThresholdInDays = 60

$dnsNameList = @{}

<#
.Synopsis
    Name: Compute-ExpirationStatus
    Description: Computes expiration status based on notAfter date.
.Parameters
    $notAfter: A date object refering to certificate expiry date.

.Returns
    Enum values "Expired", "NearlyExpired" and "Healthy"
#>
function Compute-ExpirationStatus {
    param (
        [Parameter(Mandatory = $true)]
        [DateTime]$notAfter
    )

    if ([DateTime]::Now -gt $notAfter) {
        $expirationStatus = "Expired"
    }
    else {
        $nearlyExpired = [DateTime]::Now.AddDays($nearlyExpiredThresholdInDays);

        if ($nearlyExpired -ge $notAfter) {
            $expirationStatus = "NearlyExpired"
        }
        else {
            $expirationStatus = "Healthy"
        }
    }

    $expirationStatus
}

<# main - script starts here #>

Set-Location Cert:\LocalMachine\My

$certificates = Get-ChildItem -Recurse | Microsoft.PowerShell.Utility\Select-Object Subject, FriendlyName, NotBefore, NotAfter,
 Thumbprint, Issuer, @{n="DnsNameList";e={$_.DnsNameList}}, @{n="SignatureAlgorithm";e={$_.SignatureAlgorithm.FriendlyName}} |
ForEach-Object {
    return @{
        CertificateName = $_.Subject;
        FriendlyName = $_.FriendlyName;
        NotBefore = $_.NotBefore;
        NotAfter = $_.NotAfter;
        Thumbprint = $_.Thumbprint;
        Issuer = $_.Issuer;
        DnsNameList = $_.DnsNameList;
        Status = $(Compute-ExpirationStatus $_.NotAfter);
        SignatureAlgorithm  = $_.SignatureAlgorithm;
    }
}

return $certificates;

}
## [END] Get-WACVMCertificates ##
function Get-WACVMCimEventLogRecords {
<#

.SYNOPSIS
Get Log records of event channel by using Server Manager CIM provider.

.DESCRIPTION
Get Log records of event channel by using Server Manager CIM provider.

.ROLE
Readers

#>

Param(
    [string]$FilterXml,
    [bool]$ReverseDirection
)

import-module CimCmdlets

$machineName = [System.Net.DNS]::GetHostByName('').HostName
Invoke-CimMethod -Namespace root/Microsoft/Windows/ServerManager -ClassName MSFT_ServerManagerTasks -MethodName GetServerEventDetailEx -Arguments @{FilterXml = $FilterXml; ReverseDirection = $ReverseDirection; } |
    ForEach-Object {
        $result = $_
        if ($result.PSObject.Properties.Match('ItemValue').Count) {
            foreach ($item in $result.ItemValue) {
                @{
                    ItemValue = 
                    @{
                        Description  = $item.description
                        Id           = $item.id
                        Level        = $item.level
                        Log          = $item.log
                        Source       = $item.source
                        Timestamp    = $item.timestamp
                        __ServerName = $machineName
                    }
                }
            }
        }
    }

}
## [END] Get-WACVMCimEventLogRecords ##
function Get-WACVMCimServiceDetail {
<#

.SYNOPSIS
Gets services in details using MSFT_ServerManagerTasks class.

.DESCRIPTION
Gets services in details using MSFT_ServerManagerTasks class.

.ROLE
Readers

#>

##SkipCheck=true##

Param(
)

import-module CimCmdlets

Invoke-CimMethod -Namespace root/microsoft/windows/servermanager -ClassName MSFT_ServerManagerTasks -MethodName GetServerServiceDetail

}
## [END] Get-WACVMCimServiceDetail ##
function Get-WACVMCimSingleService {
<#

.SYNOPSIS
Gets the service instance of CIM Win32_Service class.

.DESCRIPTION
Gets the service instance of CIM Win32_Service class.

.ROLE
Readers

#>

##SkipCheck=true##

Param(
[string]$Name
)

import-module CimCmdlets

$keyInstance = New-CimInstance -Namespace root/cimv2 -ClassName Win32_Service -Key @('Name') -Property @{Name=$Name;} -ClientOnly
Get-CimInstance $keyInstance

}
## [END] Get-WACVMCimSingleService ##
function Get-WACVMCimWin32LogicalDisk {
<#

.SYNOPSIS
Gets Win32_LogicalDisk object.

.DESCRIPTION
Gets Win32_LogicalDisk object.

.ROLE
Readers

#>
##SkipCheck=true##


import-module CimCmdlets

Get-CimInstance -Namespace root/cimv2 -ClassName Win32_LogicalDisk

}
## [END] Get-WACVMCimWin32LogicalDisk ##
function Get-WACVMCimWin32NetworkAdapter {
<#

.SYNOPSIS
Gets Win32_NetworkAdapter object.

.DESCRIPTION
Gets Win32_NetworkAdapter object.

.ROLE
Readers

#>
##SkipCheck=true##


import-module CimCmdlets

Get-CimInstance -Namespace root/cimv2 -ClassName Win32_NetworkAdapter

}
## [END] Get-WACVMCimWin32NetworkAdapter ##
function Get-WACVMCimWin32PhysicalMemory {
<#

.SYNOPSIS
Gets Win32_PhysicalMemory object.

.DESCRIPTION
Gets Win32_PhysicalMemory object.

.ROLE
Readers

#>
##SkipCheck=true##


import-module CimCmdlets

Get-CimInstance -Namespace root/cimv2 -ClassName Win32_PhysicalMemory

}
## [END] Get-WACVMCimWin32PhysicalMemory ##
function Get-WACVMCimWin32Processor {
<#

.SYNOPSIS
Gets Win32_Processor object.

.DESCRIPTION
Gets Win32_Processor object.

.ROLE
Readers

#>
##SkipCheck=true##


import-module CimCmdlets

Get-CimInstance -Namespace root/cimv2 -ClassName Win32_Processor

}
## [END] Get-WACVMCimWin32Processor ##
function Get-WACVMClusterEvents {
<#
.SYNOPSIS
Gets CIM instance

.DESCRIPTION
Gets CIM instance

.ROLE
Readers

#>

param (
		[Parameter(Mandatory = $true)]
		[string]
    $namespace,

    [Parameter(Mandatory = $true)]
		[string]
    $className

)
Import-Module CimCmdlets
Get-CimInstance -Namespace  $namespace -ClassName $className

}
## [END] Get-WACVMClusterEvents ##
function Get-WACVMClusterInventory {
<#

.SYNOPSIS
Retrieves the inventory data for a cluster.

.DESCRIPTION
Retrieves the inventory data for a cluster.

.ROLE
Readers

#>

Import-Module CimCmdlets -ErrorAction SilentlyContinue

# JEA code requires to pre-import the module (this is slow on failover cluster environment.)
Import-Module FailoverClusters -ErrorAction SilentlyContinue

Import-Module Storage -ErrorAction SilentlyContinue
<#

.SYNOPSIS
Get the name of this computer.

.DESCRIPTION
Get the best available name for this computer.  The FQDN is preferred, but when not avaialble
the NetBIOS name will be used instead.

#>

function getComputerName() {
    $computerSystem = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object Name, DNSHostName

    if ($computerSystem) {
        $computerName = $computerSystem.DNSHostName

        if ($null -eq $computerName) {
            $computerName = $computerSystem.Name
        }

        return $computerName
    }

    return $null
}

<#

.SYNOPSIS
Are the cluster PowerShell cmdlets installed on this server?

.DESCRIPTION
Are the cluster PowerShell cmdlets installed on this server?

#>

function getIsClusterCmdletAvailable() {
    $cmdlet = Get-Command "Get-Cluster" -ErrorAction SilentlyContinue

    return !!$cmdlet
}

<#

.SYNOPSIS
Get the MSCluster Cluster CIM instance from this server.

.DESCRIPTION
Get the MSCluster Cluster CIM instance from this server.

#>
function getClusterCimInstance() {
    $namespace = Get-CimInstance -Namespace root/MSCluster -ClassName __NAMESPACE -ErrorAction SilentlyContinue

    if ($namespace) {
        return Get-CimInstance -Namespace root/mscluster MSCluster_Cluster -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object fqdn, S2DEnabled
    }

    return $null
}


<#

.SYNOPSIS
Determines if the current cluster supports Failover Clusters Time Series Database.

.DESCRIPTION
Use the existance of the path value of cmdlet Get-StorageHealthSetting to determine if TSDB
is supported or not.

#>
function getClusterPerformanceHistoryPath() {
    return $null -ne (Get-StorageSubSystem clus* | Get-StorageHealthSetting -Name "System.PerformanceHistory.Path")
}

<#

.SYNOPSIS
Get some basic information about the cluster from the cluster.

.DESCRIPTION
Get the needed cluster properties from the cluster.

#>
function getClusterInfo() {
    $returnValues = @{}

    $returnValues.Fqdn = $null
    $returnValues.isS2DEnabled = $false
    $returnValues.isTsdbEnabled = $false

    $cluster = getClusterCimInstance
    if ($cluster) {
        $returnValues.Fqdn = $cluster.fqdn
        $isS2dEnabled = !!(Get-Member -InputObject $cluster -Name "S2DEnabled") -and ($cluster.S2DEnabled -eq 1)
        $returnValues.isS2DEnabled = $isS2dEnabled

        if ($isS2DEnabled) {
            $returnValues.isTsdbEnabled = getClusterPerformanceHistoryPath
        } else {
            $returnValues.isTsdbEnabled = $false
        }
    }

    return $returnValues
}

<#

.SYNOPSIS
Are the cluster PowerShell Health cmdlets installed on this server?

.DESCRIPTION
Are the cluster PowerShell Health cmdlets installed on this server?

s#>
function getisClusterHealthCmdletAvailable() {
    $cmdlet = Get-Command -Name "Get-HealthFault" -ErrorAction SilentlyContinue

    return !!$cmdlet
}
<#

.SYNOPSIS
Are the Britannica (sddc management resources) available on the cluster?

.DESCRIPTION
Are the Britannica (sddc management resources) available on the cluster?

#>
function getIsBritannicaEnabled() {
    return $null -ne (Get-CimInstance -Namespace root/sddc/management -ClassName SDDC_Cluster -ErrorAction SilentlyContinue)
}

<#

.SYNOPSIS
Are the Britannica (sddc management resources) virtual machine available on the cluster?

.DESCRIPTION
Are the Britannica (sddc management resources) virtual machine available on the cluster?

#>
function getIsBritannicaVirtualMachineEnabled() {
    return $null -ne (Get-CimInstance -Namespace root/sddc/management -ClassName SDDC_VirtualMachine -ErrorAction SilentlyContinue)
}

<#

.SYNOPSIS
Are the Britannica (sddc management resources) virtual switch available on the cluster?

.DESCRIPTION
Are the Britannica (sddc management resources) virtual switch available on the cluster?

#>
function getIsBritannicaVirtualSwitchEnabled() {
    return $null -ne (Get-CimInstance -Namespace root/sddc/management -ClassName SDDC_VirtualSwitch -ErrorAction SilentlyContinue)
}

###########################################################################
# main()
###########################################################################

$clusterInfo = getClusterInfo

$result = New-Object PSObject

$result | Add-Member -MemberType NoteProperty -Name 'Fqdn' -Value $clusterInfo.Fqdn
$result | Add-Member -MemberType NoteProperty -Name 'IsS2DEnabled' -Value $clusterInfo.isS2DEnabled
$result | Add-Member -MemberType NoteProperty -Name 'IsTsdbEnabled' -Value $clusterInfo.isTsdbEnabled
$result | Add-Member -MemberType NoteProperty -Name 'IsClusterHealthCmdletAvailable' -Value (getIsClusterHealthCmdletAvailable)
$result | Add-Member -MemberType NoteProperty -Name 'IsBritannicaEnabled' -Value (getIsBritannicaEnabled)
$result | Add-Member -MemberType NoteProperty -Name 'IsBritannicaVirtualMachineEnabled' -Value (getIsBritannicaVirtualMachineEnabled)
$result | Add-Member -MemberType NoteProperty -Name 'IsBritannicaVirtualSwitchEnabled' -Value (getIsBritannicaVirtualSwitchEnabled)
$result | Add-Member -MemberType NoteProperty -Name 'IsClusterCmdletAvailable' -Value (getIsClusterCmdletAvailable)
$result | Add-Member -MemberType NoteProperty -Name 'CurrentClusterNode' -Value (getComputerName)

$result

}
## [END] Get-WACVMClusterInventory ##
function Get-WACVMClusterNodes {
<#

.SYNOPSIS
Retrieves the inventory data for cluster nodes in a particular cluster.

.DESCRIPTION
Retrieves the inventory data for cluster nodes in a particular cluster.

.ROLE
Readers

#>

import-module CimCmdlets

# JEA code requires to pre-import the module (this is slow on failover cluster environment.)
import-module FailoverClusters -ErrorAction SilentlyContinue

###############################################################################
# Constants
###############################################################################

Set-Variable -Name LogName -Option Constant -Value "Microsoft-ServerManagementExperience" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SMEScripts" -ErrorAction SilentlyContinue
Set-Variable -Name ScriptName -Option Constant -Value $MyInvocation.ScriptName -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Are the cluster PowerShell cmdlets installed?

.DESCRIPTION
Use the Get-Command cmdlet to quickly test if the cluster PowerShell cmdlets
are installed on this server.

#>

function getClusterPowerShellSupport() {
    $cmdletInfo = Get-Command 'Get-ClusterNode' -ErrorAction SilentlyContinue

    return $cmdletInfo -and $cmdletInfo.Name -eq "Get-ClusterNode"
}

<#

.SYNOPSIS
Get the cluster nodes using the cluster CIM provider.

.DESCRIPTION
When the cluster PowerShell cmdlets are not available fallback to using
the cluster CIM provider to get the needed information.

#>

function getClusterNodeCimInstances() {
    # Change the WMI property NodeDrainStatus to DrainStatus to match the PS cmdlet output.
    return Get-CimInstance -Namespace root/mscluster MSCluster_Node -ErrorAction SilentlyContinue | `
        Microsoft.PowerShell.Utility\Select-Object @{Name="DrainStatus"; Expression={$_.NodeDrainStatus}}, DynamicWeight, Name, NodeWeight, FaultDomain, State
}

<#

.SYNOPSIS
Get the cluster nodes using the cluster PowerShell cmdlets.

.DESCRIPTION
When the cluster PowerShell cmdlets are available use this preferred function.

#>

function getClusterNodePsInstances() {
    return Get-ClusterNode -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object DrainStatus, DynamicWeight, Name, NodeWeight, FaultDomain, State
}

<#

.SYNOPSIS
Use DNS services to get the FQDN of the cluster NetBIOS name.

.DESCRIPTION
Use DNS services to get the FQDN of the cluster NetBIOS name.

.Notes
It is encouraged that the caller add their approprate -ErrorAction when
calling this function.

#>

function getClusterNodeFqdn([string]$clusterNodeName) {
    return ([System.Net.Dns]::GetHostEntry($clusterNodeName)).HostName
}

<#

.SYNOPSIS
Writes message to event log as warning.

.DESCRIPTION
Writes message to event log as warning.

#>

function writeToEventLog([string]$message) {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Warning `
        -Message $message  -ErrorAction SilentlyContinue
}

<#

.SYNOPSIS
Get the cluster nodes.

.DESCRIPTION
When the cluster PowerShell cmdlets are available get the information about the cluster nodes
using PowerShell.  When the cmdlets are not available use the Cluster CIM provider.

#>

function getClusterNodes() {
    $isClusterCmdletAvailable = getClusterPowerShellSupport

    if ($isClusterCmdletAvailable) {
        $clusterNodes = getClusterNodePsInstances
    } else {
        $clusterNodes = getClusterNodeCimInstances
    }

    $clusterNodeMap = @{}

    foreach ($clusterNode in $clusterNodes) {
        $clusterNodeName = $clusterNode.Name.ToLower()
        try 
        {
            $clusterNodeFqdn = getClusterNodeFqdn $clusterNodeName -ErrorAction SilentlyContinue
        }
        catch 
        {
            $clusterNodeFqdn = $clusterNodeName
            writeToEventLog "[$ScriptName]: The fqdn for node '$clusterNodeName' could not be obtained. Defaulting to machine name '$clusterNodeName'"
        }

        $clusterNodeResult = New-Object PSObject

        $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'FullyQualifiedDomainName' -Value $clusterNodeFqdn
        $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'Name' -Value $clusterNodeName
        $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'DynamicWeight' -Value $clusterNode.DynamicWeight
        $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'NodeWeight' -Value $clusterNode.NodeWeight
        $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'FaultDomain' -Value $clusterNode.FaultDomain
        $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'State' -Value $clusterNode.State
        $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'DrainStatus' -Value $clusterNode.DrainStatus

        $clusterNodeMap.Add($clusterNodeName, $clusterNodeResult)
    }

    return $clusterNodeMap
}

###########################################################################
# main()
###########################################################################

getClusterNodes

}
## [END] Get-WACVMClusterNodes ##
function Get-WACVMComputerName {
<#

.SYNOPSIS
Gets the computer name.

.DESCRIPTION
Gets the compuiter name.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0

$ComputerName = $env:COMPUTERNAME
@{ computerName = $ComputerName }

}
## [END] Get-WACVMComputerName ##
function Get-WACVMDecryptedDataFromNode {
<#

.SYNOPSIS
Gets data after decrypting it on a node.

.DESCRIPTION
Decrypts data on node using a cached RSAProvider used during encryption within 3 minutes of encryption and returns the decrypted data.
This script should be imported or copied directly to other scripts, do not send the returned data as an argument to other scripts.

.PARAMETER encryptedData
Encrypted data to be decrypted (String).

.ROLE
Readers

#>
param (
  [Parameter(Mandatory = $true)]
  [String]
  $encryptedData
)

Set-StrictMode -Version 5.0

New-Variable -Name rsaProviderInstanceName -Value "RSA" -Option Constant

function DecryptDataWithJWKOnNode {
  if(Get-Variable -Scope Global -Name $rsaProviderInstanceName -EA SilentlyContinue) {
    $rsaProvider = (Get-Variable -Scope Global -Name $rsaProviderInstanceName).Value
    $decryptedBytes = $rsaProvider.Decrypt([Convert]::FromBase64String($encryptedData), [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA1)
    return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
  }
  # If you copy this script directly to another, you can get rid of the throw statement and add custom error handling logic such as "Write-Error"
  throw [System.InvalidOperationException] "Password decryption failed. RSACryptoServiceProvider Instance not found"
}

}
## [END] Get-WACVMDecryptedDataFromNode ##
function Get-WACVMDesktopAvailability {
<#

.SYNOPSIS
Gets the availability of the installed desktop GUI features to enable Remote Applications

.DESCRIPTION
Gets the availability of the installed desktop GUI features across all Operating System types. This information is
is used as a basis for enabling connections to Remote Apps.

.ROLE
Readers

#>

Set-Variable StateAvailable -Option Constant -Value 'Available' -ErrorAction SilentlyContinue
Set-Variable MessageAvailable -Option Constant -Value 'Remote App tool is enabled and ready' -ErrorAction SilentlyContinue

Set-Variable StateNotSupported -Option Constant -Value 'NotSupported' -ErrorAction SilentlyContinue
Set-Variable MessageNotSupported -Option Constant -Value 'Remote App tool is not supported for this system configuration' -ErrorAction SilentlyContinue

Set-Variable RegistryKey -Option Constant -Value 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
Set-Variable PropertyName -Option Constant -Value 'InstallationType' -ErrorAction SilentlyContinue

# Gets the value of the installed operating system type. Returns a string, eg: 'Server Core'
function GetOperatingSystemType () {
    return Get-ItemProperty -Path $RegistryKey -Name $PropertyName | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty $PropertyName
}

# Checks to see if the Desktop UI is installed on the OS. Builds an 'Available' response if it is.
function CheckIfFeatureInstalled ([string] $oSTypeString) {
    switch ($oSTypeString) {
        'Client' {
            return BuildResponseObject -State $StateAvailable -Message $MessageAvailable;
        }
        'Server' {
            if (Get-Command Get-WindowsFeature -errorAction SilentlyContinue) {
                $DesktopFeature = Get-WindowsFeature -Name Desktop-Experience
                if ($DesktopFeature.Installed) {
                    return BuildResponseObject -State $StateAvailable -Message $MessageAvailable;
                }
            }
        }
    }
}

# The object that is returned to the inventory loader when a tool should be available or not. 
function BuildResponseObject ([string] $state, [string] $message) {
    $ResponseObject = @{
        State      = $state;
        Message    = $message;
        Properties = @{};
    }

    return $ResponseObject
}

# Checks the OS type, and builds a response object based on whether the desktop UI is available or not.
function GetAvailability() {
    $OperatingSystemType = GetOperatingSystemType
    $Response = CheckIfFeatureInstalled -oSTypeString $OperatingSystemType
    if (!$Response) {
        $Response = BuildResponseObject -state $StateNotSupported -message $MessageNotSupported
    }

    return $Response
}

return GetAvailability

}
## [END] Get-WACVMDesktopAvailability ##
function Get-WACVMEncryptionJWKOnNode {
<#

.SYNOPSIS
Gets encrytion JSON web key from node.

.DESCRIPTION
Gets encrytion JSON web key from node.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0

New-Variable -Name rsaProviderInstanceName -Value "RSA" -Option Constant

function Get-RSAProvider
{
    if(Get-Variable -Scope Global -Name $rsaProviderInstanceName -EA SilentlyContinue)
    {
        return (Get-Variable -Scope Global -Name $rsaProviderInstanceName).Value
    }

    $Global:RSA = New-Object System.Security.Cryptography.RSACryptoServiceProvider -ArgumentList 4096
    return $RSA
}

function Get-JsonWebKey
{
    $rsaProvider = Get-RSAProvider
    $parameters = $rsaProvider.ExportParameters($false)
    return [PSCustomObject]@{
        kty = 'RSA'
        alg = 'RSA-OAEP'
        e = [Convert]::ToBase64String($parameters.Exponent)
        n = [Convert]::ToBase64String($parameters.Modulus).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    }
}

$jwk = Get-JsonWebKey
ConvertTo-Json $jwk -Compress

}
## [END] Get-WACVMEncryptionJWKOnNode ##
function Get-WACVMEnhancedSessionState {
<#

.SYNOPSIS
Gets the enumerated Enhanced Session state from a VM

.DESCRIPTION
Gets the enumerated Enhanced Session state between a VM and it's host system by querying the Msvm_Computersystem class in the cim instance.
It's enumeration values can be found at https://msdn.microsoft.com/en-us/library/windows/desktop/hh850116(v=vs.85).aspx

.ROLE
Readers

#>

Param(
    [Parameter(Mandatory = $true)]
    [string]
    $vmGuid
)

function GetEnhancedSessionState([string] $vmGuid) {
    $state = Get-CimInstance  -Namespace Root\Virtualization\V2 -ClassName Msvm_ComputerSystem | 
        Where-Object {$_.Name -eq $vmGuid} | 
        Microsoft.PowerShell.Utility\Select-Object -ExpandProperty EnhancedSessionModeState
    
    return $state
}

GetEnhancedSessionState $vmGuid
}
## [END] Get-WACVMEnhancedSessionState ##
function Get-WACVMEventLogDisplayName {
<#

.SYNOPSIS
Get the EventLog log name and display name by using Get-EventLog cmdlet.

.DESCRIPTION
Get the EventLog log name and display name by using Get-EventLog cmdlet.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>


return (Get-EventLog -LogName * | Microsoft.PowerShell.Utility\Select-Object Log,LogDisplayName)
}
## [END] Get-WACVMEventLogDisplayName ##
function Get-WACVMEventLogFilteredCount {
<#

.SYNOPSIS
Get the total amout of events that meet the filters selected by using Get-WinEvent cmdlet.

.DESCRIPTION
Get the total amout of events that meet the filters selected by using Get-WinEvent cmdlet.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Param(
    [string]$filterXml
)

return (Get-WinEvent -FilterXml "$filterXml" -ErrorAction 'SilentlyContinue').count
}
## [END] Get-WACVMEventLogFilteredCount ##
function Get-WACVMEventLogRecords {
<#

.SYNOPSIS
Get Log records of event channel by using Get-WinEvent cmdlet.

.DESCRIPTION
Get Log records of event channel by using Get-WinEvent cmdlet.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers
#>

Param(
    [string]
    $filterXml,
    [bool]
    $reverseDirection
)

$ErrorActionPreference = 'SilentlyContinue'
Import-Module Microsoft.PowerShell.Diagnostics;

#
# Prepare parameters for command Get-WinEvent
#
$winEventscmdParams = @{
    FilterXml = $filterXml;
    Oldest    = !$reverseDirection;
}

Get-WinEvent  @winEventscmdParams -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object recordId,
id, 
@{Name = "Log"; Expression = {$_."logname"}}, 
level, 
timeCreated, 
machineName, 
@{Name = "Source"; Expression = {$_."ProviderName"}}, 
@{Name = "Description"; Expression = {$_."Message"}}



}
## [END] Get-WACVMEventLogRecords ##
function Get-WACVMEventLogSummary {
<#

.SYNOPSIS
Get the log summary (Name, Total) for the channel selected by using Get-WinEvent cmdlet.

.DESCRIPTION
Get the log summary (Name, Total) for the channel selected by using Get-WinEvent cmdlet.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Param(
    [string]$channel
)

Import-Module Microsoft.PowerShell.Diagnostics

$channelList = $channel.split(",")

Get-WinEvent -ListLog $channelList -Force -ErrorAction SilentlyContinue |`
    Microsoft.PowerShell.Utility\Select-Object LogName, IsEnabled, RecordCount, IsClassicLog, LogType, OwningProviderName
}
## [END] Get-WACVMEventLogSummary ##
function Get-WACVMFileNamesInPath {
<#

.SYNOPSIS
Enumerates all of the file system entities (files, folders, volumes) of the system.

.DESCRIPTION
Enumerates all of the file system entities (files, folders, volumes) of the system on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER Path
    String -- The path to enumerate.

.PARAMETER OnlyFolders
    switch -- 

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path,

    [Parameter(Mandatory = $false)]
    [switch]
    $OnlyFolders
)

Set-StrictMode -Version 5.0

function isFolder($item) {
    return $item.Attributes -match "Directory"
}

function getName($item) {
    $slash = '';

    if (isFolder $item) {
        $slash = '\';
    }

    return "$($_.Name)$slash"
}

if ($onlyFolders) {
    return (Get-ChildItem -Path $Path | Where-Object {isFolder $_}) | ForEach-Object { return "$($_.Name)\"} | Sort-Object
}

return (Get-ChildItem -Path $Path) | ForEach-Object { return getName($_)} | Sort-Object

}
## [END] Get-WACVMFileNamesInPath ##
function Get-WACVMFileSystemEntities {
<#

.SYNOPSIS
Enumerates all of the file system entities (files, folders, volumes) of the system.

.DESCRIPTION
Enumerates all of the file system entities (files, folders, volumes) of the system on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER Path
    String -- The path to enumerate.

.PARAMETER OnlyFiles
    switch --

.PARAMETER OnlyFolders
    switch --

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path,

    [Parameter(Mandatory = $false)]
    [Switch]
    $OnlyFiles,

    [Parameter(Mandatory = $false)]
    [Switch]
    $OnlyFolders
)

Set-StrictMode -Version 5.0

<#
.Synopsis
    Name: Get-FileSystemEntities
    Description: Gets all the local file system entities of the machine.

.Parameter Path
    String -- The path to enumerate.

.Returns
    The local file system entities.
#>
function Get-FileSystemEntities {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path
    )

    $folderShares = Get-CimInstance -Class Win32_Share;

    if ($Path -match '\[' -or $Path -match '\]') {
        return Get-ChildItem -LiteralPath $Path -Force |
        Microsoft.PowerShell.Utility\Select-Object @{Name = "Caption"; Expression = { $_.FullName } },
        @{Name = "CreationDate"; Expression = { $_.CreationTimeUtc } },
        Extension,
        @{Name = "IsHidden"; Expression = { $_.Attributes -match "Hidden" } },
        @{Name = "IsShared"; Expression = { [bool]($folderShares | Where-Object Path -eq $_.FullName) } },
        Name,
        @{Name = "Type"; Expression = { Get-FileSystemEntityType -Attributes $_.Attributes } },
        @{Name = "LastModifiedDate"; Expression = { $_.LastWriteTimeUtc } },
        @{Name = "Size"; Expression = { if ($_.PSIsContainer) { $null } else { $_.Length } } };
    }


    return Get-ChildItem -Path $Path -Force |
    Microsoft.PowerShell.Utility\Select-Object @{Name = "Caption"; Expression = { $_.FullName } },
    @{Name = "CreationDate"; Expression = { $_.CreationTimeUtc } },
    Extension,
    @{Name = "IsHidden"; Expression = { $_.Attributes -match "Hidden" } },
    @{Name = "IsShared"; Expression = { [bool]($folderShares | Where-Object Path -eq $_.FullName) } },
    Name,
    @{Name = "Type"; Expression = { Get-FileSystemEntityType -Attributes $_.Attributes } },
    @{Name = "LastModifiedDate"; Expression = { $_.LastWriteTimeUtc } },
    @{Name = "Size"; Expression = { if ($_.PSIsContainer) { $null } else { $_.Length } } };
}

<#
.Synopsis
    Name: Get-FileSystemEntityType
    Description: Gets the type of a local file system entity.

.Parameter Attributes
    The System.IO.FileAttributes of the FileSystemEntity.

.Returns
    The type of the local file system entity.
#>
function Get-FileSystemEntityType {
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileAttributes]
        $Attributes
    )

    if ($Attributes -match "Directory") {
        return "Folder";
    }
    else {
        return "File";
    }
}

$entities = Get-FileSystemEntities -Path $Path;
if ($OnlyFiles -and $OnlyFolders) {
    return $entities;
}

if ($OnlyFiles) {
    return $entities | Where-Object { $_.Type -eq "File" };
}

if ($OnlyFolders) {
    return $entities | Where-Object { $_.Type -eq "Folder" };
}

return $entities;

}
## [END] Get-WACVMFileSystemEntities ##
function Get-WACVMFileSystemRoot {
<#

.SYNOPSIS
Enumerates the root of the file system (volumes and related entities) of the system.

.DESCRIPTION
Enumerates the root of the file system (volumes and related entities) of the system on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0
import-module CimCmdlets

<#
.Synopsis
    Name: Get-FileSystemRoot
    Description: Gets the local file system root entities of the machine.

.Returns
    The local file system root entities.
#>
function Get-FileSystemRoot
{
    $volumes = Enumerate-Volumes;

    return $volumes |
        Microsoft.PowerShell.Utility\Select-Object @{Name="Caption"; Expression={$_.DriveLetter +":\"}},
                      @{Name="CreationDate"; Expression={$null}},
                      @{Name="Extension"; Expression={$null}},
                      @{Name="IsHidden"; Expression={$false}},
                      @{Name="Name"; Expression={if ($_.FileSystemLabel) { $_.FileSystemLabel + " (" + $_.DriveLetter + ":)"} else { "(" + $_.DriveLetter + ":)" }}},
                      @{Name="Type"; Expression={"Volume"}},
                      @{Name="LastModifiedDate"; Expression={$null}},
                      @{Name="Size"; Expression={$_.Size}},
                      @{Name="SizeRemaining"; Expression={$_.SizeRemaining}}
}

<#
.Synopsis
    Name: Get-Volumes
    Description: Gets the local volumes of the machine.

.Returns
    The local volumes.
#>
function Enumerate-Volumes
{
    Remove-Module Storage -ErrorAction Ignore; # Remove the Storage module to prevent it from automatically localizing

    $isDownlevel = [Environment]::OSVersion.Version.Major -lt 10;
    if ($isDownlevel)
    {
        $disks = Get-CimInstance -ClassName MSFT_Disk -Namespace root/Microsoft/Windows/Storage | Where-Object { !$_.IsClustered };
        $partitions = @($disks | Get-CimAssociatedInstance -ResultClassName MSFT_Partition)
        if ($partitions.Length -eq 0) {
            $volumes = Get-CimInstance -ClassName MSFT_Volume -Namespace root/Microsoft/Windows/Storage;
        } else {
            $volumes = $partitions | Get-CimAssociatedInstance -ResultClassName MSFT_Volume;
        }
    }
    else
    {
        $subsystem = Get-CimInstance -ClassName MSFT_StorageSubSystem -Namespace root/Microsoft/Windows/Storage| Where-Object { $_.FriendlyName -like "*Win*" };
        $volumes = $subsystem | Get-CimAssociatedInstance -ResultClassName MSFT_Volume;
    }

    return $volumes | Where-Object {
        try {
            [byte]$_.DriveLetter -ne 0 -and $_.DriveLetter -ne $null -and $_.Size -gt 0
        } catch {
            $false
        }
    };
}

Get-FileSystemRoot;

}
## [END] Get-WACVMFileSystemRoot ##
function Get-WACVMFolderItemCount {
<#

.SYNOPSIS
Gets the count of elements in the folder

.DESCRIPTION
Gets the count of elements in the folder
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER Path
    String -- The path to the folder

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path
)

Set-StrictMode -Version 5.0

$directoryInfo = Get-ChildItem $Path | Microsoft.PowerShell.Utility\Measure-Object
$directoryInfo.count

}
## [END] Get-WACVMFolderItemCount ##
function Get-WACVMFolderOwner {
<#

.SYNOPSIS
Gets the owner of a folder.

.DESCRIPTION
Gets the owner of a folder.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path
)

Set-StrictMode -Version 5.0

$Owner = (Get-Acl $Path).Owner
@{ owner = $Owner; }

}
## [END] Get-WACVMFolderOwner ##
function Get-WACVMFolderShareNames {
<#

.SYNOPSIS
Gets the existing share names of a shared folder

.DESCRIPTION
Gets the existing share names of a shared folder
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER Path
    String -- The path to the folder.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path
)

Set-StrictMode -Version 5.0

Get-CimInstance -Class Win32_Share -Filter Path="'$Path'" | Microsoft.PowerShell.Utility\Select-Object Name

}
## [END] Get-WACVMFolderShareNames ##
function Get-WACVMFolderSharePath {
<#

.SYNOPSIS
Gets the existing share names of a shared folder

.DESCRIPTION
Gets the existing share names of a shared folder
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER Name
    String -- The share name to the shared folder.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Name
)

Set-StrictMode -Version 5.0

Get-SmbShare -Includehidden | Where-Object { $_.Name -eq $Name } | Microsoft.PowerShell.Utility\Select-Object Path

}
## [END] Get-WACVMFolderSharePath ##
function Get-WACVMFolderShareStatus {
<#

.SYNOPSIS
Checks if a folder is shared

.DESCRIPTION
Checks if a folder is shared
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER Path
    String -- the path to the folder.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path
)

Set-StrictMode -Version 5.0

$Shared = [bool](Get-CimInstance -Class Win32_Share -Filter Path="'$Path'")
@{ isShared = $Shared }

}
## [END] Get-WACVMFolderShareStatus ##
function Get-WACVMFolderShareUsers {
<#

.SYNOPSIS
Gets the user access rights of a folder

.DESCRIPTION
Gets the user access rights of a folder
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER Path
    String -- The path to the folder.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path
)

Set-StrictMode -Version 5.0

Get-Acl $Path |  Microsoft.PowerShell.Utility\Select-Object -ExpandProperty Access | Microsoft.PowerShell.Utility\Select-Object IdentityReference, FileSystemRights, AccessControlType

}
## [END] Get-WACVMFolderShareUsers ##
function Get-WACVMIfFileExists {
<#

.SYNOPSIS
Checks the target server node to see if the selected app exists before launching it.

.DESCRIPTION
Checks the target server node to see if the selected app exists before launching it. This is used
as verification that the original file location hasn't changed and that the file is ready for use.

.ROLE
Readers

#>

Param(
    [string]$selectedFilePath
)

Test-Path -Path $selectedFilePath
}
## [END] Get-WACVMIfFileExists ##
function Get-WACVMIsAzureTurbineServer {
<#
.SYNOPSIS
Checks if the current server is Azure Turbine edition.

.DESCRIPTION
Returns true if the current server is Azure Turbine which supports smb over QUIC.

.ROLE
Readers

#>

$result = Get-WmiObject -Class Win32_OperatingSystem | Microsoft.PowerShell.Utility\Select-Object OperatingSystemSKU, Version

$result.OperatingSystemSKU -eq "407" -and [version]$result.version -ge [version]"10.0.20348"

}
## [END] Get-WACVMIsAzureTurbineServer ##
function Get-WACVMItemProperties {
<#

.SYNOPSIS
Get item's properties.

.DESCRIPTION
Get item's properties on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER Path
    String -- the path to the item whose properites are requested.

.PARAMETER ItemType
    String -- What kind of item?

#>

param (
    [Parameter(Mandatory = $true)]
    [String[]]
    $Path,

    [Parameter(Mandatory = $true)]
    [String]
    $ItemType
)

Set-StrictMode -Version 5.0

switch ($ItemType) {
    0 {
        Get-Volume $Path | Microsoft.PowerShell.Utility\Select-Object -Property *
    }
    default {
        Get-ItemProperty -Path $Path | Microsoft.PowerShell.Utility\Select-Object -Property *
    }
}

}
## [END] Get-WACVMItemProperties ##
function Get-WACVMItemType {
<#

.SYNOPSIS
Enumerates all of the file system entities (files, folders, volumes) of the system.

.DESCRIPTION
Enumerates all of the file system entities (files, folders, volumes) of the system on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER Path
    String -- the path to the folder where enumeration should start.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path
)

Set-StrictMode -Version 5.0

<#
.Synopsis
    Name: Get-FileSystemEntityType
    Description: Gets the type of a local file system entity.

.Parameter Attributes
    The System.IO.FileAttributes of the FileSystemEntity.

.Returns
    The type of the local file system entity.
#>
function Get-FileSystemEntityType
{
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileAttributes]
        $Attributes
    )

    if ($Attributes -match "Directory")
    {
        return "Folder";
    }
    else
    {
        return "File";
    }
}

if (Test-Path -LiteralPath $Path) {
    return Get-FileSystemEntityType -Attributes (Get-Item $Path).Attributes
} else {
    return ''
}

}
## [END] Get-WACVMItemType ##
function Get-WACVMLocalGroups {
<#

.SYNOPSIS
Gets the local groups.

.DESCRIPTION
Gets the local groups. The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction SilentlyContinue

$isWinServer2016OrNewer = [Environment]::OSVersion.Version.Major -ge 10;
# ADSI does NOT support 2016 Nano, meanwhile New-LocalUser, Get-LocalUser, Set-LocalUser do NOT support downlevel

    if ($isWinServer2016OrNewer)
    {
       return  Get-LocalGroup | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object Name
                                
    }
    else
    {
       return  Get-WmiObject -Class Win32_Group -Filter "LocalAccount='True'" | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object Name
    }


}
## [END] Get-WACVMLocalGroups ##
function Get-WACVMLocalUsers {
<#

.SYNOPSIS
Gets the local users.

.DESCRIPTION
Gets the local users. The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>


$isWinServer2016OrNewer = [Environment]::OSVersion.Version.Major -ge 10;

if ($isWinServer2016OrNewer){

	return Get-LocalUser | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object Name

}
else{
    return Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'" | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object  Name;
}
}
## [END] Get-WACVMLocalUsers ##
function Get-WACVMOSVersion {
<#

.SYNOPSIS
Get OS Version

.DESCRIPTION
Get OS Version

.ROLE
Readers

#>

$result = Get-WmiObject -Class Win32_OperatingSystem | Microsoft.PowerShell.Utility\Select-Object Version

return [version]$result.version -ge [version]"10.0.20348"

}
## [END] Get-WACVMOSVersion ##
function Get-WACVMRemoteAppIcon {
<#

.SYNOPSIS
Gets an embedded Icon from a selected executable file.

.DESCRIPTION
Gets an embedded Icon from a selected executable file by extracting it to a bitmap
and then converting it to a base64 string. This is useful for transferring the graphical
information as direct HTML data.

.ROLE
Readers

#>

Param(
    # [string]$fileName,
    [string]$selectedFilePath
)

Add-Type -AssemblyName System.Drawing
$Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($selectedFilePath)
$MemoryStream = New-Object System.IO.MemoryStream
$Icon.ToBitmap().Save($MemoryStream, [System.Drawing.Imaging.ImageFormat]::Png)
$Bytes = $MemoryStream.ToArray()   
$MemoryStream.Flush() 
$MemoryStream.Dispose()
[convert]::ToBase64String($Bytes)
}
## [END] Get-WACVMRemoteAppIcon ##
function Get-WACVMRemoteApplicationSettings {
<#

.SYNOPSIS
Gets the Remote App tool allow setting on the target node.

.DESCRIPTION
Gets the Remote App tool allow setting on the target node. If enabled, returns an object with the 'Available' state. Used in manifest
to dynamically enable/disable the Remote App tool from the inventory.

.ROLE
Readers

#>

$response = @{
    state = 'NotConfigured';
    message = 'Remote App tool is not enabled in settings';
}

$key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\TSAppAllowList'

$exists = Get-ItemProperty -Path $key -Name fDisabledAllowList -ErrorAction SilentlyContinue

if($exists.fDisabledAllowList) {
    $response.state = 'Available';
    $response.message = 'Remote App is enabled and ready';
}

$response

}
## [END] Get-WACVMRemoteApplicationSettings ##
function Get-WACVMRemoteDesktopAccountLockout {
<#

.SYNOPSIS
Gets the Remote Access lockout settings for the target node.

.DESCRIPTION
Gets the Remote Access lockout settings for the target node. Retrieves information on reset time
and max lockouts for the node. If a failure occurs, error message is returned.

.ROLE
Readers

#>

try {
    $accessSettings = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\AccountLockout" -ErrorAction Stop
} catch {
    return @{
        success = $false
        error = $_.Exception.Message
    }
}

return @{
    success = $true
    maxDenials = $accessSettings.MaxDenials
    resetTime = $accessSettings.'ResetTime (mins)'
}
}
## [END] Get-WACVMRemoteDesktopAccountLockout ##
function Get-WACVMRemoteDesktopCertificate {
<#

.SYNOPSIS
Gets the Remote Desktop certificate on the target node.

.DESCRIPTION
Gets the Remote Desktop certificate on the target node.

.ROLE
Readers

#>

$thumbprint = Get-CimInstance -Class " Win32_TSGeneralSetting " -Namespace root\cimv2\terminalservices | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty SSLCertificateSHA1Hash
$cert = Get-ChildItem -Path "Cert:\LocalMachine\*$thumbprint" -Recurse | Microsoft.PowerShell.Utility\Select-Object -First 1

$result = @{
    "FingerprintSha1" = $cert.Thumbprint;
    "Subject" = $cert.Subject;
    "Issuer" = $cert.Issuer;
    "ExtendedUsage" = $cert.EnhancedKeyUsageList.FriendlyName; # Not sure if this is everu an array
    "ValidFrom" = $cert.NotBefore;
    "ValidTo" = $cert.NotAfter;
}
 
return $result

}
## [END] Get-WACVMRemoteDesktopCertificate ##
function Get-WACVMRemoteDesktopSettings {
<#

.SYNOPSIS
Gets the Remote Desktop setting on the target node.

.DESCRIPTION
Gets the Remote Desktop setting on the target node.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0

Set-Variable -Option Constant -Name RdpSystemRegistryKey -Value "HKLM:\\SYSTEM\CurrentControlSet\Control\Terminal Server"
Set-Variable -Option Constant -Name RdpGroupPolicyProperty -Value "fDenyTSConnections" -ErrorAction SilentlyContinue
Set-Variable -Option Constant -Name RdpNlaGroupPolicyProperty -Value "UserAuthentication" -ErrorAction SilentlyContinue
Set-Variable -Option Constant -Name RdpGroupPolicyRegistryKey -Value "HKLM:\\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
Set-Variable -Option Constant -Name RdpListenerRegistryKey -Value "$RdpSystemRegistryKey\WinStations"
Set-Variable -Option Constant -Name RdpProtocolTypeUM -Value "{5828227c-20cf-4408-b73f-73ab70b8849f}"
Set-Variable -Option Constant -Name RdpProtocolTypeKM -Value "{18b726bb-6fe6-4fb9-9276-ed57ce7c7cb2}"
Set-Variable -Option Constant -Name RdpWdfSubDesktop -Value 0x00008000
Set-Variable -Option Constant -Name RdpFirewallGroup -Value "@FirewallAPI.dll,-28752"

<#

.SYNOPSIS
Gets the Remote Desktop Network Level Authentication settings of the current machine.

.DESCRIPTION
Gets the Remote Desktop Network Level Authentication settings of the system.

.ROLE
Readers

#>
function Get-RdpNlaGroupPolicySettings {
    $nlaGroupPolicySettings = @{}
    $nlaGroupPolicySettings.GroupPolicyIsSet = $false
    $nlaGroupPolicySettings.GroupPolicyIsEnabled = $false
    $registryKey = Get-ItemProperty -Path $RdpGroupPolicyRegistryKey -ErrorAction SilentlyContinue
    if (!!$registryKey) {
        if ((Get-Member -InputObject $registryKey -name $RdpNlaGroupPolicyProperty -MemberType Properties) -and ($null -ne $registryKey.$RdpNlaGroupPolicyProperty)) {
            $nlaGroupPolicySettings.GroupPolicyIsSet = $true
            $nlaGroupPolicySettings.GroupPolicyIsEnabled = $registryKey.$RdpNlaGroupPolicyProperty -eq 1
        }
    }

    return $nlaGroupPolicySettings
}

<#

.SYNOPSIS
Gets the Remote Desktop settings of the system related to Group Policy.

.DESCRIPTION
Gets the Remote Desktop settings of the system related to Group Policy.

.ROLE
Readers

#>
function Get-RdpGroupPolicySettings {
    $rdpGroupPolicySettings = @{}
    $rdpGroupPolicySettings.GroupPolicyIsSet = $false
    $rdpGroupPolicySettings.GroupPolicyIsEnabled = $false
    $registryKey = Get-ItemProperty -Path $RdpGroupPolicyRegistryKey -ErrorAction SilentlyContinue
    if (!!$registryKey) {
        if ((Get-Member -InputObject $registryKey -name $RdpGroupPolicyProperty -MemberType Properties) -and ($null -ne $registryKey.$RdpGroupPolicyProperty)) {
            $rdpGroupPolicySettings.groupPolicyIsSet = $true
            $rdpGroupPolicySettings.groupPolicyIsEnabled = $registryKey.$RdpGroupPolicyProperty -eq 0
        }
    }

    return $rdpGroupPolicySettings
}

<#

.SYNOPSIS
Gets all of the valid Remote Desktop Protocol listeners.

.DESCRIPTION
Gets all of the valid Remote Desktop Protocol listeners.

.ROLE
Readers

#>
function Get-RdpListener {
    $listeners = @()
    Get-ChildItem -Name $RdpListenerRegistryKey | Where-Object { $_.PSChildName.ToLower() -ne "console" } | ForEach-Object {
        $registryKeyValues = Get-ItemProperty -Path "$RdpListenerRegistryKey\$_" -ErrorAction SilentlyContinue
        if ($registryKeyValues -ne $null) {
            $protocol = $registryKeyValues.LoadableProtocol_Object
            $isProtocolRDP = ($protocol -ne $null) -and ($protocol -eq $RdpProtocolTypeUM -or $protocol -eq $RdpProtocolTypeKM)

            $wdFlag = $registryKeyValues.WdFlag
            $isSubDesktop = ($wdFlag -ne $null) -and ($wdFlag -band $RdpWdfSubDesktop)

            $isRDPListener = $isProtocolRDP -and !$isSubDesktop
            if ($isRDPListener) {
                $listeners += $registryKeyValues
            }
        }
    }

    return ,$listeners
}

<#

.SYNOPSIS
Gets the number of the ports that the Remote Desktop Protocol is operating over.

.DESCRIPTION
Gets the number of the ports that the Remote Desktop Protocol is operating over.


.ROLE
Readers

#>
function Get-RdpPortNumber {
    $portNumbers = @()
    Get-RdpListener | Where-Object { $_.PortNumber -ne $null } | ForEach-Object { $portNumbers += $_.PortNumber }
    return ,$portNumbers
}

<#

.SYNOPSIS
Gets the Remote Desktop settings of the system.

.DESCRIPTION
Gets the Remote Desktop settings of the system.

.ROLE
Readers

#>
function Get-RdpSettings {
    $remoteDesktopSettings = New-Object -TypeName PSObject
    $rdpEnabledSource = $null
    $rdpIsEnabled = Test-RdpEnabled
    $rdpRequiresNla = Test-RdpUserAuthentication
    $rdpPortNumbers = Get-RdpPortNumber
    if ($rdpIsEnabled) {
        $rdpGroupPolicySettings = Get-RdpGroupPolicySettings
        if ($rdpGroupPolicySettings.groupPolicyIsEnabled) {
            $rdpEnabledSource = "GroupPolicy"
        } else {
            $rdpEnabledSource = "System"
        }
    }

    $remoteDesktopSettings | Add-Member -MemberType NoteProperty -Name "IsEnabled" -Value $rdpIsEnabled
    $remoteDesktopSettings | Add-Member -MemberType NoteProperty -Name "RequiresNLA" -Value $rdpRequiresNla
    $remoteDesktopSettings | Add-Member -MemberType NoteProperty -Name "Ports" -Value $rdpPortNumbers
    $remoteDesktopSettings | Add-Member -MemberType NoteProperty -Name "EnabledSource" -Value $rdpEnabledSource

    return $remoteDesktopSettings
}

<#

.SYNOPSIS
Tests whether Remote Desktop Protocol is enabled.

.DESCRIPTION
Tests whether Remote Desktop Protocol is enabled.


.ROLE
Readers

#>
function Test-RdpEnabled {
    $rdpEnabledWithGP = $false
    $rdpEnabledLocally = $false
    $rdpGroupPolicySettings = Get-RdpGroupPolicySettings
    $rdpEnabledWithGP = $rdpGroupPolicySettings.GroupPolicyIsSet -and $rdpGroupPolicySettings.GroupPolicyIsEnabled
    $rdpEnabledLocally = !($rdpGroupPolicySettings.GroupPolicyIsSet) -and (Test-RdpSystem)

    return (Test-RdpListener) -and ($rdpEnabledWithGP -or $rdpEnabledLocally)
}

<#

.SYNOPSIS
Tests whether or not a Remote Desktop Protocol listener exists.

.DESCRIPTION
Tests whether or not a Remote Desktop Protocol listener exists.

.ROLE
Readers

#>
function Test-RdpListener {
    $listeners = Get-RdpListener
    return $listeners.Count -gt 0
}

<#

.SYNOPSIS
Tests whether Remote Desktop Protocol is enabled via local system settings.

.DESCRIPTION
Tests whether Remote Desktop Protocol is enabled via local system settings.

.ROLE
Readers

#>
function Test-RdpSystem {
    $registryKey = Get-ItemProperty -Path $RdpSystemRegistryKey -ErrorAction SilentlyContinue
    return $registryKey.fDenyTSConnections -eq 0
}

<#

.SYNOPSIS
Tests whether Remote Desktop connections require Network Level Authentication while enabled via local system settings.

.DESCRIPTION
Tests whether Remote Desktop connections require Network Level Authentication while enabled via local system settings.

.ROLE
Readers

#>
function Test-RdpSystemUserAuthentication {
    $listener = Get-RdpListener | Where-Object { $_.UserAuthentication -ne $null } | Microsoft.PowerShell.Utility\Select-Object -First 1
    return $listener.UserAuthentication -eq 1
}

<#

.SYNOPSIS
Tests whether Remote Desktop connections require Network Level Authentication.

.DESCRIPTION
Tests whether Remote Desktop connections require Network Level Authentication.

.ROLE
Readers

#>
function Test-RdpUserAuthentication {
    $nlaEnabledWithGP = $false
    $nlaEnabledLocally = $false
    $nlaGroupPolicySettings = Get-RdpNlaGroupPolicySettings
    $nlaEnabledWithGP = $nlaGroupPolicySettings.GroupPolicyIsSet -and $nlaGroupPolicySettings.GroupPolicyIsEnabled
    $nlaEnabledLocally = !($nlaGroupPolicySettings.GroupPolicyIsSet) -and (Test-RdpSystemUserAuthentication)

    return $nlaEnabledWithGP -or $nlaEnabledLocally
}

#########
# Main
#########

Get-RdpSettings

}
## [END] Get-WACVMRemoteDesktopSettings ##
function Get-WACVMServerInventory {
<#

.SYNOPSIS
Retrieves the inventory data for a server.

.DESCRIPTION
Retrieves the inventory data for a server.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0

Import-Module CimCmdlets

Import-Module Storage -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Converts an arbitrary version string into just 'Major.Minor'

.DESCRIPTION
To make OS version comparisons we only want to compare the major and
minor version.  Build number and/os CSD are not interesting.

#>

function convertOsVersion([string]$osVersion) {
  [Ref]$parsedVersion = $null
  if (![Version]::TryParse($osVersion, $parsedVersion)) {
    return $null
  }

  $version = [Version]$parsedVersion.Value
  return New-Object Version -ArgumentList $version.Major, $version.Minor
}

<#

.SYNOPSIS
Determines if CredSSP is enabled for the current server or client.

.DESCRIPTION
Check the registry value for the CredSSP enabled state.

#>

function isCredSSPEnabled() {
  Set-Variable credSSPServicePath -Option Constant -Value "WSMan:\localhost\Service\Auth\CredSSP"
  Set-Variable credSSPClientPath -Option Constant -Value "WSMan:\localhost\Client\Auth\CredSSP"

  $credSSPServerEnabled = $false;
  $credSSPClientEnabled = $false;

  $credSSPServerService = Get-Item $credSSPServicePath -ErrorAction SilentlyContinue
  if ($credSSPServerService) {
    $credSSPServerEnabled = [System.Convert]::ToBoolean($credSSPServerService.Value)
  }

  $credSSPClientService = Get-Item $credSSPClientPath -ErrorAction SilentlyContinue
  if ($credSSPClientService) {
    $credSSPClientEnabled = [System.Convert]::ToBoolean($credSSPClientService.Value)
  }

  return ($credSSPServerEnabled -or $credSSPClientEnabled)
}

<#

.SYNOPSIS
Determines if the Hyper-V role is installed for the current server or client.

.DESCRIPTION
The Hyper-V role is installed when the VMMS service is available.  This is much
faster then checking Get-WindowsFeature and works on Windows Client SKUs.

#>

function isHyperVRoleInstalled() {
  $vmmsService = Get-Service -Name "VMMS" -ErrorAction SilentlyContinue

  return $vmmsService -and $vmmsService.Name -eq "VMMS"
}

<#

.SYNOPSIS
Determines if the Hyper-V PowerShell support module is installed for the current server or client.

.DESCRIPTION
The Hyper-V PowerShell support module is installed when the modules cmdlets are available.  This is much
faster then checking Get-WindowsFeature and works on Windows Client SKUs.

#>
function isHyperVPowerShellSupportInstalled() {
  # quicker way to find the module existence. it doesn't load the module.
  return !!(Get-Module -ListAvailable Hyper-V -ErrorAction SilentlyContinue)
}

<#

.SYNOPSIS
Determines if Windows Management Framework (WMF) 5.0, or higher, is installed for the current server or client.

.DESCRIPTION
Windows Admin Center requires WMF 5 so check the registey for WMF version on Windows versions that are less than
Windows Server 2016.

#>
function isWMF5Installed([string] $operatingSystemVersion) {
  Set-Variable Server2016 -Option Constant -Value (New-Object Version '10.0')   # And Windows 10 client SKUs
  Set-Variable Server2012 -Option Constant -Value (New-Object Version '6.2')

  $version = convertOsVersion $operatingSystemVersion
  if (-not $version) {
    # Since the OS version string is not properly formatted we cannot know the true installed state.
    return $false
  }

  if ($version -ge $Server2016) {
    # It's okay to assume that 2016 and up comes with WMF 5 or higher installed
    return $true
  }
  else {
    if ($version -ge $Server2012) {
      # Windows 2012/2012R2 are supported as long as WMF 5 or higher is installed
      $registryKey = 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine'
      $registryKeyValue = Get-ItemProperty -Path $registryKey -Name PowerShellVersion -ErrorAction SilentlyContinue

      if ($registryKeyValue -and ($registryKeyValue.PowerShellVersion.Length -ne 0)) {
        $installedWmfVersion = [Version]$registryKeyValue.PowerShellVersion

        if ($installedWmfVersion -ge [Version]'5.0') {
          return $true
        }
      }
    }
  }

  return $false
}

<#

.SYNOPSIS
Determines if the current usser is a system administrator of the current server or client.

.DESCRIPTION
Determines if the current usser is a system administrator of the current server or client.

#>
function isUserAnAdministrator() {
  return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
}

<#

.SYNOPSIS
Get some basic information about the Failover Cluster that is running on this server.

.DESCRIPTION
Create a basic inventory of the Failover Cluster that may be running in this server.

#>
function getClusterInformation() {
  $returnValues = @{ }

  $returnValues.IsS2dEnabled = $false
  $returnValues.IsCluster = $false
  $returnValues.ClusterFqdn = $null
  $returnValues.IsBritannicaEnabled = $false

  $namespace = Get-CimInstance -Namespace root/MSCluster -ClassName __NAMESPACE -ErrorAction SilentlyContinue
  if ($namespace) {
    $cluster = Get-CimInstance -Namespace root/MSCluster -ClassName MSCluster_Cluster -ErrorAction SilentlyContinue
    if ($cluster) {
      $returnValues.IsCluster = $true
      $returnValues.ClusterFqdn = $cluster.Fqdn
      $returnValues.IsS2dEnabled = !!(Get-Member -InputObject $cluster -Name "S2DEnabled") -and ($cluster.S2DEnabled -gt 0)
      $returnValues.IsBritannicaEnabled = $null -ne (Get-CimInstance -Namespace root/sddc/management -ClassName SDDC_Cluster -ErrorAction SilentlyContinue)
    }
  }

  return $returnValues
}

<#

.SYNOPSIS
Get the Fully Qaulified Domain (DNS domain) Name (FQDN) of the passed in computer name.

.DESCRIPTION
Get the Fully Qaulified Domain (DNS domain) Name (FQDN) of the passed in computer name.

#>
function getComputerFqdnAndAddress($computerName) {
  $hostEntry = [System.Net.Dns]::GetHostEntry($computerName)
  $addressList = @()
  foreach ($item in $hostEntry.AddressList) {
    $address = New-Object PSObject
    $address | Add-Member -MemberType NoteProperty -Name 'IpAddress' -Value $item.ToString()
    $address | Add-Member -MemberType NoteProperty -Name 'AddressFamily' -Value $item.AddressFamily.ToString()
    $addressList += $address
  }

  $result = New-Object PSObject
  $result | Add-Member -MemberType NoteProperty -Name 'Fqdn' -Value $hostEntry.HostName
  $result | Add-Member -MemberType NoteProperty -Name 'AddressList' -Value $addressList
  return $result
}

<#

.SYNOPSIS
Get the Fully Qaulified Domain (DNS domain) Name (FQDN) of the current server or client.

.DESCRIPTION
Get the Fully Qaulified Domain (DNS domain) Name (FQDN) of the current server or client.

#>
function getHostFqdnAndAddress($computerSystem) {
  $computerName = $computerSystem.DNSHostName
  if (!$computerName) {
    $computerName = $computerSystem.Name
  }

  return getComputerFqdnAndAddress $computerName
}

<#

.SYNOPSIS
Are the needed management CIM interfaces available on the current server or client.

.DESCRIPTION
Check for the presence of the required server management CIM interfaces.

#>
function getManagementToolsSupportInformation() {
  $returnValues = @{ }

  $returnValues.ManagementToolsAvailable = $false
  $returnValues.ServerManagerAvailable = $false

  $namespaces = Get-CimInstance -Namespace root/microsoft/windows -ClassName __NAMESPACE -ErrorAction SilentlyContinue

  if ($namespaces) {
    $returnValues.ManagementToolsAvailable = !!($namespaces | Where-Object { $_.Name -ieq "ManagementTools" })
    $returnValues.ServerManagerAvailable = !!($namespaces | Where-Object { $_.Name -ieq "ServerManager" })
  }

  return $returnValues
}

<#

.SYNOPSIS
Check the remote app enabled or not.

.DESCRIPTION
Check the remote app enabled or not.

#>
function isRemoteAppEnabled() {
  Set-Variable key -Option Constant -Value "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\TSAppAllowList"

  $registryKeyValue = Get-ItemProperty -Path $key -Name fDisabledAllowList -ErrorAction SilentlyContinue

  if (-not $registryKeyValue) {
    return $false
  }
  return $registryKeyValue.fDisabledAllowList -eq 1
}

<#

.SYNOPSIS
Check the remote app enabled or not.

.DESCRIPTION
Check the remote app enabled or not.

#>

<#
c
.SYNOPSIS
Get the Win32_OperatingSystem information as well as current version information from the registry

.DESCRIPTION
Get the Win32_OperatingSystem instance and filter the results to just the required properties.
This filtering will make the response payload much smaller. Included in the results are current version
information from the registry

#>
function getOperatingSystemInfo() {
  $operatingSystemInfo = Get-CimInstance Win32_OperatingSystem | Microsoft.PowerShell.Utility\Select-Object csName, Caption, OperatingSystemSKU, Version, ProductType, OSType, LastBootUpTime
  $currentVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" | Microsoft.PowerShell.Utility\Select-Object CurrentBuild, UBR, DisplayVersion

  $operatingSystemInfo | Add-Member -MemberType NoteProperty -Name CurrentBuild -Value $currentVersion.CurrentBuild
  $operatingSystemInfo | Add-Member -MemberType NoteProperty -Name UpdateBuildRevision -Value $currentVersion.UBR
  $operatingSystemInfo | Add-Member -MemberType NoteProperty -Name DisplayVersion -Value $currentVersion.DisplayVersion

  return $operatingSystemInfo
}

<#

.SYNOPSIS
Get the Win32_ComputerSystem information

.DESCRIPTION
Get the Win32_ComputerSystem instance and filter the results to just the required properties.
This filtering will make the response payload much smaller.

#>
function getComputerSystemInfo() {
  return Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue | `
    Microsoft.PowerShell.Utility\Select-Object TotalPhysicalMemory, DomainRole, Manufacturer, Model, NumberOfLogicalProcessors, Domain, Workgroup, DNSHostName, Name, PartOfDomain, SystemFamily, SystemSKUNumber
}

<#

.SYNOPSIS
script to query SMBIOS locally from the passed in machineName


.DESCRIPTION
script to query SMBIOS locally from the passed in machine name
#>
function getSmbiosData($computerSystem) {
  <#
    Array of chassis types.
    The following list of ChassisTypes is copied from the latest DMTF SMBIOS specification.
    REF: https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.1.1.pdf
  #>
  $ChassisTypes =
  @{
    1  = 'Other'
    2  = 'Unknown'
    3  = 'Desktop'
    4  = 'Low Profile Desktop'
    5  = 'Pizza Box'
    6  = 'Mini Tower'
    7  = 'Tower'
    8  = 'Portable'
    9  = 'Laptop'
    10 = 'Notebook'
    11 = 'Hand Held'
    12 = 'Docking Station'
    13 = 'All in One'
    14 = 'Sub Notebook'
    15 = 'Space-Saving'
    16 = 'Lunch Box'
    17 = 'Main System Chassis'
    18 = 'Expansion Chassis'
    19 = 'SubChassis'
    20 = 'Bus Expansion Chassis'
    21 = 'Peripheral Chassis'
    22 = 'Storage Chassis'
    23 = 'Rack Mount Chassis'
    24 = 'Sealed-Case PC'
    25 = 'Multi-system chassis'
    26 = 'Compact PCI'
    27 = 'Advanced TCA'
    28 = 'Blade'
    29 = 'Blade Enclosure'
    30 = 'Tablet'
    31 = 'Convertible'
    32 = 'Detachable'
    33 = 'IoT Gateway'
    34 = 'Embedded PC'
    35 = 'Mini PC'
    36 = 'Stick PC'
  }

  $list = New-Object System.Collections.ArrayList
  $win32_Bios = Get-CimInstance -class Win32_Bios
  $obj = New-Object -Type PSObject | Microsoft.PowerShell.Utility\Select-Object SerialNumber, Manufacturer, UUID, BaseBoardProduct, ChassisTypes, Chassis, SystemFamily, SystemSKUNumber, SMBIOSAssetTag
  $obj.SerialNumber = $win32_Bios.SerialNumber
  $obj.Manufacturer = $win32_Bios.Manufacturer
  $computerSystemProduct = Get-CimInstance Win32_ComputerSystemProduct
  if ($null -ne $computerSystemProduct) {
    $obj.UUID = $computerSystemProduct.UUID
  }
  $baseboard = Get-CimInstance Win32_BaseBoard
  if ($null -ne $baseboard) {
    $obj.BaseBoardProduct = $baseboard.Product
  }
  $systemEnclosure = Get-CimInstance Win32_SystemEnclosure
  if ($null -ne $systemEnclosure) {
    $obj.SMBIOSAssetTag = $systemEnclosure.SMBIOSAssetTag
  }
  $obj.ChassisTypes = Get-CimInstance Win32_SystemEnclosure | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty ChassisTypes
  $obj.Chassis = New-Object -TypeName 'System.Collections.ArrayList'
  $obj.ChassisTypes | ForEach-Object -Process {
    $obj.Chassis.Add($ChassisTypes[[int]$_])
  }
  $obj.SystemFamily = $computerSystem.SystemFamily
  $obj.SystemSKUNumber = $computerSystem.SystemSKUNumber
  $list.Add($obj) | Out-Null

  return $list

}
###########################################################################
# main()
###########################################################################

$operatingSystem = getOperatingSystemInfo
$computerSystem = getComputerSystemInfo
$isAdministrator = isUserAnAdministrator
$fqdnAndAddress = getHostFqdnAndAddress $computerSystem
$hostname = [Environment]::MachineName
$netbios = $env:ComputerName
$managementToolsInformation = getManagementToolsSupportInformation
$isWmfInstalled = isWMF5Installed $operatingSystem.Version
$clusterInformation = getClusterInformation -ErrorAction SilentlyContinue
$isHyperVPowershellInstalled = isHyperVPowerShellSupportInstalled
$isHyperVRoleInstalled = isHyperVRoleInstalled
$isCredSSPEnabled = isCredSSPEnabled
$isRemoteAppEnabled = isRemoteAppEnabled
$smbiosData = getSmbiosData $computerSystem

$result = New-Object PSObject
$result | Add-Member -MemberType NoteProperty -Name 'IsAdministrator' -Value $isAdministrator
$result | Add-Member -MemberType NoteProperty -Name 'OperatingSystem' -Value $operatingSystem
$result | Add-Member -MemberType NoteProperty -Name 'ComputerSystem' -Value $computerSystem
$result | Add-Member -MemberType NoteProperty -Name 'Fqdn' -Value $fqdnAndAddress.Fqdn
$result | Add-Member -MemberType NoteProperty -Name 'AddressList' -Value $fqdnAndAddress.AddressList
$result | Add-Member -MemberType NoteProperty -Name 'Hostname' -Value $hostname
$result | Add-Member -MemberType NoteProperty -Name 'NetBios' -Value $netbios
$result | Add-Member -MemberType NoteProperty -Name 'IsManagementToolsAvailable' -Value $managementToolsInformation.ManagementToolsAvailable
$result | Add-Member -MemberType NoteProperty -Name 'IsServerManagerAvailable' -Value $managementToolsInformation.ServerManagerAvailable
$result | Add-Member -MemberType NoteProperty -Name 'IsWmfInstalled' -Value $isWmfInstalled
$result | Add-Member -MemberType NoteProperty -Name 'IsCluster' -Value $clusterInformation.IsCluster
$result | Add-Member -MemberType NoteProperty -Name 'ClusterFqdn' -Value $clusterInformation.ClusterFqdn
$result | Add-Member -MemberType NoteProperty -Name 'IsS2dEnabled' -Value $clusterInformation.IsS2dEnabled
$result | Add-Member -MemberType NoteProperty -Name 'IsBritannicaEnabled' -Value $clusterInformation.IsBritannicaEnabled
$result | Add-Member -MemberType NoteProperty -Name 'IsHyperVRoleInstalled' -Value $isHyperVRoleInstalled
$result | Add-Member -MemberType NoteProperty -Name 'IsHyperVPowershellInstalled' -Value $isHyperVPowershellInstalled
$result | Add-Member -MemberType NoteProperty -Name 'IsCredSSPEnabled' -Value $isCredSSPEnabled
$result | Add-Member -MemberType NoteProperty -Name 'IsRemoteAppEnabled' -Value $isRemoteAppEnabled
$result | Add-Member -MemberType NoteProperty -Name 'SmbiosData' -Value $smbiosData

$result

}
## [END] Get-WACVMServerInventory ##
function Get-WACVMShareEntities {
<#

.SYNOPSIS
Enumerates all of the file system entities (files, folders, volumes) of the system.

.DESCRIPTION
Enumerates all of the file system entities (files, folders, volumes) of the system on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER Path
    String -- The path to enumerate.

.PARAMETER OnlyFiles
    switch --

.PARAMETER OnlyFolders
    switch --

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $ComputerName
)

Set-StrictMode -Version 5.0

<#
.Synopsis
    Name: Get-FileSystemEntities
    Description: Gets all the local file system entities of the machine.

.Parameter Path
    String -- The path to enumerate.

.Returns
    The local file system entities.
#>
function Get-FileSystemEntities {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $ComputerName
    )

    return Invoke-Command -ComputerName $ComputerName -ScriptBlock { get-smbshare | Where-Object { -not ($_.name.EndsWith('$')) } } |
    Microsoft.PowerShell.Utility\Select-Object @{Name = "Caption"; Expression = { "\\" + $_.PSComputerName + "\" + $_.Name } },
    @{Name = "CreationDate"; Expression = { $_.CreationTimeUtc } },
    Extension,
    @{Name = "IsHidden"; Expression = { [bool]$false } },
    @{Name = "IsShared"; Expression = { [bool]$true } },
    Name,
    @{Name = "Type"; Expression = { "FileShare" } },
    @{Name = "LastModifiedDate"; Expression = { $_.LastWriteTimeUtc } },
    @{Name = "Size"; Expression = { if ($_.PSIsContainer) { $null } else { $_.Length } } };
}

$entities = Get-FileSystemEntities -ComputerName $ComputerName;

return $entities;

}
## [END] Get-WACVMShareEntities ##
function Get-WACVMSmb1InstallationStatus {
<#

.SYNOPSIS
Get SMB1 installation status.

.DESCRIPTION
Get SMB1 installation status.

.ROLE
Readers

#>

Import-Module DISM

$Enabled = [bool]( Get-WindowsOptionalFeature -online -featurename SMB1Protocol | Where-Object State -eq "Enabled")
@{ isEnabled = $Enabled }

}
## [END] Get-WACVMSmb1InstallationStatus ##
function Get-WACVMSmbFileShareDetails {
<#

.SYNOPSIS
Enumerates all of the smb local file shares of the system.

.DESCRIPTION
Enumerates all of the smb local file shares of the system.

.ROLE
Readers

#>

<#
.Synopsis
    Name: Get-SmbFileShareDetails
    Description: Retrieves the SMB shares on the computer.
.Returns
    The local smb file share(s).
#>

$shares = Get-SmbShare -includehidden | Where-Object {-not ($_.Name -eq "IPC$")} | Microsoft.PowerShell.Utility\Select-Object Name, Path, CachingMode, EncryptData, CurrentUsers, Special, LeasingMode, FolderEnumerationMode, CompressData

$uncPath = (Get-CimInstance Win32_ComputerSystem).DNSHostName + "." + (Get-CimInstance Win32_ComputerSystem).Domain

return @{
    shares = $shares;
    uncPath = $uncPath
}
   
}
## [END] Get-WACVMSmbFileShareDetails ##
function Get-WACVMSmbOverQuicSettings {
<#

.SYNOPSIS
Retrieves smb over QUIC settings from the server.

.DESCRIPTION
Returns smb over QUIC settings and server dns name

.ROLE
Readers

#>

Import-Module SmbShare

$serverConfigurationSettings = Get-SmbServerConfiguration | Microsoft.PowerShell.Utility\Select-Object DisableSmbEncryptionOnSecureConnection, RestrictNamedpipeAccessViaQuic

return @{
    serverConfigurationSettings = $serverConfigurationSettings
}

}
## [END] Get-WACVMSmbOverQuicSettings ##
function Get-WACVMSmbServerCertificateHealth {
<#

.SYNOPSIS
Retrieves health of the current certificate for smb over QUIC.

.DESCRIPTION
Retrieves health of the current certificate for smb over QUIC based on if the certificate is self signed or not.

.ROLE
Readers

#>

param (
  [Parameter(Mandatory = $true)]
  [String]
  $thumbprint,
  [Parameter(Mandatory = $true)]
  [boolean]
  $isSelfSigned,
  [Parameter(Mandatory = $true)]
  [boolean]
  $fromTaskScheduler,
  [Parameter(Mandatory = $false)]
  [String]
  $ResultFile,
  [Parameter(Mandatory = $false)]
  [String]
  $WarningsFile,
  [Parameter(Mandatory = $false)]
  [String]
  $ErrorFile
)

Set-StrictMode -Version 5.0



function getSmbServerCertificateHealth() {
  param (
    [String]
    $thumbprint,
    [boolean]
    $isSelfSigned,
    [String]
    $ResultFile,
    [String]
    $WarningsFile,
    [String]
    $ErrorFile
  )

  # create local runspace
  $ps = [PowerShell]::Create()
  # define input data but make it completed
  $inData = New-Object -Typename  System.Management.Automation.PSDataCollection[PSObject]
  $inData.Complete()
  # define output data to receive output
  $outData = New-Object -Typename  System.Management.Automation.PSDataCollection[PSObject]
  # register the script
  if ($isSelfSigned) {
    $ps.Commands.AddScript("Get-Item -Path " + $thumbprint + "| Test-Certificate -AllowUntrustedRoot") | Out-Null
  }
  else {
    $ps.Commands.AddScript("Get-Item -Path " + $thumbprint + "| Test-Certificate") | Out-Null
  }
  # execute async way.
  $async = $ps.BeginInvoke($inData, $outData)
  # wait for completion (callback will be called if any)
  $ps.EndInvoke($async)
  Start-Sleep -MilliSeconds 10
  # read output
  if ($outData.Count -gt 0) {
    @{ Output = $outData[0]; } | ConvertTo-Json | Out-File -FilePath $ResultFile
  }
  # read warnings
  if ($ps.Streams.Warning.Count -gt 0) {
    $ps.Streams.Warning | % { $_.ToString() } | Out-File -FilePath $WarningsFile
  }
  # read errors
  if ($ps.HadErrors) {
    $ps.Streams.Error | % { $_.ToString() } | Out-File -FilePath $ErrorFile
  }
}

#---- Script execution starts here ----
$isWdacEnforced = $ExecutionContext.SessionState.LanguageMode -eq 'ConstrainedLanguage';

#In WDAC environment script file will already be available on the machine
#In WDAC mode the same script is executed - once normally and once through task Scheduler
if ($isWdacEnforced) {
  if ($fromTaskScheduler) {
    getSmbServerCertificateHealth $thumbprint $isSelfSigned $ResultFile $WarningsFile $ErrorFile;
    return;
  }
}
else {
  #In non-WDAC environment script file will not be available on the machine
  #Hence, a dynamic script is created which is executed through the task Scheduler
  $ScriptFile = $env:temp + "\smbOverQuic-certificateHealth.ps1"
}

$thumbprint = Join-Path "Cert:\LocalMachine\My" $thumbprint

# Pass parameters tpt and generate script file in temp folder
$ResultFile = $env:temp + "\smbOverQuic-certificateHealth_result.txt"
$WarningsFile = $env:temp + "\smbOverQuic-certificateHealth_warnings.txt"
$ErrorFile = $env:temp + "\smbOverQuic-certificateHealth_error.txt"
if (Test-Path $ErrorFile) {
  Remove-Item $ErrorFile
}

if (Test-Path $ResultFile) {
  Remove-Item $ResultFile
}

if (Test-Path $WarningsFile) {
  Remove-Item $WarningsFile
}
$isSelfSignedtemp = if ($isSelfSigned) { "`$true" } else { "`$false" }

if ($isWdacEnforced) {
  $arg = "-NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -command ""&{Import-Module Microsoft.SME.FileExplorer; Get-WACFESmbServerCertificateHealth -fromTaskScheduler `$true -thumbprint $thumbprint -isSelfSigned $isSelfSignedtemp -ResultFile $ResultFile -WarningsFile $WarningsFile -ErrorFile $ErrorFile }"""
}
else {
  (Get-Command getSmbServerCertificateHealth).ScriptBlock | Set-Content -path $ScriptFile
  $arg = "-NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -command ""&{Set-Location -Path $env:temp; .\smbOverQuic-certificateHealth.ps1 -thumbprint $thumbprint -isSelfSigned $isSelfSignedtemp -ResultFile $ResultFile -WarningsFile $WarningsFile -ErrorFile $ErrorFile }"""
}

# Create a scheduled task
$TaskName = "SMESmbOverQuicCertificate"
$User = [Security.Principal.WindowsIdentity]::GetCurrent()
$Role = (New-Object Security.Principal.WindowsPrincipal $User).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (!$Role) {
  Write-Warning "To perform some operations you must run an elevated Windows PowerShell console."
}

$Scheduler = New-Object -ComObject Schedule.Service
#Try to connect to schedule service 3 time since it may fail the first time
for ($i = 1; $i -le 3; $i++) {
  Try {
    $Scheduler.Connect()
    Break
  }
  Catch {
    if ($i -ge 3) {
      writeErrorLog "Can't connect to Schedule service"
      throw "Can't connect to Schedule service"
    }
    else {
      Start-Sleep -s 1
    }
  }
}

$RootFolder = $Scheduler.GetFolder("\")

#Delete existing task
if ($RootFolder.GetTasks(0) | Where-Object { $_.Name -eq $TaskName }) {
  Write-Debug("Deleting existing task" + $TaskName)
  try {
    $RootFolder.DeleteTask($TaskName, 0)
  }
  catch {

  }
}

$Task = $Scheduler.NewTask(0)
$RegistrationInfo = $Task.RegistrationInfo
$RegistrationInfo.Description = $TaskName
$RegistrationInfo.Author = $User.Name

$Triggers = $Task.Triggers
$Trigger = $Triggers.Create(7) #TASK_TRIGGER_REGISTRATION: Starts the task when the task is registered.
$Trigger.Enabled = $true

$Settings = $Task.Settings
$Settings.Enabled = $True
$Settings.StartWhenAvailable = $True
$Settings.Hidden = $False

$Action = $Task.Actions.Create(0)
$Action.Path = "powershell"
$Action.Arguments = $arg

#Tasks will be run with the highest privileges
$Task.Principal.RunLevel = 1

#### example Start the task with user specified invoke username and password
####$Task.Principal.LogonType = 1
####$RootFolder.RegisterTaskDefinition($TaskName, $Task, 6, $invokeUserName, $invokePassword, 1) | Out-Null

#### Start the task with SYSTEM creds
$RootFolder.RegisterTaskDefinition($TaskName, $Task, 6, "SYSTEM", $Null, 1) | Out-Null
#Wait for running task finished
$RootFolder.GetTask($TaskName).Run(0) | Out-Null
while ($RootFolder.GetTask($TaskName).State -ne 4) {
  Start-Sleep -MilliSeconds 10
}
while ($Scheduler.GetRunningTasks(0) | Where-Object { $_.Name -eq $TaskName }) {
  Start-Sleep -Seconds 1
}

#Clean up
try {
  $RootFolder.DeleteTask($TaskName, 0)
}
catch {

}
if (!$isWdacEnforced) {
  Remove-Item $ScriptFile
}

#Return result
if (Test-Path $ResultFile) {
  $result = Get-Content -Raw -Path $ResultFile | ConvertFrom-Json
  Remove-Item $ResultFile
  if ($result.Output) {
    return $result.Output;
  }
  else {
    if (Test-Path $WarningsFile) {
      $result = Get-Content -Path $WarningsFile
      Remove-Item $WarningsFile
    }
    if (Test-Path $ErrorFile) {
      Remove-Item $ErrorFile
    }
  }
  return $result;
}
else {
  if (Test-Path $ErrorFile) {
    $result = Get-Content -Path $ErrorFile
    Remove-Item $ErrorFile
    throw $result
  }
}

}
## [END] Get-WACVMSmbServerCertificateHealth ##
function Get-WACVMSmbServerCertificateMapping {
<#

.SYNOPSIS
Retrieves the current certifcate installed for smb over QUIC and smboverQuic status on the server.

.DESCRIPTION
Retrieves the current certifcate installed for smb over QUIC and smboverQuic status on the server.

.ROLE
Readers

#>

Import-Module SmbShare

$certHash = $null;
$kdcPort = $null;

function Retrieve-WACPort {
  $details = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManagementGateway -ErrorAction SilentlyContinue
  if ($details) {
    $smePort = $details | Microsoft.PowerShell.Utility\Select-Object SmePort;
    return $smePort.smePort -eq 443
  }
  else {
    return $false;
  }
}

# retrieving smbcertificate mappings, if any
$smbCertificateMapping = @(Get-SmbServerCertificateMapping | Microsoft.PowerShell.Utility\Select-Object Thumbprint, Name)

# determining if WAC is installed on port 443
$isWacOnPort443 = Retrieve-WACPort;

# retrieving if smbOverQuic is enable on the server
$isSmbOverQuicEnabled = Get-SmbServerConfiguration | Microsoft.PowerShell.Utility\Select-Object EnableSMBQUIC

try {
  # retrieving kdc Proxy status on the server
  $kdcUrl = netsh http show urlacl | findstr /i "KdcProxy"
  if ($kdcUrl) {
    $pos = $kdcUrl.IndexOf("+")
    $rightPart = $kdcUrl.Substring($pos + 1)
    $pos1 = $rightPart.IndexOf("/")
    $kdcPort = $rightPart.SubString(1, $pos1 - 1)
  }

  [array]$path = Get-Item  -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" -ErrorAction SilentlyContinue

  [array]$clientAuthproperty = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" -Name "HttpsClientAuth" -ErrorAction SilentlyContinue

  [array]$passwordAuthproperty = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" -Name "DisallowUnprotectedPasswordAuth" -ErrorAction SilentlyContinue

  $status = Get-Service -Name kpssvc | Microsoft.PowerShell.Utility\Select-Object Status

  if ($null -ne $kdcPort) {
    $port = "0.0.0.0:"
    $ipport = $port + $kdcPort
    $certBinding = @(netsh http show sslcert ipport=$ipport | findstr "Hash")
    if ($null -ne $certBinding -and $certBinding.count -gt 0) {
      $index = $certBinding[0].IndexOf(":")
      $certHash = $certBinding[0].Substring($index + 1).trim()
    }
  }

  $isKdcProxyMappedForSmbOverQuic = $false;
  $moreThanOneCertMapping = $false;

  if (($null -ne $certHash) -and ($null -ne $smbCertificateMapping) -and ($smbCertificateMapping.count -eq 1)) {
    $isKdcProxyMappedForSmbOverQuic = $smbCertificateMapping.thumbprint -eq $certHash
  }
  elseif ($null -ne $smbCertificateMapping -and $smbCertificateMapping.count -gt 1) {
    $set = New-Object System.Collections.Generic.HashSet[string]
    foreach ($mapping in $smbCertificateMapping) {
      # Adding Out null as set.Add always returns true/false and we do not want that.
      $set.Add($smbCertificateMapping.thumbprint) | Out-Null;
    }
    if ($set.Count -gt 1) {
      $moreThanOneCertMapping = $true;
    }
    if (!$moreThanOneCertMapping -and $null -ne $certHash) {
      $isKdcProxyMappedForSmbOverQuic = $smbCertificateMapping[0].thumbprint -eq $certHash
    }
  }
}
catch {
  throw $_
}

return @{
  smbCertificateMapping          = $smbCertificateMapping
  isSmbOverQuicEnabled           = $isSmbOverQuicEnabled
  isKdcProxyMappedForSmbOverQuic = $isKdcProxyMappedForSmbOverQuic
  kdcPort                        = $kdcPort
  isKdcProxyEnabled              = $kdcPort -and ($null -ne $path -and $path.count -gt 0) -and ($null -ne $clientAuthproperty -and $clientAuthproperty.count -gt 0) -and ($null -ne $passwordAuthproperty -and $passwordAuthproperty.count -gt 0) -and $status.status -eq "Running"
  isWacOnPort443                 = $isWacOnPort443;
}

}
## [END] Get-WACVMSmbServerCertificateMapping ##
function Get-WACVMSmbServerCertificateValues {
<#

.SYNOPSIS
Retrieves other values based on the installed certifcate for smb over QUIC.

.DESCRIPTION
Retrieves other values based on the installed certifcate for smb over QUIC.

.ROLE 
Readers

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $thumbprint
)

Set-Location Cert:\LocalMachine\My

[array] $smbServerDnsNames = Get-SmbServerCertificateMapping | Where-Object { $_.Thumbprint -eq $thumbprint } | Microsoft.PowerShell.Utility\Select-Object Name

$smbCertificateValues = Get-ChildItem -Recurse | Where-Object { $_.Thumbprint -eq $thumbprint } | Microsoft.PowerShell.Utility\Select-Object Subject, Thumbprint, Issuer, NotBefore, NotAfter

return @{ 
    smbServerDnsNames = $smbServerDnsNames
    smbCertificateValues = $smbCertificateValues
}

}
## [END] Get-WACVMSmbServerCertificateValues ##
function Get-WACVMSmbServerSettings {

<#

.SYNOPSIS
Enumerates the SMB server configuration settings on the computer.

.DESCRIPTION
Enumerates  the SMB server configuration settings on the computer.

.ROLE
Readers

#>

<#
.Synopsis
    Name: Get-SmbServerConfiguration
    Description: Retrieves the SMB server configuration settings on the computer.
.Returns
    SMB server configuration settings
#>

Import-Module SmbShare

$settings = Get-SmbServerConfiguration | Microsoft.PowerShell.Utility\Select-Object RequireSecuritySignature,RejectUnencryptedAccess,AuditSmb1Access,EncryptData
$compressionSettings = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\parameters" -Name "DisableCompression" -ErrorAction SilentlyContinue

@{ settings = $settings
    compressionSettings = $compressionSettings }

}
## [END] Get-WACVMSmbServerSettings ##
function Get-WACVMSmbShareAccess {
<#

.SYNOPSIS
Enumerates the SMB server access rights and details on the server.

.DESCRIPTION
Enumerates the SMB server access rights and details on the server.

.ROLE
Readers

#>

<#
.Synopsis
    Name: Get-SmbShareAccess
    Description: Retrieves the SMB server access rights and details on the server.
.Returns
    Retrieves the SMB server access rights and details on the server.
#>
param (
    [Parameter(Mandatory = $true)]
    [String]
    $Name
)

[array]$shareAccess = Get-SmbShareAccess -Name "$Name" | Microsoft.PowerShell.Utility\Select-Object AccountName, AccessRight, AccessControlType

$details = Get-SmbShare -Name "$Name" | Microsoft.PowerShell.Utility\Select-Object CachingMode, EncryptData, FolderEnumerationMode, CompressData

return @{ 
    details = $details
    shareAccess = $shareAccess
  }   
}
## [END] Get-WACVMSmbShareAccess ##
function Get-WACVMStorageFileShare {
<#

.SYNOPSIS
Enumerates all of the local file shares of the system.

.DESCRIPTION
Enumerates all of the local file shares of the system.

.ROLE
Readers

.PARAMETER FileShareId
    The file share ID.
#>
param (
    [Parameter(Mandatory = $false)]
    [String]
    $FileShareId
)

Import-Module CimCmdlets

<#
.Synopsis
    Name: Get-FileShares-Internal
    Description: Gets all the local file shares of the machine.

.Parameters
    $FileShareId: The unique identifier of the file share desired (Optional - for cases where only one file share is desired).

.Returns
    The local file share(s).
#>
function Get-FileSharesInternal
{
    param (
        [Parameter(Mandatory = $false)]
        [String]
        $FileShareId
    )

    Remove-Module Storage -ErrorAction Ignore; # Remove the Storage module to prevent it from automatically localizing

    $isDownlevel = [Environment]::OSVersion.Version.Major -lt 10;
    if ($isDownlevel)
    {
        # Map downlevel status to array of [health status, operational status, share state] uplevel equivalent
        $statusMap = @{
            "OK" =         @(0, 2, 1);
            "Error" =      @(2, 6, 2);
            "Degraded" =   @(1, 3, 2);
            "Unknown" =    @(5, 0, 0);
            "Pred Fail" =  @(1, 5, 2);
            "Starting" =   @(1, 8, 0);
            "Stopping" =   @(1, 9, 0);
            "Service" =    @(1, 11, 1);
            "Stressed" =   @(1, 4, 1);
            "NonRecover" = @(2, 7, 2);
            "No Contact" = @(2, 12, 2);
            "Lost Comm" =  @(2, 13, 2);
        };
        
        $shares = Get-CimInstance -ClassName Win32_Share |
            ForEach-Object {
                return @{
                    ContinuouslyAvailable = $false;
                    Description = $_.Description;
                    EncryptData = $false;
                    FileSharingProtocol = 3;
                    HealthStatus = $statusMap[$_.Status][0];
                    IsHidden = $_.Name.EndsWith("`$");
                    Name = $_.Name;
                    OperationalStatus = ,@($statusMap[$_.Status][1]);
                    ShareState = $statusMap[$_.Status][2];
                    UniqueId = "smb|" + (Get-CimInstance Win32_ComputerSystem).DNSHostName + "." + (Get-CimInstance Win32_ComputerSystem).Domain + "\" + $_.Name;
                    VolumePath = $_.Path;
                }
            }
    }
    else
    {        
        $shares = Get-CimInstance -ClassName MSFT_FileShare -Namespace Root\Microsoft\Windows/Storage |
            ForEach-Object {
                return @{
                    IsHidden = $_.Name.EndsWith("`$");
                    VolumePath = $_.VolumeRelativePath;
                    ContinuouslyAvailable = $_.ContinuouslyAvailable;
                    Description = $_.Description;
                    EncryptData = $_.EncryptData;
                    FileSharingProtocol = $_.FileSharingProtocol;
                    HealthStatus = $_.HealthStatus;
                    Name = $_.Name;
                    OperationalStatus = $_.OperationalStatus;
                    UniqueId = $_.UniqueId;
                    ShareState = $_.ShareState;
                }
            }
    }

    if ($FileShareId)
    {
        $shares = $shares | Where-Object { $_.UniqueId -eq $FileShareId };
    }

    return $shares;
}

if ($FileShareId)
{
    Get-FileSharesInternal -FileShareId $FileShareId;
}
else
{
    Get-FileSharesInternal;
}

}
## [END] Get-WACVMStorageFileShare ##
function Get-WACVMTempFolderPath {
<#

.SYNOPSIS
Gets the temporary folder (%temp%) for the user.

.DESCRIPTION
Gets the temporary folder (%temp%) for the user.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

#>

Set-StrictMode -Version 5.0

return $env:TEMP

}
## [END] Get-WACVMTempFolderPath ##
function Move-WACVMFile {
<#

.SYNOPSIS
Moves or Copies a file or folder

.DESCRIPTION
Moves or Copies a file or folder from the source location to the destination location
Folders will be copied recursively

.ROLE
Administrators

.PARAMETER Path
    String -- the path to the source file/folder to copy

.PARAMETER Destination
    String -- the path to the new location

.PARAMETER Copy
    boolean -- Determine action to be performed

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $path,

    [Parameter(Mandatory = $true)]
    [String]
    $destination,

    [Parameter(Mandatory = $true)]
    [boolean]
    $copy,

    [Parameter(Mandatory = $true)]
    [string]
    $entityType,

    [Parameter(Mandatory = $false)]
    [string]
    $existingPath
)

Set-StrictMode -Version 5.0

if($copy){
  $result = Copy-Item -Path $path -Destination $destination -Recurse -Force -PassThru -ErrorAction SilentlyContinue
  if(!$result){
    return $Error[0].Exception.Message
  }
} else {
  if ($entityType -eq "File" -Or  !$existingPath) {
    $result = Move-Item -Path $path -Destination $destination -Force -PassThru -ErrorAction SilentlyContinue
    if(!$result){
      return $Error[0].Exception.Message
    }
  }
  else {
    # Move-Item -Force doesn't work when replacing folders, remove destination folder before replacing
    Remove-Item -Path $existingPath -Confirm:$false -Force -Recurse
    $forceResult = Move-Item -Path $path -Destination $destination -Force -PassThru -ErrorAction SilentlyContinue
    if (!$forceResult) {
      return $Error[0].Exception.Message
    }
  }
}

}
## [END] Move-WACVMFile ##
function New-WACVMFile {
<#

.SYNOPSIS
Create a new file.

.DESCRIPTION
Create a new file on this server. If the file already exists, it will be overwritten.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER Path
    String -- the path to the parent of the new file.

.PARAMETER NewName
    String -- the file name.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path,

    [Parameter(Mandatory = $true)]
    [String]
    $NewName
)

Set-StrictMode -Version 5.0

$newItem = New-Item -ItemType File -Path (Join-Path -Path $Path -ChildPath $NewName) -Force

return $newItem |
    Microsoft.PowerShell.Utility\Select-Object @{Name = "Caption"; Expression = { $_.FullName } },
                  @{Name = "CreationDate"; Expression = { $_.CreationTimeUtc } },
                  Extension,
                  @{Name = "IsHidden"; Expression = { $_.Attributes -match "Hidden" } },
                  @{Name = "IsShared"; Expression = { [bool]($folderShares | Where-Object Path -eq $_.FullName) } },
                  Name,
                  @{Name = "Type"; Expression = { Get-FileSystemEntityType -Attributes $_.Attributes } },
                  @{Name = "LastModifiedDate"; Expression = { $_.LastWriteTimeUtc } },
                  @{Name = "Size"; Expression = { if ($_.PSIsContainer) { $null } else { $_.Length } } };

}
## [END] New-WACVMFile ##
function New-WACVMFolder {
<#

.SYNOPSIS
Create a new folder.

.DESCRIPTION
Create a new folder on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER Path
    String -- the path to the parent of the new folder.

.PARAMETER NewName
    String -- the folder name.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path,

    [Parameter(Mandatory = $true)]
    [String]
    $NewName
)

Set-StrictMode -Version 5.0

$pathSeparator = [System.IO.Path]::DirectorySeparatorChar;
$newItem = New-Item -ItemType Directory -Path ($Path.TrimEnd($pathSeparator) + $pathSeparator + $NewName)

return $newItem |
    Microsoft.PowerShell.Utility\Select-Object @{Name="Caption"; Expression={$_.FullName}},
                  @{Name="CreationDate"; Expression={$_.CreationTimeUtc}},
                  Extension,
                  @{Name="IsHidden"; Expression={$_.Attributes -match "Hidden"}},
                  Name,
                  @{Name="Type"; Expression={Get-FileSystemEntityType -Attributes $_.Attributes}},
                  @{Name="LastModifiedDate"; Expression={$_.LastWriteTimeUtc}},
                  @{Name="Size"; Expression={if ($_.PSIsContainer) { $null } else { $_.Length }}};

}
## [END] New-WACVMFolder ##
function New-WACVMSmbFileShare {
<#

.SYNOPSIS
Gets the SMB file share  details on the server.

.DESCRIPTION
Gets the SMB file share  details on the server.

.ROLE
Administrators

#>

<#
.Synopsis
    Name: New-SmbFileShare
    Description: Gets the SMB file share  details on the server.
.Returns
    Retrieves all the SMB file share  details on the server.
#>


param (
    [Parameter(Mandatory = $true)]
    [String]
    $path,    

    [Parameter(Mandatory = $true)]
    [String]
    $name,

    [Parameter(Mandatory = $false)]
    [String[]]
    $fullAccess,

    [Parameter(Mandatory = $false)]
    [String[]]
    $changeAccess,

    [Parameter(Mandatory = $false)]
    [String[]]
    $readAccess,

    [Parameter(Mandatory = $false)]
    [String[]]
    $noAccess,

    [Parameter(Mandatory = $false)]
    [Int]
    $cachingMode,

    [Parameter(Mandatory = $false)]
    [boolean]
    $encryptData,

    # TODO:
    # [Parameter(Mandatory = $false)]
    # [Int]
    # $FolderEnumerationMode

    [Parameter(Mandatory = $false)]
    [boolean]
    $compressData,

    [Parameter(Mandatory = $false)]
    [boolean]
    $isCompressDataEnabled
)

$HashArguments = @{
  Name = "$name"
}

if($fullAccess.count -gt 0){
    $HashArguments.Add("FullAccess", $fullAccess)
}
if($changeAccess.count -gt 0){
    $HashArguments.Add("ChangeAccess", $changeAccess)
}
if($readAccess.count -gt 0){
    $HashArguments.Add("ReadAccess", $readAccess)
}
if($noAccess.count -gt 0){
    $HashArguments.Add("NoAccess", $noAccess)
}
if($cachingMode){
     $HashArguments.Add("CachingMode", "$cachingMode")
}
if($encryptData -ne $null){
    $HashArguments.Add("EncryptData", $encryptData)
}
# TODO: if($FolderEnumerationMode -eq 0){
#     $HashArguments.Add("FolderEnumerationMode", "AccessBased")
# } else {
#     $HashArguments.Add("FolderEnumerationMode", "Unrestricted")
# }
if($isCompressDataEnabled){
    $HashArguments.Add("CompressData", $compressData)
}

New-SmbShare -Path "$path" @HashArguments
@{ shareName = $name } 

}
## [END] New-WACVMSmbFileShare ##
function Remove-WACVMAllShareNames {
<#

.SYNOPSIS
Removes all shares of a folder.

.DESCRIPTION
Removes all shares of a folder.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER Path
    String -- The path to the folder.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path    
)

Set-StrictMode -Version 5.0

$CimInstance = Get-CimInstance -Class Win32_Share -Filter Path="'$Path'"
$RemoveShareCommand = ''
if ($CimInstance.name -And $CimInstance.name.GetType().name -ne 'String') { $RemoveShareCommand = $CimInstance.ForEach{ 'Remove-SmbShare -Name "' + $_.name + '" -Force'} } 
Else { $RemoveShareCommand = 'Remove-SmbShare -Name "' + $CimInstance.Name + '" -Force'}
if($RemoveShareCommand) { $RemoveShareCommand.ForEach{ Invoke-Expression $_ } }


}
## [END] Remove-WACVMAllShareNames ##
function Remove-WACVMFileSystemEntity {
<#

.SYNOPSIS
Remove the passed in file or path.

.DESCRIPTION
Remove the passed in file or path from this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER path
    String -- the file or path to remove.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path
)

Set-StrictMode -Version 5.0

Remove-Item -Path $Path -Confirm:$false -Force -Recurse

}
## [END] Remove-WACVMFileSystemEntity ##
function Remove-WACVMFolderShareUser {
<#

.SYNOPSIS
Removes a user from the folder access.

.DESCRIPTION
Removes a user from the folder access.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER Path
    String -- The path to the folder.

.PARAMETER Identity
    String -- The user identification (AD / Local user).

.PARAMETER FileSystemRights
    String -- File system rights of the user.

.PARAMETER AccessControlType
    String -- Access control type of the user.    

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path,

    [Parameter(Mandatory = $true)]
    [String]
    $Identity,

    [Parameter(Mandatory = $true)]
    [String]
    $FileSystemRights,

    [ValidateSet('Deny','Allow')]
    [Parameter(Mandatory = $true)]
    [String]
    $AccessControlType
)

Set-StrictMode -Version 5.0

function Remove-UserPermission
{
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path,
    
        [Parameter(Mandatory = $true)]
        [String]
        $Identity,
        
        [ValidateSet('Deny','Allow')]
        [Parameter(Mandatory = $true)]
        [String]
        $ACT
    )

    $Acl = Get-Acl $Path
    $AccessRule = New-Object system.security.accesscontrol.filesystemaccessrule($Identity, 'ReadAndExecute','ContainerInherit, ObjectInherit', 'None', $ACT)
    $Acl.RemoveAccessRuleAll($AccessRule)
    Set-Acl $Path $Acl
}

Remove-UserPermission $Path $Identity 'Allow'
Remove-UserPermission $Path $Identity 'Deny'
}
## [END] Remove-WACVMFolderShareUser ##
function Remove-WACVMSmbServerCertificateMapping {
<#
.SYNOPSIS
Removes the currently installed certificate for smb over QUIC on the server.

.DESCRIPTION
Removes the currently installed certificate for smb over QUIC on the server and also sets the status of smbOverQuic to enabled on the server.

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $false)]
    [String[]]
    $ServerDNSNames,

    [Parameter(Mandatory = $false)]
    [String]
    $KdcPort,

    [Parameter(Mandatory = $true)]
    [boolean]
    $IsKdcProxyMappedForSmbOverQuic
)

Set-Location Cert:\LocalMachine\My


if($ServerDNSNames.count -gt 0){
    foreach($serverDNSName in $ServerDNSNames){
        Remove-SmbServerCertificateMapping -Name $serverDNSName -Force
    }
}

if($IsKdcProxyMappedForSmbOverQuic -and $KdcPort -ne $null){
    $port = "0.0.0.0:"
    $ipport = $port+$KdcPort
    $deleteCertKdc = netsh http delete sslcert ipport=$ipport
    if ($LASTEXITCODE -ne 0) {
        throw $deleteCertKdc
    }
    $firewallString = "KDC Proxy Server service (KPS) for SMB over QUIC"
    Remove-NetFirewallRule -DisplayName $firewallString
}

Set-SmbServerConfiguration -EnableSMBQUIC $true -Force
}
## [END] Remove-WACVMSmbServerCertificateMapping ##
function Remove-WACVMSmbShare {
<#

.SYNOPSIS
Removes shares of a folder.

.DESCRIPTION
Removes selected shares of a folder.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER name
    String -- The name of the folder.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Name    
)

Remove-SmbShare -Name $Name -Force


}
## [END] Remove-WACVMSmbShare ##
function Rename-WACVMFileSystemEntity {
<#

.SYNOPSIS
Rename a folder.

.DESCRIPTION
Rename a folder on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER Path
    String -- the path to the folder.

.PARAMETER NewName
    String -- the new folder name.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path,

    [Parameter(Mandatory = $true)]
    [String]
    $NewName
)

Set-StrictMode -Version 5.0

<#
.Synopsis
    Name: Get-FileSystemEntityType
    Description: Gets the type of a local file system entity.

.Parameters
    $Attributes: The System.IO.FileAttributes of the FileSystemEntity.

.Returns
    The type of the local file system entity.
#>
function Get-FileSystemEntityType
{
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileAttributes]
        $Attributes
    )

    if ($Attributes -match "Directory")
    {
        return "Folder";
    }
    else
    {
        return "File";
    }
}

Rename-Item -Path $Path -NewName $NewName -PassThru |
    Microsoft.PowerShell.Utility\Select-Object @{Name="Caption"; Expression={$_.FullName}},
                @{Name="CreationDate"; Expression={$_.CreationTimeUtc}},
                Extension,
                @{Name="IsHidden"; Expression={$_.Attributes -match "Hidden"}},
                Name,
                @{Name="Type"; Expression={Get-FileSystemEntityType -Attributes $_.Attributes}},
                @{Name="LastModifiedDate"; Expression={$_.LastWriteTimeUtc}},
                @{Name="Size"; Expression={if ($_.PSIsContainer) { $null } else { $_.Length }}};

}
## [END] Rename-WACVMFileSystemEntity ##
function Resolve-WACVMDNSName {
<#

.SYNOPSIS
Resolve VM Provisioning

.DESCRIPTION
Resolve VM Provisioning

.ROLE
Administrators

#>

Param
(
    [string] $computerName
)

$succeeded = $null
$count = 0;
$maxRetryTimes = 15 * 100 # 15 minutes worth of 10 second sleep times
while ($count -lt $maxRetryTimes)
{
  $resolved =  Resolve-DnsName -Name $computerName -ErrorAction SilentlyContinue

    if ($resolved)
    {
      $succeeded = $true
      break
    }

    $count += 1

    if ($count -eq $maxRetryTimes)
    {
        $succeeded = $false
    }

    Start-Sleep -Seconds 10
}

Write-Output @{ "succeeded" = $succeeded }

}
## [END] Resolve-WACVMDNSName ##
function Restore-WACVMConfigureSmbServerCertificateMapping {
<#
.SYNOPSIS
Rolls back to the previous state of certificate maping if configure/edit action failed.

.DESCRIPTION
Rolls back to the previous state of certificate maping if configure/edit action failed.

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [boolean]
    $IsKdcProxyEnabled,

    [Parameter(Mandatory = $false)]
    [string]
    $KdcPort,

    [Parameter(Mandatory = $true)]
    [string]
    $KdcProxyOptionSelected
)

[array]$smbCertificateMappings = Get-SmbServerCertificateMapping | Microsoft.PowerShell.Utility\Select-Object Name
[array]$mappingNames = $smbCertificateMappings.name

if ($mappingNames.count -eq 0) {
    return;
}
if ($mappingNames.count -gt 0) {
    foreach ($mappingName in $mappingNames) {
        Remove-SmbServerCertificateMapping -Name $mappingName -Force
    }
}

if (!$IsKdcProxyEnabled -and $KdcProxyOptionSelected -eq 'enabled' -and $KdcPort -ne $null) {
    $urlLeft = "https://+:"
    $urlRight = "/KdcProxy/"
    $url = $urlLeft + $KdcPort + $urlRight
    $output = @(netsh http show urlacl | findstr /i "KdcProxy")
    if ($LASTEXITCODE -ne 0) {
        throw $output
    }

    if ($null -ne $output -and $output.count -gt 0) {
        $deleteOutput = netsh http delete urlacl url=$url
        if ($LASTEXITCODE -ne 0) {
            throw $deleteOutput
        }
    }
    [array]$clientAuthproperty = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" -Name "HttpsClientAuth" -ErrorAction SilentlyContinue
    if ($null -ne $clientAuthproperty -and $clientAuthproperty.count -gt 0) {
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" -Name "HttpsClientAuth"
    }
    [array]$passwordAuthproperty = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" -Name "DisallowUnprotectedPasswordAuth" -ErrorAction SilentlyContinue
    if ($null -ne $passwordAuthproperty -and $passwordAuthproperty.count -gt 0) {
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" -Name "DisallowUnprotectedPasswordAuth"
    }
    [array]$path = Get-Item  -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" -ErrorAction SilentlyContinue
    if ($null -ne $path -and $path.count -gt 0) {
        Remove-Item  -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings"
    }
    Stop-Service -Name kpssvc
    $firewallString = "KDC Proxy Server service (KPS) for SMB over QUIC"
    $rule = @(Get-NetFirewallRule -DisplayName $firewallString -ErrorAction SilentlyContinue)
    if($null -ne $rule -and $rule.count -gt 0) {
        Remove-NetFirewallRule -DisplayName $firewallString
    }

    $port = "0.0.0.0:"
    $ipport = $port+$KdcPort
    $certBinding =  @(netsh http show sslcert ipport=$ipport | findstr "Hash")
    if ($LASTEXITCODE -ne 0) {
        throw $certBinding
    }
    if($null -ne $certBinding -and $certBinding.count -gt 0) {
        $deleteCertKdc = netsh http delete sslcert ipport=$ipport
        if ($LASTEXITCODE -ne 0) {
            throw $deleteCertKdc
        } 
    }
}


}
## [END] Restore-WACVMConfigureSmbServerCertificateMapping ##
function Resume-WACVMCimService {
<#

.SYNOPSIS
Resume a service using CIM Win32_Service class.

.DESCRIPTION
Resume a service using CIM Win32_Service class.

.ROLE
Readers

#>

##SkipCheck=true##

Param(
[string]$Name
)

import-module CimCmdlets

$keyInstance = New-CimInstance -Namespace root/cimv2 -ClassName Win32_Service -Key @('Name') -Property @{Name=$Name;} -ClientOnly
Invoke-CimMethod $keyInstance -MethodName ResumeService

}
## [END] Resume-WACVMCimService ##
function Set-WACVMAzureHybridManagement {
<#

.SYNOPSIS
Onboards a machine for hybrid management.

.DESCRIPTION
Sets up a non-Azure machine to be used as a resource in Azure
The supported Operating Systems are Windows Server 2012 R2 and above.

.ROLE
Administrators

.PARAMETER subscriptionId
    The GUID that identifies subscription to Azure services

.PARAMETER resourceGroup
    The container that holds related resources for an Azure solution

.PARAMETER tenantId
    The GUID that identifies a tenant in AAD

.PARAMETER azureRegion
    The region in Azure where the service is to be deployed

.PARAMETER useProxyServer
    The flag to determine whether to use proxy server or not

.PARAMETER proxyServerIpAddress
    The IP address of the proxy server

.PARAMETER proxyServerIpPort
    The IP port of the proxy server

.PARAMETER authToken
    The authentication token for connection

.PARAMETER correlationId
    The correlation ID for the connection

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $subscriptionId,
    [Parameter(Mandatory = $true)]
    [String]
    $resourceGroup,
    [Parameter(Mandatory = $true)]
    [String]
    $tenantId,
    [Parameter(Mandatory = $true)]
    [String]
    $azureRegion,
    [Parameter(Mandatory = $true)]
    [boolean]
    $useProxyServer,
    [Parameter(Mandatory = $false)]
    [String]
    $proxyServerIpAddress,
    [Parameter(Mandatory = $false)]
    [String]
    $proxyServerIpPort,
    [Parameter(Mandatory = $true)]
    [string]
    $authToken,
    [Parameter(Mandatory = $true)]
    [string]
    $correlationId
)

Set-StrictMode -Version 5.0

<#

.SYNOPSIS
Setup script runtime environment.

.DESCRIPTION
Setup script runtime environment.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "Microsoft-ServerManagementExperience" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScript" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Set-HybridManagement.ps1" -Scope Script
    Set-Variable -Name Machine -Option ReadOnly -Value "Machine" -Scope Script
    Set-Variable -Name HybridAgentFile -Option ReadOnly -Value "AzureConnectedMachineAgent.msi" -Scope Script
    Set-Variable -Name HybridAgentPackageLink -Option ReadOnly -Value "https://aka.ms/AzureConnectedMachineAgent" -Scope Script
    Set-Variable -Name HybridAgentExecutable -Option ReadOnly -Value "$env:ProgramFiles\AzureConnectedMachineAgent\azcmagent.exe" -Scope Script
    Set-Variable -Name HttpsProxy -Option ReadOnly -Value "https_proxy" -Scope Script
}

<#

.SYNOPSIS
Cleanup script runtime environment.

.DESCRIPTION
Cleanup script runtime environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name Machine -Scope Script -Force
    Remove-Variable -Name HybridAgentFile -Scope Script -Force
    Remove-Variable -Name HybridAgentPackageLink -Scope Script -Force
    Remove-Variable -Name HybridAgentExecutable -Scope Script -Force
    Remove-Variable -Name HttpsProxy -Scope Script -Force
}

<#

.SYNOPSIS
The main function.

.DESCRIPTION
Export the passed in virtual machine on this server.

#>

function main(
    [string]$subscriptionId,
    [string]$resourceGroup,
    [string]$tenantId,
    [string]$azureRegion,
    [boolean]$useProxyServer,
    [string]$proxyServerIpAddress,
    [string]$proxyServerIpPort,
    [string]$authToken,
    [string]$correlationId
) {
    $err = $null
    $args = @{}

    # Download the package
    Invoke-WebRequest -Uri $HybridAgentPackageLink -OutFile $HybridAgentFile -ErrorAction SilentlyContinue -ErrorVariable +err
    if ($err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]:Couldn't download the hybrid management package. Error: $err"  -ErrorAction SilentlyContinue

        Write-Error @($err)[0]
        return @()
    }

    # Install the package
    msiexec /i $HybridAgentFile /l*v installationlog.txt /qn | Out-String -ErrorAction SilentlyContinue -ErrorVariable +err
    if ($err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]:Error while installing the hybrid agent package. Error: $err"  -ErrorAction SilentlyContinue

        Write-Error @($err)[0]
        return @()
    }

    # Set the proxy environment variable. Note that authenticated proxies are not supported for Private Preview.
    if ($useProxyServer) {
        [System.Environment]::SetEnvironmentVariable($HttpsProxy, $proxyServerIpAddress+':'+$proxyServerIpPort, $Machine)
        $env:https_proxy = [System.Environment]::GetEnvironmentVariable($HttpsProxy, $Machine)
    }

    # Run connect command
    & $HybridAgentExecutable connect --resource-group $resourceGroup --tenant-id $tenantId --location $azureRegion `
                                     --subscription-id $subscriptionId --access-token $authToken --correlation-id $correlationId

    # Restart himds service
    Restart-Service -Name himds -ErrorAction SilentlyContinue -ErrorVariable +err
    if ($err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]:Couldn't restart the himds service. Error: $err"  -ErrorAction SilentlyContinue

        Write-Error @($err)[0]
        return $err
    }
}


###############################################################################
# Script execution starts here
###############################################################################
setupScriptEnv

try {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    return main $subscriptionId $resourceGroup $tenantId $azureRegion $useProxyServer $proxyServerIpAddress $proxyServerIpPort $authToken $correlationId

} finally {
    cleanupScriptEnv
}

}
## [END] Set-WACVMAzureHybridManagement ##
function Set-WACVMEventLogChannelStatus {
 <#

.SYNOPSIS
 Change the current status (Enabled/Disabled) for the selected channel.

.DESCRIPTION
Change the current status (Enabled/Disabled) for the selected channel.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

#>

Param(
    [string]$channel,
    [boolean]$status
)

$ch = Get-WinEvent -ListLog $channel
$ch.set_IsEnabled($status)
$ch.SaveChanges()
}
## [END] Set-WACVMEventLogChannelStatus ##
function Set-WACVMRemoteApplicationSettings {
<#

.SYNOPSIS
Sets the remote application allow list setting on target node.

.DESCRIPTION
Sets the remote application allow list setting on target node. This value is used
to determine whether the Remote App tool is available for usage.

.ROLE
Administrators

#>

param(
     [Parameter(Mandatory=$true)]
    [int]
    $allowRemoteApplication)

$key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\TSAppAllowList'
Set-ItemProperty -Path $key -Name 'fDisabledAllowList' -Value $allowRemoteApplication


}
## [END] Set-WACVMRemoteApplicationSettings ##
function Set-WACVMRemoteDesktopSettings {
<#

.SYNOPSIS
Sets the remote desktop settings on target node.

.DESCRIPTION
Sets the remote desktop settings on target node. The value stored is used to
determine whether Remote Desktop and Remote App capabilities will be avaiable.

.ROLE
Administrators

#>

param(
    [Parameter(Mandatory=$False)]
    [boolean]
    $AllowRemoteDesktop,

    [Parameter(Mandatory=$False)]
    [boolean]
    $AllowRemoteDesktopWithNLA,

    [Parameter(Mandatory=$False)]
    [int]
    $PortNumber)

    Set-Variable -Option Constant -Name RdpFirewallGroup -Value "@FirewallAPI.dll,-28752" -ErrorAction SilentlyContinue

    $regKey1 = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $regKey2 = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'

    $keyProperty1 = "fDenyTSConnections"
    $keyProperty2 = "UserAuthentication"
    $keyProperty3 = "PortNumber"

    $keyPropertyValue1 = $(if ($AllowRemoteDesktop -eq $True) { 0 } else { 1 })
    $keyPropertyValue2 = $(if ($AllowRemoteDesktopWithNLA -eq $True) { 1 } else { 0 })

    if (!(Test-Path $regKey1))
    {
        New-Item -Path $regKey1 -Force | Out-Null
    }
    New-ItemProperty -Path $regKey1 -Name $keyProperty1 -Value $keyPropertyValue1 -PropertyType DWORD -Force | Out-Null

    if (!(Test-Path $regKey2))
    {
        New-Item -Path $regKey2 -Force | Out-Null
    }
    New-ItemProperty -Path $regKey2 -Name $keyProperty2 -Value $keyPropertyValue2 -PropertyType DWORD -Force | Out-Null

    if ($keyPropertyValue3) {
        New-ItemProperty -Path $regKey2 -Name $keyProperty3 -Value $PortNumber -PropertyType DWORD -Force | Out-Null
    }

    Enable-NetFirewallRule -Group $RdpFirewallGroup

}
## [END] Set-WACVMRemoteDesktopSettings ##
function Set-WACVMSmbOverQuicServerSettings {
<#

.SYNOPSIS
Sets smb server settings for QUIC.

.DESCRIPTION
Sets smb server settings for QUIC.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER disableSmbEncryptionOnSecureConnection
To enable or disable smbEncryption on the server.

.PARAMETER restrictNamedPipeAccessViaQuic
To enable or diable namedPipeAccess on the server.

#>

param (
[Parameter(Mandatory = $true)]
[boolean]
$disableSmbEncryptionOnSecureConnection,

[Parameter(Mandatory = $true)]
[boolean]
$restrictNamedPipeAccessViaQuic
)


Set-SmbServerConfiguration -DisableSmbEncryptionOnSecureConnection $disableSmbEncryptionOnSecureConnection -RestrictNamedPipeAccessViaQuic $restrictNamedPipeAccessViaQuic -Force;

}
## [END] Set-WACVMSmbOverQuicServerSettings ##
function Set-WACVMSmbServerCertificateMapping {
<#
.SYNOPSIS
Set Smb Server Certificate Mapping

.DESCRIPTION
Configures smb over QUIC.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER Thumbprint
    String -- The thumbprint of the certifiacte selected.

.PARAMETER ServerDNSNames
    String[] -- The addresses of the server for certificate mapping.
#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Thumbprint,

    [Parameter(Mandatory = $true)]
    [String[]]
    $ServerDNSNames,

    [Parameter(Mandatory = $true)]
    [boolean]
    $IsKdcProxyEnabled,

    [Parameter(Mandatory = $true)]
    [String]
    $KdcProxyOptionSelected,

    [Parameter(Mandatory = $false)]
    [String]
    $KdcPort
)

Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue
Set-Variable -Name LogName -Option Constant -Value "Microsoft-ServerManagementExperience" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SmeScripts-ConfigureKdcProxy" -ErrorAction SilentlyContinue

function writeInfoLog($logMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
        -Message $logMessage -ErrorAction SilentlyContinue
}

Set-Location Cert:\LocalMachine\My

function Enable-KdcProxy {

    $urlLeft = "https://+:"
    $urlRight = "/KdcProxy"
    $url = $urlLeft + $KdcPort + $urlRight

    $port = "0.0.0.0:"
    $ipport = $port+$KdcPort

    $ComputerName = (Get-CimInstance Win32_ComputerSystem).DNSHostName + "." + (Get-CimInstance Win32_ComputerSystem).Domain

    try {
        $certBinding = @(netsh http show sslcert ipport=$ipport | findstr "Hash")
        if($null -ne $certBinding -and $certBinding.count -gt 0) {
            $deleteCertKdc = netsh http delete sslcert ipport=$ipport
            if ($LASTEXITCODE -ne 0) {
                throw $deleteCertKdc
            }
        }
        $guid = [Guid]::NewGuid()
        $netshAddCertBinding = netsh http add sslcert ipport=$ipport certhash=$Thumbprint certstorename="my" appid="{$guid}"
        if ($LASTEXITCODE -ne 0) {
          throw $netshAddCertBinding
        }
        $message = 'Completed adding ssl certificate port'
        writeInfoLog $message
        if ($ServerDNSNames.count -gt 0) {
            foreach ($serverDnsName in $ServerDnsNames) {
                if($ComputerName.trim() -ne $serverDnsName.trim()){
                    $output = Echo 'Y' | netdom computername $ComputerName /add $serverDnsName
                    if ($LASTEXITCODE -ne 0) {
                        throw $output
                    }
                }
            }
            $message = 'Completed adding alternative names'
            writeInfoLog $message
        }
        if(!$IsKdcProxyEnabled) {
            $netshOutput = netsh http add urlacl url=$url user="NT authority\Network Service"
            if ($LASTEXITCODE -ne 0) {
                throw $netshOutput
            }
            $message = 'Completed adding urlacl'
            writeInfoLog $message
            New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings"  -force
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" -Name "HttpsClientAuth" -Value 0x0 -type DWORD
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" -Name "DisallowUnprotectedPasswordAuth" -Value 0x0 -type DWORD
            Set-Service -Name kpssvc -StartupType Automatic
            Start-Service -Name kpssvc
        }
        $message = 'Returning method Enable-KdcProxy'
        writeInfoLog $message
        return $true;
    }
    catch {
        throw $_
    }
}
function New-SmbCertificateMapping {
    if ($ServerDNSNames.count -gt 0) {
        $message = 'Setting server dns names'
        writeInfoLog $message
        foreach ($serverDNSName in $ServerDNSNames) {
            New-SmbServerCertificateMapping -Name $serverDNSName -Thumbprint $Thumbprint -StoreName My -Force
        }
        if ($KdcProxyOptionSelected -eq "enabled" -and $KdcPort -ne $null){
            $message = 'Enabling Kdc Proxy'
            writeInfoLog $message
            $result = Enable-KdcProxy
            if($result) {
                $firewallString = "KDC Proxy Server service (KPS) for SMB over QUIC"
                $firewallDesc = "The KDC Proxy Server service runs on edge servers to proxy Kerberos protocol messages to domain controllers on the corporate network. Default port is TCP/443."
                New-NetFirewallRule -DisplayName $firewallString -Description $firewallDesc -Protocol TCP -LocalPort $KdcPort -Direction Inbound -Action Allow
            }
        }
        return $true;
    }
    $message = 'Exiting method smb certificate mapping '
    writeInfoLog $message
    return $true;
}

return New-SmbCertificateMapping;

}
## [END] Set-WACVMSmbServerCertificateMapping ##
function Set-WACVMSmbServerSettings {
<#
.SYNOPSIS
Updates the server configuration settings on the server.

.DESCRIPTION
Updates the server configuration settings on the server.

.ROLE
Administrators

#>

<#
.Synopsis
    Name: Set-SmbServerSettings
    Description: Updates the server configuration settings on the server.
#>


param (

    [Parameter(Mandatory = $true)]
    [boolean]
    $AuditSmb1Access,

    [Parameter(Mandatory = $true)]
    [boolean]
    $RequireSecuritySignature,

    [Parameter(Mandatory = $false)]
    [boolean]
    $RejectUnencryptedAccess,

    [Parameter(Mandatory = $true)]
    [boolean]
    $EncryptData,

    [Parameter(Mandatory = $true)]
    [boolean]
    $CompressionSettingsClicked
)

$HashArguments = @{
}

if($CompressionSettingsClicked) {
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\parameters" -Name "DisableCompression" -Value 0x1 -type DWORD
} else {
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\parameters" -Name "DisableCompression" -Value 0x0 -type DWORD
}

if($RejectUnencryptedAccess -ne $null){
    $HashArguments.Add("RejectUnencryptedAccess", $RejectUnencryptedAccess)
}

Set-SmbServerConfiguration -AuditSmb1Access $AuditSmb1Access -RequireSecuritySignature $RequireSecuritySignature  -EncryptData $EncryptData @HashArguments -Force
}
## [END] Set-WACVMSmbServerSettings ##
function Set-WACVMVMPovisioning {
<#

.SYNOPSIS
Prepare VM Provisioning

.DESCRIPTION
Prepare VM Provisioning

.ROLE
Administrators

#>

Param (
    [Parameter(Mandatory = $true)]
    [array]$disks
)

$output = @{ }

$requiredDriveLetters = $disks.driveLetter
$volumeLettersInUse = (Get-Volume | Sort-Object DriveLetter).DriveLetter

$output.Set_Item('restartNeeded', $false)
$output.Set_Item('pageFileLetterChanged', $false)
$output.Set_Item('pageFileLetterNew', $null)
$output.Set_Item('pageFileLetterOld', $null)
$output.Set_Item('pageFileDiskNumber', $null)
$output.Set_Item('cdDriveLetterChanged', $false)
$output.Set_Item('cdDriveLetterNew', $null)
$output.Set_Item('cdDriveLetterOld', $null)

$cdDriveLetterNeeded = $false
$cdDrive = Get-WmiObject -Class Win32_volume -Filter 'DriveType=5' | Microsoft.PowerShell.Utility\Select-Object -First 1
if ($cdDrive -ne $null) {
    $cdDriveLetter = $cdDrive.DriveLetter.split(':')[0]
    $output.Set_Item('cdDriveLetterOld', $cdDriveLetter)

    if ($requiredDriveLetters.Contains($cdDriveLetter)) {
        $cdDriveLetterNeeded = $true
    }
}

$pageFileLetterNeeded = $false
$pageFile = Get-WmiObject Win32_PageFileusage
if ($pageFile -ne $null) {
    $pagingDriveLetter = $pageFile.Name.split(':')[0]
    $output.Set_Item('pageFileLetterOld', $pagingDriveLetter)

    if ($requiredDriveLetters.Contains($pagingDriveLetter)) {
        $pageFileLetterNeeded = $true
    }
}

if ($cdDriveLetterNeeded -or $pageFileLetterNeeded) {
    $capitalCCharNumber = 67;
    $capitalZCharNumber = 90;

    for ($index = $capitalCCharNumber; $index -le $capitalZCharNumber; $index++) {
        $tempDriveLetter = [char]$index

        $willConflict = $requiredDriveLetters.Contains([string]$tempDriveLetter)
        $inUse = $volumeLettersInUse.Contains($tempDriveLetter)
        if (!$willConflict -and !$inUse) {
            if ($cdDriveLetterNeeded) {
                $output.Set_Item('cdDriveLetterNew', $tempDriveLetter)
                $cdDrive | Set-WmiInstance -Arguments @{DriveLetter = $tempDriveLetter + ':' } > $null
                $output.Set_Item('cdDriveLetterChanged', $true)
                $cdDriveLetterNeeded = $false
            }
            elseif ($pageFileLetterNeeded) {

                $computerObject = Get-WmiObject Win32_computersystem -EnableAllPrivileges
                $computerObject.AutomaticManagedPagefile = $false
                $computerObject.Put() > $null

                $currentPageFile = Get-WmiObject Win32_PageFilesetting
                $currentPageFile.delete() > $null

                $diskNumber = (Get-Partition -DriveLetter $pagingDriveLetter).DiskNumber

                $output.Set_Item('pageFileLetterNew', $tempDriveLetter)
                $output.Set_Item('pageFileDiskNumber', $diskNumber)
                $output.Set_Item('pageFileLetterChanged', $true)
                $output.Set_Item('restartNeeded', $true)
                $pageFileLetterNeeded = $false
            }

        }
        if (!$cdDriveLetterNeeded -and !$pageFileLetterNeeded) {
            break
        }
    }
}

# case where not enough drive letters available after iterating through C-Z
if ($cdDriveLetterNeeded -or $pageFileLetterNeeded) {
    $output.Set_Item('preProvisioningSucceeded', $false)
}
else {
    $output.Set_Item('preProvisioningSucceeded', $true)
}


Write-Output $output


}
## [END] Set-WACVMVMPovisioning ##
function Start-WACVMCimService {
<#

.SYNOPSIS
Start a service using CIM Win32_Service class.

.DESCRIPTION
Start a service using CIM Win32_Service class.

.ROLE
Administrators

#>

##SkipCheck=true##

Param(
[string]$Name
)

import-module CimCmdlets

$keyInstance = New-CimInstance -Namespace root/cimv2 -ClassName Win32_Service -Key @('Name') -Property @{Name=$Name;} -ClientOnly
Invoke-CimMethod $keyInstance -MethodName StartService

}
## [END] Start-WACVMCimService ##
function Start-WACVMVMProvisioning {
<#

.SYNOPSIS
Execute VM Provisioning

.DESCRIPTION
Execute VM Provisioning

.ROLE
Administrators

#>

Param (
    [Parameter(Mandatory = $true)]
    [bool] $partitionDisks,

    [Parameter(Mandatory = $true)]
    [array]$disks,

    [Parameter(Mandatory = $true)]
    [bool]$pageFileLetterChanged,

    [Parameter(Mandatory = $false)]
    [string]$pageFileLetterNew,

    [Parameter(Mandatory = $false)]
    [int]$pageFileDiskNumber,

    [Parameter(Mandatory = $true)]
    [bool]$systemDriveModified
)

$output = @{ }

$output.Set_Item('restartNeeded', $pageFileLetterChanged)

if ($pageFileLetterChanged) {
    Get-Partition -DiskNumber $pageFileDiskNumber | Set-Partition -NewDriveLetter $pageFileLetterNew
    $newPageFile = $pageFileLetterNew + ':\pagefile.sys'
    Set-WMIInstance -Class Win32_PageFileSetting -Arguments @{name = $newPageFile; InitialSize = 0; MaximumSize = 0 } > $null
}

if ($systemDriveModified) {
    $size = Get-PartitionSupportedSize -DriveLetter C
    Resize-Partition -DriveLetter C -Size $size.SizeMax > $null
}

if ($partitionDisks -eq $true) {
    $dataDisks = Get-Disk | Where-Object PartitionStyle -eq 'RAW' | Sort-Object Number
    for ($index = 0; $index -lt $dataDisks.Length; $index++) {
        Initialize-Disk  $dataDisks[$index].DiskNumber -PartitionStyle GPT -PassThru |
        New-Partition -Size $disks[$index].volumeSizeInBytes -DriveLetter $disks[$index].driveLetter |
        Format-Volume -FileSystem $disks[$index].fileSystem -NewFileSystemLabel $disks[$index].name -Confirm:$false -Force > $null;
    }
}

Write-Output $output

}
## [END] Start-WACVMVMProvisioning ##
function Suspend-WACVMCimService {
<#

.SYNOPSIS
Suspend a service using CIM Win32_Service class.

.DESCRIPTION
Suspend a service using CIM Win32_Service class.

.ROLE
Administrators

#>

##SkipCheck=true##

Param(
[string]$Name
)

import-module CimCmdlets

$keyInstance = New-CimInstance -Namespace root/cimv2 -ClassName Win32_Service -Key @('Name') -Property @{Name=$Name;} -ClientOnly
Invoke-CimMethod $keyInstance -MethodName PauseService

}
## [END] Suspend-WACVMCimService ##
function Test-WACVMFileSystemEntity {
<#

.SYNOPSIS
Checks if a file or folder exists

.DESCRIPTION
Checks if a file or folder exists
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER Path
    String -- The path to check if it exists

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path    
)

Set-StrictMode -Version 5.0

Test-Path -path $Path

}
## [END] Test-WACVMFileSystemEntity ##
function Uninstall-WACVMSmb1 {
<#
.SYNOPSIS
Disables SMB1 on the server.

.DESCRIPTION
Disables SMB1 on the server.

.ROLE
Administrators

#>

<#
.Synopsis
    Name: UninstallSmb1
    Description: Disables SMB1 on the server.
#>

Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart
}
## [END] Uninstall-WACVMSmb1 ##