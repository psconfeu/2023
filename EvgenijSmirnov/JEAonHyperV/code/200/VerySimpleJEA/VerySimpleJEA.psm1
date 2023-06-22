function Update-MyVMList {
    [CmdletBinding()]
    Param()
    $authzFilePath = Join-Path -Path $PSScriptRoot -ChildPath 'AuthZ.csv'
    if (-not (Test-Path $authzFilePath -PathType Leaf)) {
        Write-Warning "AuthZ file not found: $($authzFilePath)"
        return
    }
    try {
        $authZtable = Import-Csv -Path $authzFilePath -Delimiter ";" -EA Stop
        Write-Host "Imported $($authZtable.Count) authZ items"
    } catch {
        Write-Warning $_.Exception.Message
        return
    }
    $allVMs = (Hyper-V\Get-VM).Name 
    $allSIDs = $PSSenderInfo.UserInfo.WindowsIdentity.Groups.Value
    foreach($item in $authZtable) {
        if ($allSIDs -contains $item.SID) {
            if ($allVMs -contains $item.VMName) {
                if ($global:MyVMGetList -notcontains $item.VMName) {
                    $global:MyVMGetList += $item.VMName
                }
                if ($item.CanStart -eq "1") {
                    if ($global:MyVMStartList -notcontains $item.VMName) {
                        $global:MyVMStartList += $item.VMName
                    }
                }
                if ($item.CanStop -eq "1") {
                    if ($global:MyVMStopList -notcontains $item.VMName) {
                        $global:MyVMStopList += $item.VMName
                    }
                }
            }
        }
    }
}

function Get-MyVM {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false, ValueFromPipeline = $true, Position=0)]
        [string[]]$Name
    )
    Begin { }
    Process {
        if (($PSBoundParameters.Keys -contains "Name") -or ($null -ne $Name)) {
            foreach ($vm in $Name) {
                if ($global:MyVMGetList -contains $vm) {
                    $VMNames += $vm
                } else {
                    Write-Warning "Not authorized to get VM [$($vm)]"
                }
            }
        } else {
            $VMNames = $global:MyVMGetList
        }
    }
    End {
        Write-Host "VMs selected: $($VMNames -join ",")"
        if ($VMNames.Count -gt 0) {
            Hyper-V\Get-VM -Name $VMNames
        }
    }
}

function Start-MyVM {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName = $true)]
        [string[]]$Name
    )
    Begin {
        if ($PSBoundParameters.Keys -contains "Name") {
            $VMNames = @()
        } else {
            $VMNames = $global:MyVMStartList
        }
    }
    Process {
        if ($PSBoundParameters.Keys -contains "Name") {
            foreach ($vm in $Name) {
                if ($global:MyVMStartList -contains $vm) {
                    $VMNames += $vm
                } else {
                    Write-Warning "Not authorized to Start VM [$($vm)]"
                }
            }
        }
    }
    End {
        if ($VMNames.Count -gt 0) {
            Hyper-V\Start-VM -Name $VMNames
        }
    }
}

function Stop-MyVM {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName = $true)]
        [string[]]$Name
    )
    Begin {
        if ($PSBoundParameters.Keys -contains "Name") {
            $VMNames = @()
        } else {
            $VMNames = $global:MyVMStopList
        }
    }
    Process {
        if ($PSBoundParameters.Keys -contains "Name") {
            foreach ($vm in $Name) {
                if ($global:MyVMStopList -contains $vm) {
                    $VMNames += $vm
                } else {
                    Write-Warning "Not authorized to Stop VM [$($vm)]"
                }
            }
        }
    }
    End {
        if ($VMNames.Count -gt 0) {
            Hyper-V\Stop-VM -Name $VMNames
        }
    }
}
$global:MyVMGetList = @()
$global:MyVMStartList = @()
$global:MyVMStopList = @()
Update-MyVMList
Write-Host "Available VMs: $($global:MyVMGetList.Count)" -ForegroundColor Green
Export-ModuleMember -Function @('Get-MyVM','Start-MyVM','Stop-MyVM')