#header
function Test-SQLite {
    return (-not [string]::IsNullOrWhiteSpace(([appdomain]::currentdomain.getassemblies().Location -match 'System\.Data\.SQLite\.dll')))
}
function Get-RBACVM {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string[]]$VMName
    )
    Write-Verbose 'Checking if VMList can be updated'
    if (-not (Update-VMList)) {
        return $null
    }
    Write-Verbose ('{0} VMs are visible to this user' -f ($Script:VMIdlist).Count)
    if (($Script:VMIdlist).Count -eq 0) {
        return $null
    }
    Write-Verbose 'Importing Hyper-V module'
    try {
        Import-Module Hyper-V -EA Stop
    } catch {
        Write-Warning $_.Exception.Message
        return $null
    }
    foreach ($id in $Script:VMIdlist) {
        Write-Verbose ('Processing VM {0}' -f $id) 
        $vm = Get-VM -Id $id
        if ($PSBoundParameters.ContainsKey('VMName')) {
            $valid = $false
            foreach ($name in $VMName) {
                if ($vm.Name -like $name) {
                    $valid = $true
                    break
                }
            }
        } else {
            $valid = $true
        }
        if ($valid) {
            $vm
        }
    }
}
function Start-RBACVM {
	[CmdletBinding()]
	Param()
	return $true
}
function Stop-RBACVM {
	[CmdletBinding()]
	Param()
	return $true
}
function Update-VMList {
    [CmdletBinding()]
    Param()
    Write-Verbose 'Update-VMList started'
    if (-not (Test-SQLite)) { return $false }
    Write-Verbose 'SQLite loaded'
    if ([string]::IsNullOrWhiteSpace($script:datastorePath)) { return $false }
    Write-Verbose ('Datastore path is set to {0}' -f $script:datastorePath)
    if (-not (Test-Path -Path $script:datastorePath -PathType Leaf)) { return $false }
    Write-Verbose 'Datastore exists'
    if ($script:SIDList.Count -eq 0) { return $null }
    $dbConn = New-Object System.Data.SQLite.SQLiteConnection
    $dbConn.ConnectionString = "Data Source=$($script:datastorePath);Version=3;Read Only=True;"
    try {
        $dbConn.Open()
        Write-Verbose 'Datastore opened'
    } catch {
        Write-Warning $_.Exception.Message
        return $false
    }
    $sidClause = "SID IN ('$($script:SIDList -join "','")')"
    Write-Verbose $sidClause
    $dbCmd = $dbConn.CreateCommand()
    $res = @{}
    $idList = New-Object System.Collections.Generic.HashSet[string]
    $perms = @{}
    $dbCmd.CommandText = "SELECT * FROM PERMISSIONS"
    Write-Verbose 'Reading permissions'
    $rdr = $dbCmd.ExecuteReader()
    while ($rdr.Read()) {
        $perms.Add($rdr['PermID'],$rdr['Name'])
        Write-Verbose ('Permissioon entry: {0} = {1}' -f $rdr['PermID'],$rdr['Name'])
    }
    $rdr.Close()
    foreach ($perm in $perms.GetEnumerator()) {
        Write-Verbose ('Processing permission {0}' -f $perm.Name)
        $vmList = New-Object System.Collections.Generic.List[object]
        $dbcmd.CommandText = "SELECT VMID FROM VMACLS WHERE $sidClause AND PermID='$($perm.Name)'"
        Write-Verbose $dbcmd.CommandText
        Write-Verbose 'Reading direct ACLs'
        $rdr = $dbCmd.ExecuteReader()
        while ($rdr.Read()) {
            Write-Verbose ('Found VM: {0}' -f $rdr['VMID'])
            $null = $vmList.Add($rdr['VMID'])
            $null = $idList.Add($rdr['VMID'])
        }
        $rdr.Close()
        $dbcmd.CommandText = "SELECT VMGROUPMEMBERS.VMID FROM VMGROUPMEMBERS INNER JOIN VMGROUPACLS ON VMGROUPMEMBERS.VMGroupID=VMGROUPACLS.VMGroupID WHERE $sidClause AND PermID='$($perm.Name)'"
        Write-Verbose $dbcmd.CommandText
        write-Verbose 'Reading Group ACLs'
        $rdr = $dbCmd.ExecuteReader()
        while ($rdr.Read()) {
            Write-Verbose ('Found VM: {0}' -f $rdr['VMID'])
            $null = $vmList.Add($rdr['VMID'])
            $null = $idList.Add($rdr['VMID'])
        }
        $rdr.Close()
        $res.Add($perm.Name, $vmList)
    }
    $script:VMPermissionedList = $res
    $script:VMIDList = $idList
    Write-Verbose 'Closing datastore'
    try {
        $dbCmd.Dispose()
        $dbConn.Close()
        $dbConn.Dispose()
        [System.Data.SQLite.SQLiteConnection]::ClearAllPools()
    } catch {
        Write-Warning $_.Exception.Message
    }
    [gc]::Collect()
    [gc]::WaitForPendingFinalizers()
    return $true
}
#region footer
$script:sqlitePath = Join-Path -Path $PSScriptRoot -ChildPath 'System.Data.SQLite.dll'
Write-Verbose ('Looking for SQLite in {0}' -f $script:sqlitePath)
if (Test-Path -Path $script:sqlitePath) {
    Write-Verbose 'Loading SQLite library'
    try {
        Add-Type -Path $script:sqlitePath -EA Stop
        Write-Verbose 'SQLite loaded successfully'
    } catch {
        Write-Warning $_.Exception.Message
        return
    }
} else {
    Write-Warning 'SQLite library not found'
    return
}
$script:datastorePath = Join-Path -Path $env:ProgramData -ChildPath 'metaBPA.org\HyperV-RBAC\LocalStore.sqlite'
if (Test-Path -Path $script:datastorePath -PathType Leaf) {
    Write-Verbose ('Found local datastore at {0}' -f $script:datastorePath)
} else {
    Write-Warning ('Local datastore not present at {0}' -f $script:datastorePath)
    exit
}
if ($null -eq $PSSenderInfo) {
    Write-Verbose 'Running in a local PSSession'
    $curId = [Security.Principal.WindowsIdentity]::GetCurrent()
} else {
    Write-Verbose 'Running in a remote PSSession'
    $curId = $PSSenderInfo.UserInfo.WindowsIdentity
}
Write-Host ('Connected as {0}' -f $curId.Name) -ForegroundColor Green
$script:SIDList = @($curid.User.Value) + $curid.Groups.Value
Write-Host ('User token has {0} SIDs' -f $script:SIDList.Count) -ForegroundColor Green
#endregion
Export-ModuleMember -Function @('Get-RBACVM','Start-RBACVM','Stop-RBACVM')
