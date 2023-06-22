#header
function Test-SQLite {
    return (-not [string]::IsNullOrWhiteSpace(([appdomain]::currentdomain.getassemblies().Location -match 'System\.Data\.SQLite\.dll')))
}


function ConvertTo-SID {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        $InputValue
    )
    if (24 -le $InputValue.Count) {
        $Val3 = $InputValue[15]
        $Val3 = $Val3 * 256 + $InputValue[14]
        $Val3 = $Val3 * 256 + $InputValue[13]
        $Val3 = $Val3 * 256 + $InputValue[12]
        $Val4 = $InputValue[19]
        $Val4 = $Val4 * 256 + $InputValue[18]
        $Val4 = $Val4 * 256 + $InputValue[17]
        $Val4 = $Val4 * 256 + $InputValue[16]
        $Val5 = $InputValue[23]
        $Val5 = $Val5 * 256 + $InputValue[22]
        $Val5 = $Val5 * 256 + $InputValue[21]
        $Val5 = $Val5 * 256 + $InputValue[20]
        if (26 -le $InputValue.Count) {
            $Val6 = $InputValue[25]
            $Val6 = $Val6 * 256 + $InputValue[24]
            $out = 'S-{0}-{1}-{2}-{3}-{4}-{5}-{6}' -f $InputValue[0], $InputValue[7], $InputValue[8], $Val3, $Val4, $Val5, $Val6
        } else {
            $out = 'S-{0}-{1}-{2}-{3}-{4}-{5}' -f $InputValue[0], $InputValue[7], $InputValue[8], $Val3, $Val4, $Val5
        }
    } elseif (16 -eq $InputValue.Count) {
        $Val3 = $InputValue[15]
        $Val3 = $Val3 * 256 + $InputValue[14]
        $Val3 = $Val3 * 256 + $InputValue[13]
        $Val3 = $Val3 * 256 + $InputValue[12]
        $out = 'S-{0}-{1}-{2}-{3}' -f $InputValue[0], $InputValue[7], $InputValue[8], $Val3
    } else {
        Write-Warning ('[Convert-CharArrayToSID] Wrong byte count [{0}], should be 16, 24 or 26+' -f $InputValue.Count)
        $out = $null
    }
    return $out
}
function Add-VMGroupMember {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$GroupName,
        [Parameter(Mandatory=$true)]
        [string]$VMName
    )
    if (-not (Test-SQLite)) {
        Write-Warning 'SQLite not loaded'
        return $false
    }
    if ([string]::IsNullOrWhiteSpace($script:DatabaseLocation)) {
        Write-Warning 'Database path not set. Use Set-DatabaseLocation to connect to an existing database or New-Database to create a new RBAC database!'
        return $false
    } elseif (-not (Test-Path -Path $script:DatabaseLocation -PathType Leaf)) {
        Write-Warning ('Database path not found or not accessible: {0}' -f $script:DatabaseLocation)
        return $false
    }
    $dbConn = New-Object System.Data.SQLite.SQLiteConnection
    $dbConn.ConnectionString = "Data Source=$($Script:DatabaseLocation);Version=3;"
    try {
        $dbConn.Open()
    } catch {
        Write-Warning $_.Exception.Message
        return $false
    }
    $dbCmd = $dbConn.CreateCommand()
    $dbCmd.CommandText = "SELECT COUNT(*) FROM VMGROUPS WHERE VMGroupName='$($GroupName.Trim() -replace "'","''")'"
    $cnt = $dbCmd.ExecuteScalar()
    if ($cnt -eq 0) {
        Write-Warning ('Group not found: ' -f $GroupName)
    } else {
        $dbCmd.CommandText = "SELECT COUNT(*) FROM VMS WHERE VMName='$($VMName.Trim() -replace "'","''")'"
        $cnt = $dbCmd.ExecuteScalar()
        if ($cnt -eq 0) {
            Write-Warning ('VM not found: ' -f $VMName)
        } else { 
            $dbCmd.CommandText = "SELECT VMGroupID FROM VMGROUPS WHERE VMGroupName='$($GroupName.Trim() -replace "'","''")'"
            $groupID = $dbCmd.ExecuteScalar()
            $dbCmd.CommandText = "SELECT VMID FROM VMS WHERE VMName='$($VMName.Trim() -replace "'","''")'"
            $vmID = $dbCmd.ExecuteScalar()
            $dbCmd.CommandText = "SELECT COUNT(*) FROM VMGROUPMEMBERS WHERE VMID='$($vmID)' AND VMGroupID='$($groupID)'"
            $cnt = $dbCmd.ExecuteScalar()
            if ($cnt -gt 0) {
                Write-Warning 'Membership already present'
            } else {
                $dbCmd.CommandText = "INSERT INTO VMGROUPMEMBERS (VMID,VMGroupID) VALUES ('$($vmID)','$($groupID)')"
                $null = $dbCmd.ExecuteNonQuery()
            }
        }
    }

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
    return $res
}
function Add-VMGroupPermission {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$GroupName,
        [Parameter(Mandatory=$true)]
        [ValidatePattern('^[a-zA-Z0-9\-_\.]+$')]
        [string]$PrincipalName,
        [Parameter(Mandatory=$false)]
        [ValidateSet('View','Start','Stop','CreateSnapshot','RestoreSnapshot','DeleteSnapshot','Delete')]
        [string[]]$Permission = 'View'
    )
    if (-not (Test-SQLite)) {
        Write-Warning 'SQLite not loaded'
        return $false
    }
    if ([string]::IsNullOrWhiteSpace($script:DatabaseLocation)) {
        Write-Warning 'Database path not set. Use Set-DatabaseLocation to connect to an existing database or New-Database to create a new RBAC database!'
        return $false
    } elseif (-not (Test-Path -Path $script:DatabaseLocation -PathType Leaf)) {
        Write-Warning ('Database path not found or not accessible: {0}' -f $script:DatabaseLocation)
        return $false
    }
    $dbConn = New-Object System.Data.SQLite.SQLiteConnection
    $dbConn.ConnectionString = "Data Source=$($Script:DatabaseLocation);Version=3;"
    try {
        $dbConn.Open()
    } catch {
        Write-Warning $_.Exception.Message
        return $false
    }
    $dbCmd = $dbConn.CreateCommand()
    $dbCmd.CommandText = "SELECT COUNT(*) FROM VMGROUPS WHERE VMGroupName='$($GroupName.Trim() -replace "'","''")'"
    $cnt = $dbCmd.ExecuteScalar()
    if ($cnt -eq 0) {
        Write-Warning 'VM not found'
    } else {
        $dbCmd.CommandText = "SELECT VMGroupID FROM VMGROUPS WHERE VMGroupName='$($GroupName.Trim() -replace "'","''")'"
        $vmGroupID = $dbCmd.ExecuteScalar()
        $rootDSE = [adsi]"LDAP://RootDSE"
        $rootDE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($rootDSE.defaultNamingContext)")
        $ds = New-Object System.DirectoryServices.DirectorySearcher
        $ds.SearchRoot = $rootDE
        $ds.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        $ds.Filter = "(&(|(objectclass=group)(objectclass=user))(samAccountName=$($PrincipalName)))"
        $null = $ds.PropertiesToLoad.Add("objectSID")
        $found = $ds.FindOne()
        if ($null -ne $found) {
            $sid = ConvertTo-SID $found.Properties['objectSID'][0]
            if ($Permission -notcontains 'View') { $Permission = @($Permission) + 'View' }
            foreach ($perm in $Permission) {
                $dbCmd.CommandText = "SELECT PermID FROM PERMISSIONS WHERE Name='$($perm)'"
                $permID = $dbCmd.ExecuteScalar()
                $dbCmd.CommandText = "SELECT COUNT(*) FROM VMGROUPACLS WHERE (VMGroupID='$($vmgroupID)') AND (SID='$sid') AND (PermID='$($permID)')"
                $cnt = $dbCmd.ExecuteScalar()
                if ($cnt -eq 0) {
                    $dbCmd.CommandText = "INSERT INTO VMGROUPACLS (VMGroupID,SID,PermID) VALUES ('$($vmGroupID)','$sid','$($permID)')"
                    $null = $dbCmd.ExecuteNonQuery()
                }
            }
        } else {
            Write-Warning 'User or group not found'
        }
    }
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
}
function Add-VMPermission {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$VMName,
        [Parameter(Mandatory=$true)]
        [ValidatePattern('^[a-zA-Z0-9\-_\.]+$')]
        [string]$PrincipalName,
        [Parameter(Mandatory=$false)]
        [ValidateSet('View','Start','Stop','CreateSnapshot','RestoreSnapshot','DeleteSnapshot','Delete')]
        [string[]]$Permission = 'View'
    )
    if (-not (Test-SQLite)) {
        Write-Warning 'SQLite not loaded'
        return $false
    }
    if ([string]::IsNullOrWhiteSpace($script:DatabaseLocation)) {
        Write-Warning 'Database path not set. Use Set-DatabaseLocation to connect to an existing database or New-Database to create a new RBAC database!'
        return $false
    } elseif (-not (Test-Path -Path $script:DatabaseLocation -PathType Leaf)) {
        Write-Warning ('Database path not found or not accessible: {0}' -f $script:DatabaseLocation)
        return $false
    }
    $dbConn = New-Object System.Data.SQLite.SQLiteConnection
    $dbConn.ConnectionString = "Data Source=$($Script:DatabaseLocation);Version=3;"
    try {
        $dbConn.Open()
    } catch {
        Write-Warning $_.Exception.Message
        return $false
    }
    $dbCmd = $dbConn.CreateCommand()
    $dbCmd.CommandText = "SELECT COUNT(*) FROM VMS WHERE VMName='$($VMName.Trim() -replace "'","''")'"
    $cnt = $dbCmd.ExecuteScalar()
    if ($cnt -eq 0) {
        Write-Warning 'VM not found'
    } else {
        $dbCmd.CommandText = "SELECT VMID FROM VMS WHERE VMName='$($VMName.Trim() -replace "'","''")'"
        $vmID = $dbCmd.ExecuteScalar()
        $rootDSE = [adsi]"LDAP://RootDSE"
        $rootDE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($rootDSE.defaultNamingContext)")
        $ds = New-Object System.DirectoryServices.DirectorySearcher
        $ds.SearchRoot = $rootDE
        $ds.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        $ds.Filter = "(&(|(objectclass=group)(objectclass=user))(samAccountName=$($PrincipalName)))"
        $null = $ds.PropertiesToLoad.Add("objectSID")
        $found = $ds.FindOne()
        if ($null -ne $found) {
            $sid = ConvertTo-SID $found.Properties['objectSID'][0]
            if ($Permission -notcontains 'View') { $Permission = @($Permission) + 'View' }
            foreach ($perm in $Permission) {
                $dbCmd.CommandText = "SELECT PermID FROM PERMISSIONS WHERE Name='$($perm)'"
                $permID = $dbCmd.ExecuteScalar()
                $dbCmd.CommandText = "SELECT COUNT(*) FROM VMACLS WHERE (VMID='$($vmID)') AND (SID='$sid') AND (PermID='$($permID)')"
                $cnt = $dbCmd.ExecuteScalar()
                if ($cnt -eq 0) {
                    $dbCmd.CommandText = "INSERT INTO VMACLS (VMID,SID,PermID) VALUES ('$($vmID)','$sid','$($permID)')"
                    $null = $dbCmd.ExecuteNonQuery()
                }
            }
        } else {
            Write-Warning 'User or group not found'
        }
    }
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
}
function Get-HostVM {
    [CmdletBinding()]
    Param()
    if (-not (Test-SQLite)) {
        Write-Warning 'SQLite not loaded'
        return $false
    }
    if ([string]::IsNullOrWhiteSpace($script:DatabaseLocation)) {
        Write-Warning 'Database path not set. Use Set-DatabaseLocation to connect to an existing database or New-Database to create a new RBAC database!'
        return $false
    } elseif (-not (Test-Path -Path $script:DatabaseLocation -PathType Leaf)) {
        Write-Warning ('Database path not found or not accessible: {0}' -f $script:DatabaseLocation)
        return $false
    }
    $dbConn = New-Object System.Data.SQLite.SQLiteConnection
    $dbConn.ConnectionString = "Data Source=$($Script:DatabaseLocation);Version=3;"
    try {
        $dbConn.Open()
    } catch {
        Write-Warning $_.Exception.Message
        return $false
    }
    $dbCmd = $dbConn.CreateCommand()
    $res = @()
    $dbCmd.CommandText = "SELECT * FROM VMS"
    $rdr = $dbCmd.ExecuteReader()
    while ($rdr.Read()) {
        $res += [PSCustomObject]@{
            'VMID' = $rdr['VMID']
            'VMName' = $rdr['VMName']
            'VMGroups' = @()
            'ACLs' = @()
        }
    }
    $rdr.Close()
    foreach ($vm in $res) {
        $dbCmd.CommandText = "SELECT VMGroupName FROM VMGROUPS INNER JOIN VMGROUPMEMBERS ON VMGROUPS.VMGroupID=VMGROUPMEMBERS.VMGroupID WHERE VMGROUPMEMBERS.VMID='$($vm.VMID)'"
        $rdr = $dbCmd.ExecuteReader()
        while ($rdr.Read()) {
            $vm.VMGroups += $rdr['VMGroupName']
        }
        $rdr.Close()
    }
    foreach ($vm in $res) {
        $dbCmd.CommandText = "SELECT SID, PermID FROM VMACLS WHERE VMID='$($vm.VMID)'"
        $rdr = $dbCmd.ExecuteReader()
        while ($rdr.Read()) {
            $vm.ACLs += [PSCustomObject]@{
                    'SID' = $rdr['SID']
                    'PermissionID' = $rdr['PermID']
                }
        }
        $rdr.Close()
    }
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
    return $res
}
function Get-VMGroup {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$GroupName
    )
    if (-not (Test-SQLite)) {
        Write-Warning 'SQLite not loaded'
        return $false
    }
    if ([string]::IsNullOrWhiteSpace($script:DatabaseLocation)) {
        Write-Warning 'Database path not set. Use Set-DatabaseLocation to connect to an existing database or New-Database to create a new RBAC database!'
        return $false
    } elseif (-not (Test-Path -Path $script:DatabaseLocation -PathType Leaf)) {
        Write-Warning ('Database path not found or not accessible: {0}' -f $script:DatabaseLocation)
        return $false
    }
    $dbConn = New-Object System.Data.SQLite.SQLiteConnection
    $dbConn.ConnectionString = "Data Source=$($Script:DatabaseLocation);Version=3;"
    try {
        $dbConn.Open()
    } catch {
        Write-Warning $_.Exception.Message
        return $false
    }
    $dbCmd = $dbConn.CreateCommand()
    $res = @()
    if ([string]::IsNullOrWhiteSpace($GroupName)) {
        $dbCmd.CommandText = "SELECT * FROM VMGROUPS"
    } else {
        $dbCmd.CommandText = "SELECT * FROM VMGROUPS WHERE VMGroupName='$($GroupName.Trim() -replace "'","''")'"
    }
    $rdr = $dbCmd.ExecuteReader()
    while ($rdr.Read()) {
        $res += [PSCustomObject]@{
            'VMGroupID' = $rdr['VMGroupId']
            'VMGroupName' = $rdr['VMGroupName']
            'MemberVMs' = @()
            'ACLs' = @()
        }
    }
    $rdr.Close()
    foreach ($g in $res) {
        $dbcmd.CommandText = "SELECT VMName FROM VMS INNER JOIN VMGROUPMEMBERS ON VMS.VMID=VMGROUPMEMBERS.VMID WHERE VMGROUPMEMBERS.VMGroupID='$($g.VMGroupID)'"
        $rdr = $dbCmd.ExecuteReader()
        while ($rdr.Read()) {
            $g.MemberVMs += $rdr['VMName']
        }
        $rdr.Close()
        $dbcmd.CommandText = "SELECT SID, PermID FROM VMGROUPACLS WHERE VMGroupID='$($g.VMGroupID)'"
        $rdr = $dbCmd.ExecuteReader()
        while ($rdr.Read()) {
            $g.ACLs += [PSCustomObject]@{
                    'SID' = $rdr['SID']
                    'PermissionID' = $rdr['PermID']
                }
        }
        $rdr.Close()
    }
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
    return $res
}
function Import-HostVM {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$ComputerName
    )
    if (-not (Test-SQLite)) {
        Write-Warning 'SQLite not loaded'
        return $false
    }
    if ([string]::IsNullOrWhiteSpace($script:DatabaseLocation)) {
        Write-Warning 'Database path not set. Use Set-DatabaseLocation to connect to an existing database or New-Database to create a new RBAC database!'
        return $false
    } elseif (-not (Test-Path -Path $script:DatabaseLocation -PathType Leaf)) {
        Write-Warning ('Database path not found or not accessible: {0}' -f $script:DatabaseLocation)
        return $false
    }
    try {
        Import-Module Hyper-V -EA Stop
    } catch {
        Write-Warning $_.Exception.Message
        return $false
    }
    if ([string]::IsNullOrWhiteSpace($ComputerName)) { $ComputerName = '.' }
    try {
        $vms = @(Get-VM -ComputerName $ComputerName -EA Stop)
    } catch {
        Write-Warning $_.Exception.Message
        return $false
    }
    if ($vms.Count -eq 0) {
        Write-Host 'No VMs returned from host'
        return $false
    }
    $dbConn = New-Object System.Data.SQLite.SQLiteConnection
    $dbConn.ConnectionString = "Data Source=$($Script:DatabaseLocation);Version=3;"
    try {
        $dbConn.Open()
    } catch {
        Write-Warning $_.Exception.Message
        return $false
    }
    $ok = $true
    $dbCmd = $dbConn.CreateCommand()
    foreach ($vm in $vms) {
        Write-Verbose ('Checking for VM [{1}] with ID {0}' -f $vm.Id, $vm.Name)
        $dbcmd.CommandText = "SELECT COUNT(*) FROM VMS WHERE VMID='$($vm.Id)'"
        $cnt = $dbCmd.ExecuteScalar()
        if ($cnt -eq 0) {
            Write-Verbose 'New VM, inserting'
            $dbcmd.CommandText = "INSERT INTO VMS (VMID, VMName) VALUES ('$($vm.Id)','$($vm.Name)')"
        } else {
            Write-Verbose 'Existing VM, updating'
            $dbcmd.CommandText = "UPDATE VMS SET VMName='$($vm.Name)' WHERE VMID='$($vm.Id)'"
        }
        $null = $dbCmd.ExecuteNonQuery()
    }
    $surplusClause = "WHERE VMID NOT IN ('$($vms.Id -join "','")')"
    $dbcmd.CommandText = "SELECT COUNT(*) FROM VMS $surplusClause"
    $cnt = $dbcmd.ExecuteScalar()
    Write-Verbose ('{0} surplus VMs detected' -f $cnt)
    if ($cnt -gt 0) {
        Write-Verbose 'Delete VM ACLs'
        $dbcmd.CommandText = "DELETE FROM VMACLS $surplusClause"
        $null = $dbCmd.ExecuteNonQuery()
        Write-Verbose 'Delete VM Group associations'
        $dbcmd.CommandText = "DELETE FROM VMGROUPMEMBERS $surplusClause"
        $null = $dbCmd.ExecuteNonQuery()
        Write-Verbose 'Delete VMs'
        $dbcmd.CommandText = "DELETE FROM VMS $surplusClause"
        $null = $dbCmd.ExecuteNonQuery()
    }
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
}
function New-Database {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$FolderPath = $env:TEMP,
        [Parameter(Mandatory=$true)]
        [ValidatePattern('^[a-zA-Z0-9\-]{1,15}$')]
        [string]$ComputerName
    )
    if (-not (Test-SQLite)) {
        Write-Warning 'SQLite not loaded'
        return $false
    }
    if (Test-Path -Path $FolderPath -PathType Container) {
        $realPath = Resolve-Path -Path $FolderPath
        $dbPath = Join-Path -Path $realPath -ChildPath 'LocalStore.sqlite'
        Write-Verbose ('Creating database in {0}' -f $dbPath)
        if (Test-Path -Path $dbPath -PathType Leaf) {
            try {
                Remove-Item -Path $dbPath -Force -EA Stop
            } catch {
                Write-Warning $_.Exception.Message
                return $false
            }
        }
        $dbConn = New-Object System.Data.SQLite.SQLiteConnection
        $dbConn.ConnectionString = "Data Source=$($dbPath);Version=3;"
        try {
            $dbConn.Open()
        } catch {
            Write-Warning $_.Exception.Message
            return $false
        }
        $ok = $true
        $dbCmd = $dbConn.CreateCommand()
        $dbSchema = @(
            "CREATE TABLE HOST (ComputerName TEXT, DateCreated TEXT, DateUpdated TEXT)"
            "CREATE TABLE VMS (VMID TEXT, VMName TEXT)"
            "CREATE TABLE VMGROUPS (VMGroupID TEXT, VMGroupName TEXT)"
            "CREATE TABLE VMGROUPMEMBERS (VMGroupID TEXT, VMID TEXT)"
            "CREATE TABLE PERMISSIONS (PermID TEXT, Name TEXT, Description TEXT)"
            "CREATE TABLE VMACLS (VMID TEXT, SID TEXT, PermID TEXT)"
            "CREATE TABLE VMGROUPACLS (VMGroupID TEXT, SID TEXT, PermID TEXT)"
            "INSERT INTO PERMISSIONS (PermID,Name,Description) VALUES ('130fb2a1-ec11-480f-b52a-ae045049b868','View','Allows the user to view a virtual machine''s state')"
            "INSERT INTO PERMISSIONS (PermID,Name,Description) VALUES ('b51be89b-e601-4946-be16-e7d8d9d47c81','Start','Allows the user to start a virtual machine')"
            "INSERT INTO PERMISSIONS (PermID,Name,Description) VALUES ('b4a4f703-329b-4991-a2e5-ca49980ad4f4','Stop','Allows the user to stop a virtual machine')"
            "INSERT INTO PERMISSIONS (PermID,Name,Description) VALUES ('0bc2540c-93ac-48ee-86e7-7f4406e50b7b','CreateSnapshot','Allows the user to checkpoint a virtual machine')"
            "INSERT INTO PERMISSIONS (PermID,Name,Description) VALUES ('586b78ca-8472-4a12-b340-7faab4c19b46','RestoreSnapshot','Allows the user to restore a virtual machine to a snapshot')"
            "INSERT INTO PERMISSIONS (PermID,Name,Description) VALUES ('4d142b44-22c5-4600-8f6c-751d4c325093','DeleteSnapshot','Allows the user to delete a checkpoint of a virtual machine')"
            "INSERT INTO PERMISSIONS (PermID,Name,Description) VALUES ('49f553b7-90e1-418c-a676-ec7d12e50968','Delete','Allows the user to delete a virtual machine')"
            "INSERT INTO HOST (ComputerName,DateCreated ) VALUES ('$($ComputerName)','$(Get-Date -Format "yyyy-MM-ddTHH:mm:ss")')"
        )
        foreach ($q in $dbSchema) {
            $dbCmd.CommandText = $q
            try {
                $null = $dbCmd.ExecuteNonQuery()
            } catch {
                Write-Warning $q
                Write-Warning $_.Exception.Message
                $ok = $false
            }
        }
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
        if ($ok) {
            Write-Host ('Database created successfully in {0}' -f $dbPath)
            $script:DatabaseLocation = $dbPath
        }
    } else {
        Write-Warning ('Folder path not found: {0}' -f $FolderPath)
        return $false
    }
}
function New-VMGroup {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$GroupName
    )
    if (-not (Test-SQLite)) {
        Write-Warning 'SQLite not loaded'
        return $false
    }
    if ([string]::IsNullOrWhiteSpace($script:DatabaseLocation)) {
        Write-Warning 'Database path not set. Use Set-DatabaseLocation to connect to an existing database or New-Database to create a new RBAC database!'
        return $false
    } elseif (-not (Test-Path -Path $script:DatabaseLocation -PathType Leaf)) {
        Write-Warning ('Database path not found or not accessible: {0}' -f $script:DatabaseLocation)
        return $false
    }
    $dbConn = New-Object System.Data.SQLite.SQLiteConnection
    $dbConn.ConnectionString = "Data Source=$($Script:DatabaseLocation);Version=3;"
    try {
        $dbConn.Open()
    } catch {
        Write-Warning $_.Exception.Message
        return $false
    }
    $dbCmd = $dbConn.CreateCommand()
    $dbCmd.CommandText = "SELECT COUNT(*) FROM VMGROUPS WHERE VMGroupName='$($GroupName.Trim() -replace "'","''")'"
    $cnt = $dbCmd.ExecuteScalar()
    if ($cnt -gt 0) {
        Write-Warning 'Group already present in database'
    } else {
        $guid = [GUID]::NewGuid().Guid
        $dbCmd.CommandText = "INSERT INTO VMGROUPS (VMGroupID,VMGroupName) VALUES ('$($guid)','$($GroupName.Trim() -replace "'","''")')"
        $null = $dbCmd.ExecuteNonQuery()
    }
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
}
function Pull-Database {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$ComputerName,
        [Parameter(Mandatory=$false)]
        [switch]$Force
    )
    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        $filePath = Join-Path -Path $env:ProgramData -ChildPath 'metaBPA.org\HyperV-RBAC\LocalStore.sqlite'
    } else {
        $filePath = ('\\{0}\C$\ProgramData\metaBPA.org\HyperV-RBAC\LocalStore.sqlite' -f $ComputerName.Trim())
    }
    if (Test-Path -Path $filePath -PathType Leaf) {
        $localPath = Join-Path -Path $env:TEMP -ChildPath 'LocalStore.sqlite'
        if (Test-Path -Path $localPath -PathType Leaf) {
            if ($Force) {
                try {
                    Remove-Item -Path $localPath -Force -EA Stop
                } catch {
                    Write-Warning $_.Exception.Message
                    return $false
                }
            } else {
                Write-Warning 'Local temp copy already present'
            }
        }
        if (-not (Test-Path -Path $localPath -PathType Leaf)) {
            try {
                Copy-Item -Path $filePath -Destination $env:TEMP
                $script:DatabaseLocation = $localPath
                return $true
            } catch {
                Write-Warning $_.Exception.Message
                return $false
            }
        } else {
            return $false
        }
    } else {
        Write-Warning 'Host database not found or not accessible'
        return $false
    }
}
function Push-Database {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$ComputerName,
        [Parameter(Mandatory=$false)]
        [switch]$Force
    )
    if ([string]::IsNullOrWhiteSpace($script:DatabaseLocation)) {
        Write-Warning 'Local database path not set'
        return $false
    }
    if (-not (Test-Path -Path $script:DatabaseLocation -PathType Leaf)) {
        Write-Warning ('Local database not found: {0}' -f $script:DatabaseLocation)
        return $false
    }
    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        $filePath = Join-Path -Path $env:ProgramData -ChildPath 'metaBPA.org\HyperV-RBAC\LocalStore.sqlite'
    } else {
        $filePath = ('\\{0}\C$\ProgramData\metaBPA.org\HyperV-RBAC\LocalStore.sqlite' -f $ComputerName.Trim())
    }
    Write-Verbose ('Pushing local store to {0}' -f $filePath)
    if (Test-Path -Path $filePath -PathType Leaf) {
        if ($Force) {
            Write-Verbose 'Remote file already present, removing'
            try {
                Remove-Item -Path $filePath -Force
            } catch {
                Write-Warning $_.Exception.Message
                return $false
            }
        } else {
            Write-Warning 'Remopte file already present'
        }
    }
    if (-not (Test-Path -Path $filePath -PathType Leaf)) {
        try {
            New-Item -Path (Split-Path -Path $filePath) -ItemType Directory -Force -EA Stop
        } catch {
            $_.Exception.Message
        }
        try {
            Copy-Item -Path $script:DatabaseLocation -Destination (Split-Path -Path $filePath) -Force -EA Stop
            return $true
        } catch {
            Write-Verbose 'Boo'
            Write-Warning $_.Exception.Message
            return $false
        }
    }
}
function Remove-VMGroupMember {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$GroupName,
        [Parameter(Mandatory=$true)]
        [string]$VMName
    )
    if (-not (Test-SQLite)) {
        Write-Warning 'SQLite not loaded'
        return $false
    }
    if ([string]::IsNullOrWhiteSpace($script:DatabaseLocation)) {
        Write-Warning 'Database path not set. Use Set-DatabaseLocation to connect to an existing database or New-Database to create a new RBAC database!'
        return $false
    } elseif (-not (Test-Path -Path $script:DatabaseLocation -PathType Leaf)) {
        Write-Warning ('Database path not found or not accessible: {0}' -f $script:DatabaseLocation)
        return $false
    }
    $dbConn = New-Object System.Data.SQLite.SQLiteConnection
    $dbConn.ConnectionString = "Data Source=$($Script:DatabaseLocation);Version=3;"
    try {
        $dbConn.Open()
    } catch {
        Write-Warning $_.Exception.Message
        return $false
    }
    $dbCmd = $dbConn.CreateCommand()
    $dbCmd.CommandText = "SELECT COUNT(*) FROM VMGROUPS WHERE VMGroupName='$($GroupName.Trim() -replace "'","''")'"
    $cnt = $dbCmd.ExecuteScalar()
    if ($cnt -eq 0) {
        Write-Warning ('Group not found: ' -f $GroupName)
    } else {
        $dbCmd.CommandText = "SELECT COUNT(*) FROM VMS WHERE VMName='$($VMName.Trim() -replace "'","''")'"
        $cnt = $dbCmd.ExecuteScalar()
        if ($cnt -eq 0) {
            Write-Warning ('VM not found: ' -f $VMName)
        } else { 
            $dbCmd.CommandText = "SELECT VMGroupID FROM VMGROUPS WHERE VMGroupName='$($GroupName.Trim() -replace "'","''")'"
            $groupID = $dbCmd.ExecuteScalar()
            $dbCmd.CommandText = "SELECT VMID FROM VMS WHERE VMName='$($VMName.Trim() -replace "'","''")'"
            $vmID = $dbCmd.ExecuteScalar()
            $dbCmd.CommandText = "DELETE FROM VMGROUPMEMBERS WHERE VMID='$($vmID)' AND VMGroupID='$($groupID)'"
            $cnt = $dbCmd.ExecuteNonQuery()
            if ($cnt -gt 0) {
                Write-Host 'Membership removed'
            }
        }
    }

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
    return $res
}
function Set-DatabaseLocation {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
    if (-not (Test-SQLite)) {
        Write-Warning 'SQLite not loaded'
        return $false
    }
    if (Test-Path -Path $FilePath -PathType Leaf) {
        $dbConn = New-Object System.Data.SQLite.SQLiteConnection
        $dbConn.ConnectionString = "Data Source=$($FilePath);Version=3;"
        try {
            $dbConn.Open()
        } catch {
            Write-Warning $_.Exception.Message
            return $false
        }
        if ($dbConn.State -eq 'Open') {
            $script:DatabaseLocation = $FilePath
        }
        try {
            $dbConn.Close()
            $dbConn.Dispose()
            [System.Data.SQLite.SQLiteConnection]::ClearAllPools()
        } catch {
            Write-Warning $_.Exception.Message
        }
        [gc]::Collect()
        [gc]::WaitForPendingFinalizers()
    }
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
#endregion
Export-ModuleMember -Function @('Pull-Database','Push-Database','New-Database','Set-DatabaseLocation','Import-HostVM','Get-HostVM','New-VMGroup','Get-VMGroup','Add-VMGroupMember','Remove-VMGroupMember','Add-VMPermission','Add-VMGroupPermission','Get-VMPermission','Get-VMGroupPermission','Remove-VMPermission','Remove-VMGroupPermission','Remove-VMGroup','Rename-VMGroup')
