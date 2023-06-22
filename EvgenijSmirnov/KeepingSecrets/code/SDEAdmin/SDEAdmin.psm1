#header
function Add-SDECertificate {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,ParameterSetName='File')]
        [string]$Path,
        [Parameter(Mandatory=$true,ParameterSetName='Store')]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string]$Thumbprint,
        [Parameter(Mandatory=$true,ParameterSetName='X509')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory=$false,ParameterSetName='File')]
        [Parameter(Mandatory=$false,ParameterSetName='Store')]
        [Parameter(Mandatory=$false,ParameterSetName='X509')]
        [switch]$IgnoreEKU,
        [Parameter(Mandatory=$false,ParameterSetName='File')]
        [Parameter(Mandatory=$false,ParameterSetName='Store')]
        [Parameter(Mandatory=$false,ParameterSetName='X509')]
        [string]$DisplayName
    )
    $cert2add = $null
    switch ($PSCmdlet.ParameterSetName) {
        'File' {
            if (Test-Path -Path $Path -PathType Leaf) {
                $tmpCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                try {
                    $null = $tmpCert.Import($Path)
                    $cert2add = $tmpCert
                } catch {
                    Write-Warning ('Error importing {0} into X509 Certificate: {1}' -f $Path, $_.Exception.Message)
                }
            }
        }
        'Store' {
            try {
                $tmpCert = Get-Item "Cert:\CurrentUser\My\$Thumbprint" -EA Stop
            } catch {
                $tmpCert = $null
            }
            if ($null -eq $tmpCert) {
                try {
                    $tmpCert = Get-Item "Cert:\LocalMachine\My\$Thumbprint" -EA Stop
                } catch {}
            }
            if ($null -ne $tmpCert) {
                $cert2add = $tmpCert
            }
        }
        'X509' {
            $cert2add = $Certificate
        }
    }
    if ($null -eq $cert2add) {
        return $false
        Write-AuditLog -EventType AddCertFailure -EventSubject "Certificate could not be found ($($PSCmdlet.ParameterSetName))"
    }
    if (-not $IgnoreEKU) {
        if ($cert2add.EnhancedKeyUsageList.ObjectID -notcontains '1.3.6.1.4.1.311.80.1') {
            Write-AuditLog -EventType AddCertFailure -EventSubject "Certificate does not have Document Encryption EKU ($($cert2add.Thumbprint))"
            return $false
        }
    }
    $sqlConn = New-Object System.Data.SqlClient.SqlConnection
    $sqlConn.ConnectionString = $script:moduleConfig.SQLConnectionString
    try {
        $sqlConn.Open()
    } catch {
        Write-Warning $_.Exception.Message
        return $false
    }
    if ($sqlConn.State -eq 'Open') {
        $res = $true
        $sqlCmd = $sqlConn.CreateCommand()
        $q = "SELECT COUNT(*) FROM CERTS WHERE CertThumbprint='$($cert2add.Thumbprint)'"
        $sqlCmd.CommandText = $q
        $existingCount = $sqlCmd.ExecuteScalar()
        if ($existingCount -gt 0) {
            Write-Host 'Certificate already present in the database'
            Write-AuditLog -EventType AddCertFailure -EventSubject "Certificate already present in the database ($($cert2add.Thumbprint))"
        } else {
            if ([string]::IsNullOrWhiteSpace($DisplayName)) { $DisplayName = $cert2add.Thumbprint }
            $certData = [Convert]::ToBase64String($cert2add.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert), [Base64FormattingOptions]::InsertLineBreaks)
            $certData = "-----BEGIN CERTIFICATE-----`r`n$($certData)`r`n-----END CERTIFICATE-----"
            $q = "INSERT INTO CERTS (CertName,CertThumbprint,CertSubject,CertIssuer,CertData,CertNotAfter,CertNotBefore,CertAddedBy,CertAddedOn) VALUES ('$($DisplayName)','$($cert2add.Thumbprint)','$($cert2add.Subject)','$($cert2add.Issuer)','$($certData)','$(Get-Date $cert2add.NotAfter -Format "yyyy-MM-ddTHH:mm:ss")','$(Get-Date $cert2add.NotBefore -Format "yyyy-MM-ddTHH:mm:ss")','$($env:USERDOMAIN)\$($env:USERNAME)',CURRENT_TIMESTAMP)"
            $sqlcmd.CommandText = $q
            $null = $sqlCmd.ExecuteNonQuery()
            Write-AuditLog -EventType AddCertSuccess -EventSubject "Certificate [$($cert2add.Thumbprint)] added successfully from ($($PSCmdlet.ParameterSetName)): Subject=$($cert2add.Subject), Issuer=$($cert2add.Issuer)"
        }

        $sqlCmd.Dispose()
        $sqlConn.Close()
        $sqlConn.Dispose()
        return $true
    }
}
function Add-SDEClient {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Name,
        [Parameter(Mandatory=$false)]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string[]]$Thumbprint,
        [Parameter(Mandatory=$true)]
        [ValidateScript({$ipa = ($_ -as [ipaddress]); if ($null -ne $ipa) { ($ipa.IPAddressToString -ieq $_) } else { $false }})]
        [string[]]$IPAddress,
        [Parameter(Mandatory=$false)]
        [string]$Description
    )
    $sqlConn = New-Object System.Data.SqlClient.SqlConnection
    $sqlConn.ConnectionString = $script:moduleConfig.SQLConnectionString
    try {
        $sqlConn.Open()
    } catch {
        Write-Warning $_.Exception.Message
        return
    }
    if ($sqlConn.State -eq 'Open') {
        $sqlCmd = $sqlConn.CreateCommand()
        $exNames = @()
        $sqlCmd.CommandText = "SELECT CredName FROM CREDS WHERE CredName IN ('$($Name -join "','")')"
        $rdr = $sqlCmd.ExecuteReader()
        while ($rdr.Read()) {
            $exNames += $rdr['CredName']
        }
        $rdr.Close()
        Write-Verbose "Determined $($exNames.Count) Names to process: $($exNames -join ', ')"
        foreach ($cn in $exNames) {
            Write-Verbose "Processing $cn"
            $exTP = @()
            $sqlCmd.CommandText = "SELECT CertThumbprint FROM CREDS WHERE CredName='$($cn -replace "'","''")'"
            $rdr = $sqlCmd.ExecuteReader()
            while ($rdr.Read()) {
                if ($Thumbprint.Count -eq 0) {
                    $exTP += $rdr['CertThumbprint']
                } else {
                    if ($Thumbprint -icontains $rdr['CertThumbprint']) {
                        $exTP += $rdr['CertThumbprint']
                    }
                }
            }
            $rdr.Close()
            foreach ($tp in $exTP) {
                $sqlCmd.CommandText = "SELECT COUNT(*) FROM CREDS WHERE (CredName='$($cn -replace "'","''")') AND (CertThumbprint='$($tp)')"
                $nCred = $sqlCmd.ExecuteScalar()
                if ($nCred -gt 0) {
                    foreach ($ip in $IPAddress) {
                        $sqlcmd.CommandText = "IF NOT EXISTS (SELECT * FROM CLIENTS WHERE (CredName='$($cn -replace "'","''")') AND (CertThumbprint='$($tp)') AND (SourceIP='$($ip)')) INSERT INTO CLIENTS (CredName,CertThumbprint,SourceIP,Description) VALUES ('$($cn -replace "'","''")','$($tp)','$($ip)','$($Description)')"
                        $nins = $sqlCmd.ExecuteNonQuery()
                        if ($nins -gt 0) {
                            Write-AuditLog -EventType AddClient -EventSubject "Added client restriction to $($ip) for [$($cn)] with certificate $($tp)"
                        }
                    }
                } else {
                    Write-Verbose "No credential item for [$($cn)] with certificate $($tp)"
                }
            }
        }
        $sqlCmd.Dispose()
        $sqlConn.Close()
        $sqlConn.Dispose()
    }
}
function Get-Padding {
    [CmdletBinding()]
    Param()
    $padLen = Get-Random -Minimum 10 -Maximum 100
    $padChars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789^!°"§$%&/()=?\{}[],;.:-_<>|'
    $res = '';
    for ($i = 0;$i -lt $padLen; $i++) {
        $res += $padChars.Substring((Get-Random -Minimum 0 -Maximum ($padChars.Length)),1)
    }
    return $res
}
function Get-SDECertificate {
    [CmdletBinding(DefaultParameterSetName='Thumbprint')]
    Param(
        [Parameter(Mandatory=$false,ParameterSetName='Thumbprint')]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string]$Thumbprint,
        [Parameter(Mandatory=$false,ParameterSetName='DisplayName')]
        [string]$DisplayName,
        [Parameter(Mandatory=$false)]
        [switch]$Raw
    )
    $sqlConn = New-Object System.Data.SqlClient.SqlConnection
    $sqlConn.ConnectionString = $script:moduleConfig.SQLConnectionString
    try {
        $sqlConn.Open()
    } catch {
        Write-Warning $_.Exception.Message
        return $false
    }
    if ($sqlConn.State -eq 'Open') {
        $sqlCmd = $sqlConn.CreateCommand()
        $q = "SELECT * FROM CERTS"
        if (-not [string]::IsNullOrEmpty($Thumbprint)) {
            $q += " WHERE CertThumbprint='$($Thumbprint)'"
        } elseif (-not [string]::IsNullOrEmpty($DisplayName)) {
            $q += " WHERE CertName='$($DisplayName)'"
        }
        $sqlCmd.CommandText = $q
        $sqlRdr = $sqlCmd.ExecuteReader()
        while ($sqlRdr.Read()) {
            if ($Raw) {
                $tmpCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                try {
                    $tmpCert.Import([byte[]][char[]]($sqlRdr['CertData']))
                    $tmpCert
                } catch {
                    Write-Warning "Error importing certificate [$($sqlRdr['CertThumbprint'])]: $($_.Exception.Message)"
                }
            } else {
                [PSCustomObject]@{
                    'Thumbprint' = $sqlRdr['CertThumbprint']
                    'DisplayName' = $sqlRdr['CertName']
                    'Subject' = $sqlRdr['CertSubject']
                    'Issuer' = $sqlRdr['CertIssuer']
                    'NotBefore' = $sqlRdr['CertNotBefore']
                    'NotAfter' = $sqlRdr['CertNotAfter']
                    'AddedOn' = $sqlRdr['CertAddedOn']
                    'AddedBy' = $sqlRdr['CertAddedBy']
                }
            }
        }
        $sqlrdr.Close()
        $sqlCmd.Dispose()
        $sqlConn.Close()
        $sqlConn.Dispose()
    }
}
function Get-SDEClient {
    [CmdletBinding(DefaultParameterSetName='All')]
    Param(
        [Parameter(Mandatory=$true,ParameterSetName='Name')]
        [ValidateNotNullOrEmpty()]
        [string[]]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='Thumbprint')]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string[]]$Thumbprint,
        [Parameter(Mandatory=$true,ParameterSetName='IPAddress')]
        [ValidateScript({$ipa = ($_ -as [ipaddress]); if ($null -ne $ipa) { ($ipa.IPAddressToString -ieq $_) } else { $false }})]
        [string[]]$IPAddress
    )
    $q = "SELECT * FROM CLIENTS"
    switch ($PSCmdlet.ParameterSetName) {
        'All' { $q += " ORDER BY CredName" }
        'Name' { $q += " WHERE CredName IN ('$(($Name | ForEach-Object {$_ -replace "'","''"}) -join "','")') ORDER BY CredName" }
        'Thumbprint' { $q += " WHERE CertThumbprint IN ('$($Thumbprint -join "','")') ORDER BY CertThumbprint" }
        'IPAddress' { $q += " WHERE SourceIP IN ('$($IPAddress -join "','")') ORDER BY SourceIP" }
    }
    $sqlConn = New-Object System.Data.SqlClient.SqlConnection
    $sqlConn.ConnectionString = $script:moduleConfig.SQLConnectionString
    try {
        $sqlConn.Open()
    } catch {
        Write-Warning $_.Exception.Message
        return
    }
    if ($sqlConn.State -eq 'Open') {
        $sqlCmd = $sqlConn.CreateCommand()
        Write-Verbose $q
        $sqlCmd.CommandText = $q
        $rdr = $sqlCmd.ExecuteReader()
        while ($rdr.Read()) {
            [PSCustomObject]@{
                'CredentialName' = $rdr['CredName']
                'Thumbprint' = $rdr['CertThumbprint']
                'IPAddress' = $rdr['SourceIP']
            }
        }
        $rdr.Close()
        $rdr.Dispose()
        $sqlCmd.Dispose()
        $sqlConn.Close()
        $sqlConn.Dispose()
    }
}
function New-SDECredential {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [Parameter(Mandatory=$true)]
        [PSCredential]$Credential,
        [Parameter(Mandatory=$true)]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string[]]$Thumbprint
    )
    $sqlConn = New-Object System.Data.SqlClient.SqlConnection
    $sqlConn.ConnectionString = $script:moduleConfig.SQLConnectionString
    try {
        $sqlConn.Open()
    } catch {
        Write-Warning $_.Exception.Message
        return
    }
    if ($sqlConn.State -eq 'Open') {
        $sqlCmd = $sqlConn.CreateCommand()
        $q = "SELECT COUNT(*) FROM CREDS WHERE CredName='$($Name -replace "'","''")'"
        $sqlCmd.CommandText = $q
        $nameCount = $sqlCmd.ExecuteScalar()
        if ($nameCount -gt 0) {
            Write-Warning "Credential [$($Name)] already present in the database. Use Update-SDECredential to update existing credential."
            Write-AuditLog -EventType NewCred -EventSubject "Credential [$($Name)] already present in the database."
        } else {
            $insertQ = @()
            foreach ($tp in $Thumbprint) {
                $q = "SELECT CertData, CertSubject FROM CERTS WHERE CertThumbprint='$($tp)'"
                $sqlCmd.CommandText = $q
                $rdr = $sqlCmd.ExecuteReader()
                if ($rdr.HasRows) {
                    $null = $rdr.Read()
                    $tmpCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                    $tmpCert.Import([byte[]][char[]]($rdr['certData']))
                    $payloadObject = [PSCustomObject]@{
                        'Padding' = Get-Padding
                        'UserName' = $Credential.UserName
                        'Password' = $Credential.GetNetworkCredential().Password
                    }
                    $payloadText = $payloadObject | ConvertTo-Json -Compress
                    $payloadMessage = Protect-CmsMessage -To $tmpCert -Content $payloadText
                    $insertQ += "INSERT INTO CREDS (CertThumbprint,CredName,CredData,CredAddedBy,CredAddedOn) VALUES ('$($tp)','$($Name -replace "'","''")','$($payloadMessage)','$($env:USERDOMAIN)\$($env:USERNAME)',CURRENT_TIMESTAMP)"
                    Write-AuditLog -EventType NewCred -EventSubject "Credential [$($Name)] encrypted for certificate [$($tp)]"
                    $rdr.Close()
                    $rdr.Dispose()
                } else {
                    Write-Warning ('Certificate with thumbprint [{0}] not present in the database. Use Add-SDECertificate to add it.' -f $tp)
                }
            }
            foreach ($q in $insertQ) {
                $sqlcmd.CommandText = $q
                $null = $sqlCmd.ExecuteNonQuery()
            }
        }
        $sqlCmd.Dispose()
        $sqlConn.Close()
        $sqlConn.Dispose()
        return $true
    }
}
function Remove-SDECertificate {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string]$Thumbprint
    )
    $sqlConn = New-Object System.Data.SqlClient.SqlConnection
    $sqlConn.ConnectionString = $script:moduleConfig.SQLConnectionString
    try {
        $sqlConn.Open()
    } catch {
        Write-Warning $_.Exception.Message
        return $false
    }
    if ($sqlConn.State -eq 'Open') {
        $sqlCmd = $sqlConn.CreateCommand()
        $q = "SELECT CertId FROM CERTS  WHERE CertThumbprint='$($Thumbprint)'"
        $sqlCmd.CommandText = $q
        $cid = $sqlCmd.ExecuteScalar()
        if ($cid -gt 0) {
            Write-Verbose "Certificate found, delete associated entries using ID=$($cid)"
            $q = "DELETE FROM CREDS WHERE CertThumbprint='$($Thumbprint)'"
            $sqlCmd.CommandText = $q
            $nDelCred = $sqlCmd.ExecuteNonQuery()
            Write-Verbose "Removed $($nDelCred) credentials from database"
            $q = "DELETE FROM CLIENTS WHERE CertThumbprint='$($Thumbprint)'"
            $sqlCmd.CommandText = $q
            $nDelCli = $sqlCmd.ExecuteNonQuery()
            Write-Verbose "Removed $($nDelCli) client restrictions from database"
            $q = "DELETE FROM CERTS WHERE CertThumbprint='$($Thumbprint)'"
            $sqlCmd.CommandText = $q
            $null = $sqlCmd.ExecuteNonQuery()
            Write-Verbose "Certificate removed"
            Write-AuditLog -EventType RemoveCert -EventSubject "Removed certificate [$($Thumbprint)] including $($nDelCli) client restrictions and $($nDelCred) saved credentials"
        } else {
            Write-Warning 'Certificate not found in database'
            Write-AuditLog -EventType RemoveCert -EventSubject "Certificate [$($Thumbprint)] not found in database"
        }
        $sqlCmd.Dispose()
        $sqlConn.Close()
        $sqlConn.Dispose()
    }
}
function Remove-SDEClient {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string]$Thumbprint,
        [Parameter(Mandatory=$false)]
        [ValidateScript({$ipa = ($_ -as [ipaddress]); if ($null -ne $ipa) { ($ipa.IPAddressToString -ieq $_) } else { $false }})]
        [string]$IPAddress
    )
    if ([string]::IsNullOrWhiteSpace($Name) -and [string]::IsNullOrWhiteSpace($Thumbprint) -and [string]::IsNullOrWhiteSpace($IPAddress)) { return }
    $sqlConn = New-Object System.Data.SqlClient.SqlConnection
    $sqlConn.ConnectionString = $script:moduleConfig.SQLConnectionString
    try {
        $sqlConn.Open()
    } catch {
        Write-Warning $_.Exception.Message
        return
    }
    if ($sqlConn.State -eq 'Open') {
        $sqlCmd = $sqlConn.CreateCommand()
        $clauses = @()
        if (-not [string]::IsNullOrWhiteSpace($Name)) { $clauses += "(CredName='$($Name -replace "'","''")')" }
        if (-not [string]::IsNullOrWhiteSpace($Thumbprint)) { $clauses += "(CertThumbprint='$($Thumbprint)')" }
        if (-not [string]::IsNullOrWhiteSpace($IPAddress)) { $clauses += "(SourceIP='$($IPAddress)')" }
        $sqlCmd.CommandText = "DELETE FROM CLIENTS WHERE $($clauses -join " AND ")"
        $nDel = $sqlCmd.ExecuteNonQuery()
        if ($nDel -gt 0) {
            Write-AuditLog -EventType RemoveClient -EventSubject "Removed $nDel entries for $($clauses -join " AND ")"
        }
        $sqlCmd.Dispose()
        $sqlConn.Close()
        $sqlConn.Dispose()
    }
}
function Remove-SDECredential {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string[]]$Thumbprint
    )
    $sqlConn = New-Object System.Data.SqlClient.SqlConnection
    $sqlConn.ConnectionString = $script:moduleConfig.SQLConnectionString
    try {
        $sqlConn.Open()
    } catch {
        Write-Warning $_.Exception.Message
        return
    }
    if ($sqlConn.State -eq 'Open') {
        $sqlCmd = $sqlConn.CreateCommand()
        $q = "SELECT COUNT(*) FROM CREDS WHERE CredName='$($Name -replace "'","''")'"
        $sqlCmd.CommandText = $q
        $nameCount = $sqlCmd.ExecuteScalar()
        if ($nameCount -eq 0) {
            Write-Host "Credential [$($Name)] not found in the database. Use New-SDECredential to insert new credential."
            Write-AuditLog -EventType RemoveCred -EventSubject "Credential [$($Name)] not found in the database"
        } else {
            if (-not $PSBoundParameters.ContainsKey('Thumbprint')) {
                Write-Verbose 'Determining thumbprints this credential is stored for'
                $Thumbprint = @()
                $q = "Select CertThumbprint FROM CREDS WHERE CredName='$($Name -replace "'","''")'"
                $sqlCmd.CommandText = $q
                $rdr = $sqlCmd.ExecuteReader()
                while ($rdr.Read()) {
                    Write-Verbose "Adding $($rdr['CertThumbprint'])"
                    $Thumbprint += $rdr['CertThumbprint']
                }
                $rdr.Close()
                $rdr.Dispose()
            }
            foreach ($tp in $Thumbprint) {
                $q = "DELETE FROM CREDS WHERE CredName='$($Name -replace "'","''")' AND CertThumbprint='$($tp)'"
                $sqlCmd.CommandText = $q
                $nDelCred = $sqlCmd.ExecuteNonQuery()
                $q = "DELETE FROM CLIENTS WHERE CredName='$($Name -replace "'","''")' AND CertThumbprint='$($tp)'"
                $sqlCmd.CommandText = $q
                $nDelCli = $sqlCmd.ExecuteNonQuery()
                Write-AuditLog -EventType RemoveCred -EventSubject "Credential [$($Name)] removed for certificate [$($tp)]. $nDelCred credential entries and $nDelCli client restrictions were removed."
            }
        }
        $sqlCmd.Dispose()
        $sqlConn.Close()
        $sqlConn.Dispose()
    }
}
function Set-SDEDatabase {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$SQLServer = 'DEVDC',
        [Parameter(Mandatory=$false)]
        [string]$SQLInstance,
        [Parameter(Mandatory=$false)]
        [int]$SQLPort,
        [Parameter(Mandatory=$false)]
        [string]$SQLDatabase = 'SDE4711'
    )
    if ([string]::IsNullOrWhiteSpace($SQLServer)) {
        Write-Warning 'SQLServer cannot be empty!'
        return
    }
    if ([string]::IsNullOrWhiteSpace($SQLDatabase)) {
        Write-Warning 'SQLDatabase cannot be empty!'
        return
    }
    if (($null -ne ($SQLPort -as [int])) -and ($SQLPort -gt 0) ) {
        $instancePart = (',{0}' -f $SQLPort)
    } elseif (-not [string]::IsNullOrWhiteSpace($SQLInstance)) {
        $instancePart = ('\{0}' -f $SQLInstance.Trim())
    } else {
        $instancePart = ''
    }
    $connStrDB = ('Server={0}{1}; Trusted_Connection=True; Database={2};' -f $SQLServer, $instancePart, $SQLDatabase.Trim())
    $dbConn = New-Object System.Data.SqlClient.SqlConnection
    $dbConn.ConnectionString = $connStrDB
    try {
        $dbConn.Open()
    } catch {}
    if ($dbConn.State -eq 'Open') {
        if (Test-Path -Path $script:moduleConfigFile -PathType Leaf) {
            $script:moduleConfig = (Get-Content -Path $script:moduleConfigFile | ConvertFrom-Json)
            $script:moduleConfig.SQLConnectionString = $connStrDB
        } else {
            $script:moduleConfig = [PSCustomObject]@{
                'SQLConnectionString' = $connStrDB
            }
        }
        $dbConn.Close()
        Write-Host "Saving configuration to $($script:moduleConfigFile)"
        $script:moduleConfig | ConvertTo-Json | Set-Content -Path $script:moduleConfigFile -Force
    } else {
        Write-Warning "Could not open SQL connection to $connStrDB"
    }
}
function Update-SDECredential {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [Parameter(Mandatory=$true)]
        [PSCredential]$Credential,
        [Parameter(Mandatory=$false)]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string[]]$Thumbprint
    )
    <#
        2DO:
        - add/remove instances
    #>
    $sqlConn = New-Object System.Data.SqlClient.SqlConnection
    $sqlConn.ConnectionString = $script:moduleConfig.SQLConnectionString
    try {
        $sqlConn.Open()
    } catch {
        Write-Warning $_.Exception.Message
        return
    }
    if ($sqlConn.State -eq 'Open') {
        $sqlCmd = $sqlConn.CreateCommand()
        $q = "SELECT COUNT(*) FROM CREDS WHERE CredName='$($Name -replace "'","''")'"
        $sqlCmd.CommandText = $q
        $nameCount = $sqlCmd.ExecuteScalar()
        if ($nameCount -eq 0) {
            Write-Host "Credential [$($Name)] not found in the database. Use New-SDECredential to insert new credential."
            Write-AuditLog -EventType UpdateCred -EventSubject "Credential [$($Name)] not found in the database"
        } else {
            $updateQ = @()
            if (-not $PSBoundParameters.ContainsKey('Thumbprint')) {
                Write-Verbose 'Determining thumbprints this credential is stored for'
                $Thumbprint = @()
                $q = "Select CertThumbprint FROM CREDS WHERE CredName='$($Name -replace "'","''")'"
                $sqlCmd.CommandText = $q
                $rdr = $sqlCmd.ExecuteReader()
                while ($rdr.Read()) {
                    Write-Verbose "Adding $($rdr['CertThumbprint'])"
                    $Thumbprint += $rdr['CertThumbprint']
                }
                $rdr.Close()
                $rdr.Dispose()
            }
            foreach ($tp in $Thumbprint) {
                $q = "SELECT CertData, CertSubject FROM CERTS WHERE CertThumbprint='$($tp)'"
                $sqlCmd.CommandText = $q
                $rdr = $sqlCmd.ExecuteReader()
                if ($rdr.HasRows) {
                    $null = $rdr.Read()
                    $tmpCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                    $tmpCert.Import([byte[]][char[]]($rdr['certData']))
                    $payloadObject = [PSCustomObject]@{
                        'Padding' = Get-Padding
                        'UserName' = $Credential.UserName
                        'Password' = $Credential.GetNetworkCredential().Password
                    }
                    $payloadText = $payloadObject | ConvertTo-Json -Compress
                    $payloadMessage = Protect-CmsMessage -To $tmpCert -Content $payloadText
                    $updateQ += "UPDATE CREDS SET CredData='$($payloadMessage)',CredUpdatedBy='$($env:USERDOMAIN)\$($env:USERNAME)',CredUpdatedOn=CURRENT_TIMESTAMP WHERE CertThumbprint='$($tp)' AND CredName='$($Name -replace "'","''")'"
                    $rdr.Close()
                    $rdr.Dispose()
                    Write-AuditLog -EventType UpdateCred -EventSubject "Credential [$($Name)] updated for certificate [$($tp)]"
                } else {
                    Write-Warning ('Certificate with thumbprint [{0}] not present in the database. Use Add-SDECertificate to add it.' -f $tp)
                }
            }
            foreach ($q in $updateQ) {
                $sqlcmd.CommandText = $q
                $null = $sqlCmd.ExecuteNonQuery()
            }
        }

        $sqlCmd.Dispose()
        $sqlConn.Close()
        $sqlConn.Dispose()
        return $true
    }
}
function Write-AuditLog {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$EventType,
        [Parameter(Mandatory=$true)]
        [string]$EventSubject
    )
    $sqlConn = New-Object System.Data.SqlClient.SqlConnection
    $sqlConn.ConnectionString = $script:moduleConfig.SQLConnectionString
    try {
        $sqlConn.Open()
    } catch {
        Write-Warning $_.Exception.Message
        return
    }
    if ($sqlConn.State -eq 'Open') {
        $sqlCmd = $sqlConn.CreateCommand()
        $q = "INSERT INTO AUDITLOG (EventTimeStamp,EventIdentity,EventType,EventSubject) VALUES (CURRENT_TIMESTAMP,'$($env:USERNAME)@$($env:COMPUTERNAME)','$($EventType -replace "'","''")','$($EventSubject -replace "'","''")')"
        $sqlCmd.CommandText = $q
        $null = $sqlCmd.ExecuteNonQuery()
        $sqlCmd.Dispose()
        $sqlConn.Close()
        $sqlConn.Dispose()
    }
}
#region footer
$script:moduleConfigFile = Join-Path -Path ([Environment]::GetFolderPath('UserProfile')) -ChildPath '.SDEAdmin.config'
if (Test-Path -Path $script:moduleConfigFile -PathType Leaf) {
    $script:moduleConfig = (Get-Content -Path $script:moduleConfigFile | ConvertFrom-Json)
} else {
    Write-Warning 'Module configuration not found. Use Set-SDEDatabase to create it.'
    $script:moduleConfig = $null
}
#endregion
Export-ModuleMember -Function @('Set-SDEDatabase','Get-SDECertificate','Add-SDECertificate','Remove-SDECertificate','Get-SDECredential','New-SDECredential','Update-SDECredential','Remove-SDECredential','Get-SDEClient','Add-SDEClient','Remove-SDEClient')
