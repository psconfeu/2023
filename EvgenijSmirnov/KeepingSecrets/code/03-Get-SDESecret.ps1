function Get-SDESecret {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$SDEWebService,
        [Parameter(Mandatory=$true)]
        [string]$Name
    )
    if ([Environment]::UserInteractive) {
        $certStore = 'CurrentUser'
    } else {
        $certStore = 'LocalMachine'
    }
    $DECerts = @(Get-ChildItem -Path "cert:\$($certStore)\My" | Where-Object {$_.HasPrivateKey -and ($_.EnhancedKeyUsageList.ObjectID -contains '1.3.6.1.4.1.311.80.1')})
    if ($DECerts.Count -eq 0) {
        Write-Warning "No decryption certificates found in store"
        return
    }
    $apihost = $null
    if ([string]::IsNullOrWhiteSpace($SDEWebService)) {
        $domain = (Get-WmiObject Win32_ComputerSystem).Domain
        try {
            $srvObject = Resolve-DnsName -Type SRV -Name "_secretdelivery._tcp.$($domain)" -EA Stop
        } catch {
            $srvObject = $null
        }
        if ($null -ne $srvObject) {
            $apihost = $srvObject.NameTarget
            Write-Verbose "Determined host from SRV: $apihost"
        }
    } else {
        $apihost = $SDEWebService
    }
    if ($null -ne $apihost) {
        $credObject = $null
        $credData = $null
        foreach ($cert in $DECerts) {
            $uri = "https://$($apihost)/api/$($cert.Thumbprint)/$([System.URI]::EscapeDataString($Name))"
            try {
                $apires = Invoke-RestMethod -Method Get -Uri $uri -EA Stop
            } catch {
                $apires = $null
            }
            if (-not [string]::IsNullOrWhiteSpace($apires)) { 
                try {
                    $credObject = Unprotect-CmsMessage -To $cert -Content $apires
                    if ($null -ne $credObject) { 
                        try {
                            $credData = $credObject | ConvertFrom-Json -EA Stop
                        } catch {
                            Write-Warning $_.Exception.Message
                            $credData = $null    
                        }
                    }
                } catch {
                    Write-Warning $_.Exception.Message
                    $credObject = $null
                } 
            }
        }
        if ($null -ne $credData) {
            $secPwd = $credData.Password | ConvertTo-SecureString -AsPlainText -Force
            return (New-Object System.Management.Automation.PSCredential($credData.UserName, $secPwd))
        }
    } else {
        Write-Warning "Could not determine API hostname"
        return
    }    
}
Get-SDESecret -Name vSphereAdmin -Verbose