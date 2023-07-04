#region certificates
$subjectName = "PSConfEU2023"
$certStore = "LocalMachine"
$validityPeriod = 24
$certFolder = "$($pwd)\DemoCode"
$clientID = "74864e47-6c5b-4f48-b266-6ed05924a042"
$tenantID = "5eb3e1d4-9e18-4b93-8933-29e3e47c5290"

#region not running this code in the demo today
$newCert = @{
    Subject           = "CN=$($subjectName)"
    CertStoreLocation = "Cert:\$($certStore)\My"
    KeyExportPolicy   = "Exportable"    #Exportable not great security practice tbh, use NonExportable?
    KeySpec           = "Signature"
    NotAfter          = (Get-Date).AddMonths($($validityPeriod))
}
$cert = New-SelfSignedCertificate @newCert

#export public key only
$certFolder = "$($pwd)\DemoCode"
$certExport = @{
    Cert     = $cert
    FilePath = "$($certFolder)\$($subjectName).cer"
}
Export-Certificate @certExport

#export with private key
$certFolder = "$($pwd)\DemoCode"
$certPassword = Read-Host -Prompt "Enter password for your certificate: " -AsSecureString
$pfxExport = @{
    Cert         = "Cert:\$($certStore)\My\$($cert.Thumbprint)"
    FilePath     = "$($certFolder)\$($subjectName).pfx"
    ChainOption  = "EndEntityCertOnly"
    NoProperties = $null
    Password     = $certPassword
}
Export-PfxCertificate @pfxExport
#endregion

#connect to service principal with MSAL using certificate for authentication. 
$pfxParams = @{
    FilePath = "$($certFolder)\$($subjectName).pfx"
    Password = 'P@ssw0rd' | ConvertTo-SecureString -AsPlainText -Force
}
$clientCert = Get-PfxCertificate @pfxParams
$authTokenParams = @{
    ClientId          = $clientID
    TenantId          = $tenantID
    ClientCertificate = $clientCert
}
$authToken = Get-MsalToken @authTokenParams

#make a Graph call using the token to test it works
$resourceURI = "deviceAppManagement/mobileApps?`$filter=(isof('microsoft.graph.win32LobApp'))"
$method = "GET"
$apiEndpoint = "beta"

$graphParams = @{
    Headers = @{
        "Content-Type"  = "application/json"
        "Authorization" = "$($authToken.AccessToken)"
    }
    Method  = $method
    URI     = "https://graph.microsoft.com/$($apiEndpoint)/$($resourceURI)"
}

(Invoke-RestMethod @graphParams).value

#alternative - use Microsoft.Graph module to connect using a certificate
Install-Module Microsoft.Graph -Force
Import-Module -Name Microsoft.Graph
Connect-MgGraph -TenantId $tenantID -ClientId $clientID -Certificate $clientCertificate
Get-mgContext

#Get-CBATokenMSAL.ps1 - putting it all together
#endregion