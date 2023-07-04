#region auth config
. ./DemoCode/local.ps1
#endregion

#region auth with client secret
if ($env:MSI_SECRET) { $token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com/").Token }
else {
    Disable-AzContextAutosave -Scope Process | Out-Null
    $cred = New-Object System.Management.Automation.PSCredential $env:appId, ($env:secret | ConvertTo-SecureString -AsPlainText -Force)
    Connect-AzAccount -ServicePrincipal -Credential $cred -Tenant $env:tenant
    $token = (Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com').Token
    $authHeader = @{Authorization = "Bearer $token" }
}
#endregion

#region auth with cert based...
if ($env:MSI_SECRET) { $token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com/").Token }
else {
    Disable-AzContextAutosave -Scope Process | Out-Null
    Connect-AzAccount -ServicePrincipal -ApplicationId $env:appId -CertificateThumbprint $env:certThumb -Tenant $env:tenant
    $token = (Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com').Token
    $authHeader = @{Authorization = "Bearer $token" }
}
#endregion

#region hacky mac nonsense
# Do some prep work
$StoreName = [System.Security.Cryptography.X509Certificates.StoreName]
$StoreLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]
$OpenFlags = [System.Security.Cryptography.X509Certificates.OpenFlags]
$Store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
    $StoreName::My, $StoreLocation::CurrentUser)

# Get a certificate
$X509Certificate2 = [System.Security.Cryptography.X509Certificates.X509Certificate2]
$Cert = $X509Certificate2::New($env:certPath)

# Open the store, Add the cert, Close the store.
$Store.Open($OpenFlags::ReadWrite)
$Store.Add($Cert)
$Store.Close()
#endregion