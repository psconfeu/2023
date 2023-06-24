. .\Get-OauthTokenWithCertificate.ps1

# Provide the path to your .pfx certificate to use
$CertPath = ''

# Provide the ClientId and TenantId of your Azure AD App Registration and the scope you want to request
$clientId = ''
$tenantId = ''
$scope = 'https://graph.microsoft.com/.default'

# Either provide the certificate as a .pfx file (in this case without a password)
# $cert = Get-PfxCertificate -FilePath $CertPath -NoPromptForPassword
# Or refer to the certificate in the local machine store or current user store
$cert = Get-ChildItem -Path cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq $(Get-PfxCertificate -FilePath $CertPath -NoPromptForPassword).Thumbprint}
# $cert = Get-ChildItem -Path cert:\CurrentUser\My | Where-Object {$_.Thumbprint -eq $(Get-PfxCertificate -FilePath $CertPath -NoPromptForPassword).Thumbprint}

# make sure to preload the function and obtain a token based on your certificate
$CertToken = Get-OauthTokenWithCertificate -Certificate $cert -ClientId $clientId -TenantId $tenantId -OauthScopes $scope

# Copy the token to the clipboard and open https://jwt.ms to inspect the token
$Token = $CertToken.access_token
$Token | Set-Clipboard
Start-Process https://jwt.ms


# Test to see if it works

#region generic variables
$BaseApi = 'https://graph.microsoft.com'
$ApiVersion = 'v1.0'
$Endpoint = '/users'
# https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0&tabs=http

$Uri = "{0}/{1}{2}" -f $BaseApi, $ApiVersion, $Endpoint

$Headers = @{
    'Authorization' = 'Bearer ' + $Token
    'Content-Type' = 'application/json'
}

$RequestProperties = @{
    Uri = $Uri
    Method = 'GET'
    Headers = $Headers
}
#endregion

#region Check created user
$DataWR = Invoke-WebRequest @RequestProperties
$WR = $DataWR.Content | ConvertFrom-Json
$Jaap = $WR.value.where({$_.displayName -eq 'Jaap Brasser'})
$Jaap
#endregion