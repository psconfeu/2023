## JSON batching allows you to optimize your application by combining multiple requests (up to 20) into a single JSON object.
# https://learn.microsoft.com/en-us/graph/json-batching

#region certtoken
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
#endregion

$Uri = 'https://graph.microsoft.com/v1.0/$batch'

$Headers = @{
    'Authorization' = 'Bearer ' + $Token
    'Content-Type' = 'application/json'
}

$RequestProperties = @{
    Uri = $Uri
    Method = 'POST'
    Headers = $Headers
}


#region create batch request
$myBatchRequests = @()
[int]$requestID = 0
$requestID ++

$myRequest = [pscustomobject][ordered]@{ 
    id     = $requestID
    method = "GET"
    url    = "/users"
} 
$myBatchRequests += $myRequest

$requestID ++
$myRequest = [pscustomobject][ordered]@{ 
    id     = $requestID
    method = "GET"
    url    = "/groups"
} 
$myBatchRequests += $myRequest

$allBatchRequests =  [pscustomobject][ordered]@{ 
    requests = $myBatchRequests
}

$batchBody = $allBatchRequests | ConvertTo-Json
#endregion

$RequestProperties.Add('Body', $batchBody)

$getBatchRequests = (Invoke-WebRequest @RequestProperties).Content | ConvertFrom-Json

# show the first first request of each batch id
foreach ($jobRMResult in $getBatchRequests.responses) {
    $jobRMResult.id
    write-host -ForegroundColor blue "jobID: $($jobRMResult.id)"
    $jobRMResult.body.value[0]
}