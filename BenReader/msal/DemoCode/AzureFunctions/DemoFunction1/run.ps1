using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)
try {
    #region auth
    if ($env:MSI_SECRET) { $token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com/").Token }
    else {
        Disable-AzContextAutosave -Scope Process | Out-Null
        $cred = New-Object System.Management.Automation.PSCredential $env:appId, ($env:secret | ConvertTo-SecureString -AsPlainText -Force)
        Connect-AzAccount -ServicePrincipal -Credential $cred -Tenant $env:tenant
        $token = (Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com').Token
        $authHeader = @{Authorization = "Bearer $token"}
    }
    #endregion
    #region main proces
    $params = @{
        Method = 'Get'
        Uri = 'https://graph.microsoft.com/beta/devices'
        Headers = $authHeader
        ContentType = 'Application/Json'
    }
    $restCall = Invoke-RestMethod @params
    Write-Output "Devices Found: $($restCall.value.count)"
    $resp = $restCall.value | ConvertTo-Json -Depth 100
    $statusCode = [HttpStatusCode]::OK
    $body = $resp
    #endregion
}
catch {
    write-output $_.Exception.Message
    $statusCode = [HttpStatusCode]::BadRequest
    $body = $_.Exception.Message
}

# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = $statusCode
    Body = $body
})