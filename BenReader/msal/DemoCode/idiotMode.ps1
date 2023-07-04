#region config
$clientId = $env:appId
$tenantId = $env:tenant
$clientSecret = $env:secret
$userEmail = $env:usrEmail
$redirectUri = 'http://localhost:6969/'
$authority = "https://login.microsoftonline.com/$($tenantId)/oauth2/v2.0/authorize"
$tokenAuthority = "https://login.microsoftonline.com/$($tenantId)/oauth2/v2.0/token"
$scopes = New-Object System.Collections.Generic.List[string]
$scopes.Add("https://graph.microsoft.com/.default")
$scopes.Add("offline_access")
#endregion

#region functions
function New-StateValue {
    $stateBytes = New-Object byte[] 16
    [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($stateBytes)
    [System.BitConverter]::ToString($stateBytes) -replace "-"
}
function New-HttpListener {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [string]$redirectUri
    )
    try {
        # Start a local HTTP listener to receive the authorization code
        $listener = [System.Net.HttpListener]::new()
        $listener.Prefixes.Add($redirectUri)
        $listener.Start()
        $requestTask = $listener.GetContextAsync()

        # Open the authorization URL in the default web browser
        Start-Process $authorizationUrl

        Write-Host "Waiting for authorization code..." -ForegroundColor Cyan

        # Wait for the authorization code to be received
        $context = $requestTask.GetAwaiter().GetResult()
        $authorizationCode = $context.Request.QueryString["code"] 
    }
    catch {
        Write-Warning $_.Exception.Message
    }
    finally {
        # Stop the HTTP listener
        $listener.Stop()
        $authorizationCode
    }
}
#endregion

#region auth code flow
$state = New-StateValue
# Create the authorization URL
$authorizationUrl = "{0}?response_type=code&client_id={1}&redirect_uri={2}&state={3}&scope={4}&login_hint={5}" -f $authority, $clientId, $redirectUri, $state, $($scopes -join "%20" ), $userEmail

$authorizationCode = New-HttpListener -Uri $authorizationUrl -redirectUri $redirectUri
        
# Exchange the authorization code for tokens
$tokenRequestParams = @{
    client_id     = $clientId
    #client_secret = $clientSecret
    grant_type    = "authorization_code"
    code          = $authorizationCode
    redirect_uri  = $redirectUri
}
$tokenResponse = Invoke-RestMethod -Uri $tokenAuthority -Method Post -Body $tokenRequestParams
$tokenResponse
#endregion