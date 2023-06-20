# https://learn.microsoft.com/en-us/graph/auth-v2-service?tabs=http#4-request-an-access-token
function Get-GraphToken {
    param(
        [Parameter(Mandatory)]
        [Alias('ApplicationId')]
        [ValidateNotNullOrEmpty()]
        [string]$ClientId,
        [Parameter(Mandatory)]
        [Alias('Secret')]
        [ValidateNotNullOrEmpty()]
        [string]$ClientSecret,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,
        [Parameter()]
        [string]$Scope = 'https://graph.microsoft.com/.default'
    )
    [string]$GrantType = 'client_credentials'
    $TokenUri = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
    $Tokenbody = @{
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = $Scope
        grant_type    = $GrantType
    }

    $MethodProperties = @{
        Method      = 'Post'
        Uri         = $TokenUri
        Body        = $TokenBody
        ContentType = 'application/x-www-form-urlencoded'
        ErrorAction = 'Stop'
    }

    try {
        $accessTokenJson = Invoke-WebRequest @MethodProperties
        $accessToken = $accessTokenJson.Content | ConvertFrom-Json | Select-Object -expandProperty access_token
        $accessToken
    } catch {
        Write-Error -ErrorRecord $_
    }
}