#region auth config
. ./DemoCode/local.ps1
#endregion

#region DONT DO THIS ITS REALLY BAD
$requestBody = @{
    resource   = 'https://graph.microsoft.com'
    client_id  = $env:appId
    grant_type = "password"
    username   = $env:usrEmail
    scope      = "openid"
    password   = $env:passwd
}
$auth = Invoke-RestMethod -Method post -Uri "https://login.microsoftonline.com/$($env:tenant)/oauth2/token" -Body $requestBody
$auth
#endregion

#region ALSO DONT DO THIS ITS REALLY BAD
$tenantId = 'powers-hell.com'
$requestBody = @{
    resource      = 'https://graph.microsoft.com'
    client_id     = $env:appId
    client_secret = $env:secret
    grant_type    = "client_credentials"
    scope         = "openid"
}
$auth = Invoke-RestMethod -Method post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/token" -Body $requestBody
$auth
#endregion