#region generic variables
$BaseApi = 'https://graph.microsoft.com'
$ApiVersion = 'v1.0'
$Endpoint = '/users'
# https://learn.microsoft.com/en-us/graph/api/user-post-users?view=graph-rest-1.0&tabs=http

$Uri = "{0}/{1}{2}" -f $BaseApi, $ApiVersion, $Endpoint

$Headers = @{
    'Authorization' = 'Bearer ' + $Token
    'Content-Type' = 'application/json'
}

$RequestProperties = @{
    Uri = $Uri
    Method = 'POST'
    Headers = $Headers
}
#endregion

#region Create a new user
$Body = @{
    accountEnabled = $true
    displayName = 'Jaap Brasser'
    mailNickname = 'JaapB'
    userPrincipalName = "JaapB@MSDx890288.onmicrosoft.com"
    passwordProfile = @{
        forceChangePasswordNextSignIn = $true
        password = 'PSConfEU2023isAwesome!'
    }
} | ConvertTo-Json -Depth 10

$RequestProperties.Add('Body', $Body)

$Result = Invoke-WebRequest @RequestProperties
$Result
#endregion
