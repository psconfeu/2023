#region generic variables
$BaseApi = 'https://graph.microsoft.com'
$ApiVersion = 'v1.0'
$Endpoint = "/users/{0}" -f $Jaap.id
# $Endpoint = "/users/{0}" -f $Jaap.userPrincipalName
# https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0&tabs=http

$Uri = "{0}/{1}{2}" -f $BaseApi, $ApiVersion, $Endpoint

$Headers = @{
    'Authorization' = 'Bearer ' + $Token
    'Content-Type' = 'application/json'
}

$RequestProperties = @{
    Uri = $Uri
    Method = 'PATCH'
    Headers = $Headers
}
#endregion

#region Update a user
$Body = @{
    givenName = 'Jaap'
    surname = 'Brasser'
    jobTitle = 'Professional party crasher & Beer afficianado'
} | ConvertTo-Json -Depth 10

$RequestProperties.Add('Body', $Body)

$Result = Invoke-WebRequest @RequestProperties
$Result
#endregion
