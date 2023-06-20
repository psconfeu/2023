#region Get a token
# https://developer.microsoft.com/en-us/graph/graph-explorer

# F12 - Browser Dev Tools

# Fiddler

# Azure CLI  
# az login --allow-no-subscriptions
# $AzToken = az account get-access-token --resource-type ms-graph | ConvertFrom-Json
# $Token = $AzToken.access_token

$Token = '' # Add your token here
#endregion

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

#region Invoke-WebRequest
$DataWR = Invoke-WebRequest @RequestProperties
$DataWR
# Convert the JSON response to a PowerShell object
$WR = $DataWR.Content | ConvertFrom-Json
# Count the users
$WR.value.Count
# Display a specific result
$WR.value.where({$_.displayName -eq 'Friedrich Weinmann'})
#endregion

#region Invoke-RestMethod
$DataRM = Invoke-RestMethod @RequestProperties
$DataRM
$DataRM.value.where({$_.displayName -eq 'Friedrich Weinmann'})
#endregion

#region Check created user
$DataWR = Invoke-WebRequest @RequestProperties
$WR = $DataWR.Content | ConvertFrom-Json
$Jaap = $WR.value.where({$_.displayName -eq 'Jaap Brasser'})
$Jaap
#endregion