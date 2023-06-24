#region Paging documentation
# https://learn.microsoft.com/en-us/graph/paging

#region generic variables
$BaseApi = 'https://graph.microsoft.com'
$ApiVersion = 'v1.0'
$Endpoint = '/users?$top=10'

$Uri = "{0}/{1}{2}" -f $BaseApi, $ApiVersion, $Endpoint

$Headers = @{
    'Authorization' = 'Bearer ' + $Token
    'Content-Type'  = 'application/json'
}

$RequestProperties = @{
    Uri         = $Uri
    Method      = 'GET'
    Headers     = $Headers
    ErrorAction = 'Stop'
}
#endregion

#region request data
$WRJson = Invoke-WebRequest @RequestProperties
$WR = $WRJson.Content | ConvertFrom-Json
$WR | Format-List * 
$WR.'@odata.nextLink'
$WR.value[0]

#region request next page
$RequestProperties.Uri = $WR.'@odata.nextLink'
$RequestProperties
$NextPage = Invoke-WebRequest @RequestProperties | ConvertFrom-Json
$NextPage.value[0]
#endregion

#region custom function
. .\Invoke-MSGraphMethod.ps1

$MsGraphMethodProperties = @{
    Token = $Token
    Uri = $Uri
    Method = 'GET'
    ErrorAction = 'Stop'
}

$Result = Invoke-MSGraphMethod @MsGraphMethodProperties
$Result
#endregion

# MgGraph module deals with paging using the -All parameter. 
# This allows queries made with the PowerShell SDK to automatically process paging 
# and return all the results of the query with no need to build logic around the @odata.nextlink 
# property creating a simpler scripting experience.

#endregion


#region Throttling documentation
# https://learn.microsoft.com/en-us/graph/connecting-external-content-api-limits


# https://learn.microsoft.com/en-us/graph/throttling#sample-response

# MgGraph module also deals with throttling.
# It will automatically handle 429 status code responses as well as the Retry-After response header, 
# saving the need to manually process those responses and adjust requests.  

