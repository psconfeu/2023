#region provide some input
$ReportFolder = 'C:\PSConfEU2023\Reports'
$CustomerName = 'Contoso'
#endregion

#region create the report name and path
$Date = Get-Date -Format 'yyyy-MM-dd'
$ReportType = 'DevicesWithInventory'
$ReportName = "{0}_{1}_{2}.zip" -f $CustomerName, $ReportType, $Date
$ReportPath = Join-Path $ReportFolder -ChildPath $ReportName
#endregion

#region get the token
# Provide the path to your .pfx certificate to use
$CertPath = ''

# Provide the ClientId and TenantId of your Azure AD App Registration and the scope you want to request
$clientId = ''
$tenantId = ''
$scope = 'https://graph.microsoft.com/.default'

# Either provide the certificate as a .pfx file (in this case without a password)
$cert = Get-ChildItem -Path cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq $(Get-PfxCertificate -FilePath $CertPath -NoPromptForPassword).Thumbprint}

# make sure to preload the function and obtain a token based on your certificate
$CertToken = Get-OauthTokenWithCertificate -Certificate $cert -ClientId $clientId -TenantId $tenantId -OauthScopes $scope
$Token = $CertToken.access_token



#region generic variables
$BaseApi = 'https://graph.microsoft.com'
$ApiVersion = 'beta'
$Endpoint = '/deviceManagement/reports/exportJobs'
# https://learn.microsoft.com/en-us/graph/api/intune-reporting-devicemanagementreports-get?view=graph-rest-beta

$Uri = "{0}/{1}{2}" -f $BaseApi, $ApiVersion, $Endpoint

$Headers = @{
    'Authorization' = 'Bearer ' + $Token
    'Content-Type'  = 'application/json'
}

$RequestProperties = @{
    Uri         = $Uri
    Method      = 'POST'
    Headers     = $Headers
    ErrorAction = 'Stop'
}
#endregion

#region provide the body of the request and add it to the request properties
$Body = @{
    reportName = 'DevicesWithInventory'
    filter     = ""
    select     = @()
} | ConvertTo-Json -Depth 10

$RequestProperties.Add('Body', $Body)
#endregion


#region request the report
$RequestJson = Invoke-WebRequest @RequestProperties -ErrorAction Stop
$Request = $RequestJson | ConvertFrom-Json

$ReportUri = "{0}('{1}')" -f $Uri, $($Request.id)
Start-Sleep -Seconds 15
$ReportUriProperties = @{
    Uri         = $ReportUri
    Method      = 'GET'
    Headers     = $Headers
    ErrorAction = 'Stop'
}
$ReportInfo = Invoke-WebRequest @ReportUriProperties | ConvertFrom-Json
if ($null -eq $ReportInfo.url) {
    # If the report URL is not yet available, wait 15 seconds and try again
    Start-Sleep -Seconds 5
    $ReportInfo = Invoke-WebRequest @ReportUriProperties | ConvertFrom-Json
} 
if ($ReportInfo.url) {
    $ReportProperties = @{
        Uri         = $ReportInfo.url
        Method      = 'GET'
        ErrorAction = 'Stop'
    }
    Invoke-WebRequest @ReportProperties -OutFile $ReportPath
    explorer $ReportPath
}
#endregion