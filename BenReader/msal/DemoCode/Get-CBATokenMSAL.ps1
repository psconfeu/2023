<#
.SYNOPSIS
    Authenicate using an Azure application and a certificate to obtain a token
.DESCRIPTION
    After generating a self signed certificate, use the MSAL.PS module to authenticate to AzureAD to obtain a token
.EXAMPLE
    .\Get-CBATokenMSAL.ps1 -tenantId "0cebf1f4-e0c4-46d4-8c5a-0fc80bed6b2c" -applicationId "47727b19-7b3f-472a-8057-704affed1815" -certStore "CurrentUser" -thumbprint "1dba6cef466908426ca5985f9f4473892b2d5cbb"
.NOTES
    Requires MSAL.PS module // Install-Module MSAL.PS -Scope CurrentUser    
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateSet('LocalMachine', 'CurrentUser')]
    [string]$certStore = "LocalMachine",
    [string]$thumbprint = "CCF4E88CC6C6F3BDC7D5ECEB00F4CCCAE9A74723",
    [string]$tenantId = "0cebf1f4-e0c4-46d4-8c5a-0fc80bed6b2c",
    [string]$applicationId = "06daac75-f978-4039-b563-4278554067c6"
)
Function Get-Token {
    #connect to graph and authenticate with the certificate
    Import-Module -Name MSAL.PS -Force

    $connectStringSplat = @{
        TenantId          = $tenantId
        ClientId          = $applicationId
        ClientCertificate = Get-Item -Path "Cert:\$($certStore)\My\$($thumbprint)"
    }

    $tokenRequest = Get-MsalToken @connectStringSplat
    Return $tokenRequest
}

#get token
$authToken = Get-Token
$authToken

#make a Graph call using the token to test it works
$resourceURI = "deviceAppManagement/mobileApps?`$filter=(isof('microsoft.graph.win32LobApp')and startswith(displayName,'Microsoft'))"
$method = "GET"
$apiEndpoint = "beta"

$graphParams = @{
    Headers = @{
        "Content-Type"  = "application/json"
        "Authorization" = "$($authToken.AccessToken)"
    }
    Method  = $method
    URI     = "https://graph.microsoft.com/$($apiEndpoint)/$($resourceURI)"
}

$result = (Invoke-RestMethod @graphParams).value
foreach ($app in $result) { $app | Select-Object id, displayName, displayVersion }