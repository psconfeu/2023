## Special thanks to my colleague Maurice Lok-Hin for making this function
## in Dutch: beter goed gejat, dan slecht bedacht

# https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials

#region Loading all functions
function Get-OauthTokenWithCertificate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        [Parameter(Mandatory = $true)]
        [string]$OauthScopes
    )

    #region helper functions
    # Create a JWT attestation from a certificate
    function Create-JWTAttestation {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
            [Parameter(Mandatory = $true)]
            [string]$ClientId,
            [Parameter(Mandatory = $true)]
            [string]$TenantId
        )
    
        #region mini function to base64 url encode a payload
        function Base64UrlEncode {
            param(
                [Parameter(ParameterSetName = 'Binary')]
                [byte[]]$BinaryValue,
                [Parameter(ParameterSetName = 'String')]
                [string]$StringValue
            )
            if ($PSCmdlet.ParameterSetName -eq 'Binary') {
                $Base64UrlEncoded = [System.Convert]::ToBase64String($BinaryValue).Replace('+', '-').Replace('/', '_')
                Write-Output $Base64UrlEncoded
            }
            if ($PSCmdlet.ParameterSetName -eq 'String') {
                $Base64UrlEncoded = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($StringValue)).Replace('+', '-').Replace('/', '_')
                Write-Output $Base64UrlEncoded
            }
        }
        #endregion mini function to base64 url encode a payload
    
        # if the certificate has no Private Key, throw..
        if (!$Certificate.HasPrivateKey) {throw "Certificate has no private key!"}
    
        # Create the header
        $Header = [PSCustomObject]@{
            "typ" = "JWT"
            "alg" = "RS256"
            "x5t" = $(Base64UrlEncode -BinaryValue $Certificate.GetCertHash())
        } | ConvertTo-Json
    
        # Create the body
        $Body = [PSCustomObject] @{
            "aud" = "https://login.microsoftonline.com/$($tenantId)/oauth2/token"
            "exp" = [System.DateTimeOffset]::new([datetime]::UtcNow.AddMinutes(5)).ToUnixTimeSeconds()
            "iss" = $clientId
            "jti" = $(New-Guid).Guid
            "nbf" = [System.DateTimeOffset]::new([datetime]::UtcNow).ToUnixTimeSeconds()
            "sub" = $clientId
        } | ConvertTo-Json
    
        # Combine the header and body so we can sign them
        $DataToSignBase64 = "$(Base64UrlEncode -StringValue $Header).$(Base64UrlEncode -StringValue $Body)"
        $DataToSignBytes = [System.Text.Encoding]::UTF8.GetBytes($DataToSignBase64)
    
        # Now we have to sign the data
        $SignatureBytes = $Certificate.PrivateKey.SignData($DataToSignBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $SignatureBase64UrlEnc = Base64UrlEncode -BinaryValue $SignatureBytes
    
        # Now we add the signature to the header + body
        $JWTData = "$DataToSignBase64.$($SignatureBase64UrlEnc)"
    
        $JWTData
    }
    
    # get an oauth token
    function Get-OAuthTokenWithCert {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [string]$ClientId,
    
            [Parameter(Mandatory = $true)]
            [string]$TenantId,
    
            [Parameter(Mandatory = $true)]
            [string]$Attestation,
    
            [Parameter(Mandatory = $true)]
            [string]$Scope
        )
    
        $Body = @{
            scope                 = $Scope
            client_id             = $ClientId
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $Attestation
            grant_type            = 'client_credentials'
        }
    
        $loginUrl = [string]::Format('https://login.microsoftonline.com/{0}/oauth2/v2.0/token', $TenantId)
    
        # get a token
        $TokenResponse = Invoke-RestMethod -Uri $loginUrl -UseBasicParsing -Body $Body -Method Post
    
        Write-Output $TokenResponse
    }
    #endregion helper functions
    
    $Att = Create-JWTAttestation -Certificate $Certificate -ClientId $clientId -TenantId $tenantId
    if ($null -ne $Att) {
        $tokenResponse = Get-OAuthTokenWithCert -ClientId $clientId -TenantId $tenantId -Attestation $Att -Scope $Scope
        Write-Output $tokenResponse
    }
}
#endregion Loading all functions