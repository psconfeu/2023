function Invoke-MSGraphMethod {
    [Cmdletbinding()]
    param (
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [Parameter()]
        $Body,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Get', 'Post', 'Delete', 'Put', 'Patch', 'Options')]
        $Method,
        [switch]$AdvancedFilter
    )
    begin {
        $AuthHeader = @{
            'Content-Type'  = 'application/json'
            'Authorization' = ("Bearer {0}" -f $Token)
        }
        if ($AdvancedFilter){
            $AuthHeader.ConsistencyLevel = 'eventual'
        }
    }

    process {
        Clear-Variable -Name 'Results', 'StatusCode', 'QueryResults' -ErrorAction SilentlyContinue
        $QueryResults = [System.Collections.Generic.List[PSObject]]::new()

        do {
            try {
                Write-Verbose "$Uri"
                Write-Verbose "$Body"
                $RequestProperties = @{
                    Headers         = $AuthHeader
                    Uri             = $Uri
                    UseBasicParsing = $true
                    Method          = $Method
                    ContentType     = $($AuthHeader.'Content-Type')
                    ErrorAction     = 'Stop'
                }

                if ($Method -match "Post|Delete|Put|Patch") {
                    $RequestProperties.Body = $Body
                }
                do {
                    $ResultsJson = Invoke-WebRequest @RequestProperties 
                    $Results = $ResultsJson.Content | ConvertFrom-Json

                    if ($Results.value) {
                        $QueryResults += $Results.value
                    } else {
                        $QueryResults += $Results
                    }

                    $RequestProperties.uri = $Results.'@odata.nextlink'
                    $StatusCode = $ResultsJson.StatusCode
                } until (!($RequestProperties.uri))
            } catch {
                $StatusCode = $_.Exception.Response.StatusCode.value__

                if ($StatusCode -eq 429) {
                    $RetryAfter = [int]$_.Exception.Response.Headers.'Retry-After'
                    if ($RetryAfter) {
                        Write-Warning "Got throttled by Microsoft. Retry after $RetryAfter seconds. Sleeping for $($RetryAfter + 1) seconds..."
                        Start-Sleep -Seconds $($RetryAfter +1)
                    } else {
                        Write-Warning "Got throttled by Microsoft. Sleeping for 45 seconds..."
                        Start-Sleep -Seconds 45
                    }
                } else {
                    Write-Error $_.Exception
                }
            }
        } while ($StatusCode -eq 429)
        $QueryResults
    }
}