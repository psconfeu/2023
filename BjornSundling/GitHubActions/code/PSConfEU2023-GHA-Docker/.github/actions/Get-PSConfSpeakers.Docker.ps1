function Get-PSConfSpeakers {
    param (
        [string]$Name
    )

    if (-not [string]::IsNullOrEmpty($Name)) {        
        if ($name -like "*bad*") {
            throw "Glaargh! Bad person!"
        }
        else {
            Write-Output "Hello $Name"
        }
    }
    else {
        Write-Host "Hello unknown person"
    }
}

Get-PSConfSpeakers -Name $args[0]
"time=$(Get-Date)" | Out-File -FilePath $env:GITHUB_OUTPUT -Append