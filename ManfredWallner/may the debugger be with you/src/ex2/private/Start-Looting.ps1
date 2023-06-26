
function Start-Looting {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]
        $PlayerName,

        [Parameter(Mandatory)]
        $Items
    )

    Write-Host "$($PlayerName) - GO!"
    $threadJobArgs = @{
        Name         = "$($PlayerName)'s Quest"
        ScriptBlock  = {
            param($Me, $Items)
            #  [System.Management.Automation.Runspaces.Runspace]::DefaultRunSpace
            # Wait-Debugger
            Start-Sleep -Milliseconds (Get-Random -Minimum 10 -Maximum 20)
            $myItems = [System.Collections.ArrayList]::new()
            while ($Items.Count) {
                $i = $Items.Dequeue()
                $myItems.Add($i) | Out-Null
                Start-Sleep -Milliseconds 10
            }
            @{
                Name      = $Me
                Items     = $myItems
                ItemCount = $myItems.Count
            }
        }
        ArgumentList = @($PlayerName, $Items)
    }

    Start-ThreadJob @threadJobArgs
}
