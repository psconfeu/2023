using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

$icons = $Request.Query.icons

try {
    Import-Module $PSScriptRoot/BasicFunction

    if ($icons) {
        $Body = 'Run with icon parameters set:'
        $Body += Invoke-FruitAPI -Icons
    }
    else {
        $Body = 'Run without icon parameters set:'
        $Body += Invoke-FruitAPI
    }
}
catch {
    $Body = "Cant find module - did you copy it ok?"
}

Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = [HttpStatusCode]::OK
    Body = $body
})
