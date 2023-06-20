[CmdLetBinding()]
Param(
    [Parameter(Mandatory = $true)]
    [string]$Name
)

Write-Host "Hello $Name" 