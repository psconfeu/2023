[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidTrailingWhitespace', '', Justification='Demo')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification='Demo')]

[CmdLetBinding()]
Param(
    [Parameter(Mandatory = $true)]
    [string]$Name
)

Write-Host "Hello $Name" 