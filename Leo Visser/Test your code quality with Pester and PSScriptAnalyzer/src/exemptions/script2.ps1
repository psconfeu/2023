[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidTrailingWhitespace', '', Justification='Demo')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingCmdletAliases', '', Justification='Demo')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification='Demo')]

[CmdLetBinding()]
Param(
    [Parameter(Mandatory = $true)]
    [string]$FirstName,

    [Parameter(Mandatory = $true)]
    [string]$LastName
)

echo "Hello $FirstName" 