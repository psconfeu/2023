[CmdLetBinding()]
Param(
    [Parameter(Mandatory = $true)]
    [string]$FirstName,

    [Parameter(Mandatory = $true)]
    [string]$LastName
)

echo "Hello $FirstName" 