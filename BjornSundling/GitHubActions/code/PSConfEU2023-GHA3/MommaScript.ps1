Param(
    [switch]$Icons
)

ipmo $PSScriptRoot\BasicFunction\

Invoke-FruitAPI -Icons:$Icons

Remove-Module BasicFunction

