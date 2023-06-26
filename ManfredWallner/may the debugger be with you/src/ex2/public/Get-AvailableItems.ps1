
function Get-AvailableItems {
    1..1000 | % {
        Get-Random -InputObject @('❄', '❓', '☕', '⚠', '⚡')
    }
}
