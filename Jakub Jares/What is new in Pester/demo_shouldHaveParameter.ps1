function Get-User {
    param (
        [Parameter(Mandatory)]
        [Alias("UserName")]
        [string] $Name
    ) 
}

Describe "d" {
    It "i" {
        Get-Command Get-User | Should -HaveParameter Name -Mandatory -Alias "UserName", "n"
    }
}