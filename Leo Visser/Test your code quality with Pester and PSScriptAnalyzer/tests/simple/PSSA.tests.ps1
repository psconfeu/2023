[CmdLetBinding()]
Param(
    [Parameter(Mandatory = $true)]
    [string]$TestLocation
)

Describe "Testing PSSA Rules" {

    It "ScriptAnalyzer" {
        # Test scripts
        (Invoke-ScriptAnalyzer -Path $TestLocation -Recurse).count | Should -Be 0
    }
}