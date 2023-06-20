[CmdLetBinding()]
Param(
    [Parameter(Mandatory = $true)]
    [string]$TestLocation
)

# Get all PSScript Analyzer Rules and save them in an array
$scriptAnalyzerRules = Get-ScriptAnalyzerRule
$Rules = @()
$scriptAnalyzerRules | Foreach-Object { $Rules += @{"RuleName" = $_.RuleName; "Severity" = $_.Severity } }

# Create an array of the types of rules
$Severities = @("Information", "Warning", "Error")

foreach ($Severity in $Severities) { 
    
    Describe "Testing PSSA $Severity Rules" -Tag $Severity {

        It "<RuleName>" -TestCases ($Rules | Where-Object Severity -eq $Severity) {
            
            param ($RuleName)

            #Test all scripts for the given rule and if there is a problem display this problem in a nice an reabable format in the debug message and let the test fail
            Invoke-ScriptAnalyzer -Path $TestLocation -IncludeRule $RuleName -Recurse |
            Foreach-Object {"Problem in $($_.ScriptName) at line $($_.Line) with message: $($_.Message)" } |
                Should -BeNullOrEmpty
        }
    }
}
