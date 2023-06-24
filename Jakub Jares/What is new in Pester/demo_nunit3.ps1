Import-Module Pester

$configuration = New-PesterConfiguration

$configuration.TestResult 

$configuration.TestResult.Enabled = $true
$configuration.TestResult.OutputFormat = "NUnit3"

$configuration.Run.ScriptBlock = {
    Describe "d" { 
        It "i" -ForEach @(
            @{ Name = "Jakub" }
            @{ Name = "Frode" }
        ) { 
            $name | Should -Be "bravo-kernel"
        }
    }
}


Invoke-Pester -Configuration $configuration

code .\testResults.xml