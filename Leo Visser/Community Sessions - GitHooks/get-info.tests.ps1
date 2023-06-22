Describe "Unit test" {
    BeforeAll {
        . .\get-info.ps1
    }

    It "Should return a string" {
        get-info -a "arm" -b "bicep" | Should -be "arm is better then bicep"
    }

    It "Should fail" {
        get-info -a "PowerShell" -b "Bash" | Should -be "Bash is better then PowerShell"
    }
}