Describe "d1" {
    It "i1" { 
        function Get-User { @{ Name = "Jakub" } }
        Get-User | Should -Throw -ExpectedMessage "The test failed"
    }
}