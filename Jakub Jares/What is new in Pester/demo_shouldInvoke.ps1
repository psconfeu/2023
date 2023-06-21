BeforeAll {
    $script:cache = @{}

    function Get-User ($Name) {
        # if (($script:cache).ContainsKey($Name)) { 
        #     return $script:cache[$Name]
        # }

        ($script:cache[$Name] = Get-UserInternal)
    }

    function Get-UserInternal ($Name) {
        [PSCustomObject] @{
            Name = $Name
        }
    }
}

Describe "d1" {
    It "i1" { 
        Mock Get-UserInternal -MockWith { "Jakub" }

        Get-User -Name "Jakub"
        Get-User -Name "Jakub"

        Should -Invoke Get-UserInternal -Times 1 -Exactly `
            -Because "user should be retrieved once and stored into cache"
    }
}