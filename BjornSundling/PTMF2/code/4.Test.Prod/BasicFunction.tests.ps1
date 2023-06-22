param(
    $ModulePath = "$PSScriptRoot\BasicFunction\BasicFunction"
)

BeforeAll {
    Remove-Module BasicFunction -ErrorAction SilentlyContinue
    Import-Module $ModulePath
}

Describe "Invoke-FruitAPI" {
    Context "Icons" {
        It "If icons is set it should output icons" {
            Invoke-FruitAPI -Icons | Should -Be @('🍎','🍌','🥝')
        }
    }
    Context "Bugfixes" {
        It "Bug #666 - Switch doesnt work ok! Testing text" {
            Invoke-FruitAPI | Should -Be @('apple','banana','kiwi')
        }
    }
}
