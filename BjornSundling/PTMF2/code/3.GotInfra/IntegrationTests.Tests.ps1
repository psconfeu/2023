param (
    [Parameter(Mandatory)]
    $FunctionUrl
)

Describe 'Integration tests' {
    it 'running funcion with parameters'{
        $Expected = 'Run with icon parameters set:🍎 🍌 🥝'
        $Actual = Invoke-RestMethod ${FunctionUrl}?icons=true
        $Actual | Should -Be $Expected
    }
    it 'running funcion without parameters'{
        $Expected = 'Run without icon parameters set:Apple Banana Kiwi'
        $Actual = Invoke-RestMethod ${FunctionUrl}
        $Actual | Should -Be $Expected
    }
}