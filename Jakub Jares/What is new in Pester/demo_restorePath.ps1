Invoke-Pester -Container (New-PesterContainer -ScriptBlock { 
    Describe "d1" { 
        It "i1" { 
            New-Item -ItemType Directory "aaaaa" -Force
            cd "aaaaa"
        }
    }
})