Invoke-Pester -Output None -Container (New-PesterContainer -ScriptBlock { 
    Describe "d1" { 
        It "i1" { 
            New-Item  "TestDrive:\file1.txt"

            Invoke-Pester -Output None -Container (New-PesterContainer -ScriptBlock { 
                Describe "d2" { 
                    It "i2" { 
                        New-Item  "TestDrive:\file2.txt"
                        Write-Host "Inner testdrive:" (Get-ChildItem TestDrive:\)
                    }
                }
            })

            Write-Host "Outer testdrive:" (Get-ChildItem TestDrive:\)
        }
    }
})