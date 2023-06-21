$r = Invoke-Pester -Output Detailed -Container (New-PesterContainer -ScriptBlock {
    Describe "d1" {
        BeforeAll {
            Start-Sleep -Seconds 1
        }

        It "i1" { }

        AfterAll {
            Start-Sleep -Seconds 1
        }
    }
}) -PassThru

"User duration: " + $r.UserDuration.TotalMilliseconds
"Framework duration: " + $r.FrameworkDuration.TotalMilliseconds