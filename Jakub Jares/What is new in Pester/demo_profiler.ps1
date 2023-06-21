$work = {
    Invoke-Pester -Container (New-PesterContainer -ScriptBlock {

        BeforeAll { 
            function Start-Slow {
                Start-Sleep -Seconds 2
            }
        }

        Describe "a" { 
            It "b" { 
                Start-Slow
            }
        }
    })
}

$trace = Trace-Script -ScriptBlock $work 

$trace.Top50SelfDuration | Select-Object -First 3 SelfPercent, SelfDuration, HitCount, Text

 