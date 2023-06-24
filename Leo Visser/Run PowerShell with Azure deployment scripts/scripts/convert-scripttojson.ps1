$path = ".\deploy-runbook.ps1"
(Get-Content $path -Raw).Replace("    ","")|ConvertTo-Json -Compress