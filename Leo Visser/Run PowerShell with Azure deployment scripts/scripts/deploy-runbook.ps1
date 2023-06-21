param (
    [Parameter(Mandatory = $true)]
    [string] $SubscriptionId,

    [Parameter(Mandatory = $true)]
    [string] $ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string] $AutomationAccountName
)

Get-AzContext -ListAvailable | Where-Object {$_.Subscription.id -eq $SubscriptionId} | Set-AzContext
'Write-Host \"Hello World!\"' | Out-File -FilePath '/tmp/script.ps1' -Encoding utf8
Import-AzAutomationRunbook -Path '/tmp/script.ps1' -Name 'runbook1' -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Type PowerShell -Published -Force