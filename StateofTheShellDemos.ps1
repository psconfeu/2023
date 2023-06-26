
# Predictors

Set-PSReadLineOption -PredictionSource History
Set-PSReadLineOption -PredictionViewStyle ListView

### Windows Terminal 
# The Windows Terminal is a modern, fast, efficient, powerful, and productive terminal.
# Its has multiple tabs,custom themes, styles, and configurations.

# Error View

$ErrorView
Get-ChildItem -Path C:\nowhere
Get-ChildItem -Part C:\nowhere
1/0 
#Then show in PS7 
Get-Error -Newest 3
$error[0] | fl * -force

# Secret Management

Get-Command -Module Microsoft.PowerShell.SecretManagement
Get-SecretVault
Get-SecretInfo

gmo Microsoft.PowerShell.SecretStore -ListAvailable

Register-SecretVault -Name mySecretStore -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault

Get-SecretVault

Set-Secret -Name mySecret 

Get-SecretInfo

Get-Secret mySecret
Get-Secret mySecret -AsPlainText

# Error Action Preference

### Continuing when native commands error
$ErrorActionPreference = 'Continue'

ipconfig -badswitch
Write-Output "I didnt stop I am continuing on"
Get-Command doesnotexist
Write-Host "$($PSStyle.Foreground.Magenta)This is the end of the script"

### Stopping when native commands error

$ErrorActionPreference = 'Stop'

ipconfig -badswitch
Write-Output "I didnt stop I am continuing on"
Write-Host "$($PSStyle.Foreground.Magenta)This is the end of the script"

# Crescendo

ipconfig
ipconfig | Select-Object -Property Ipv4Address
Get-Ipconfig -all
Get-Ipconfig | Select-Object -Property Ipv4Address
#Win 5.1 - works downlevel
Get-Ipconfig
#Mac - works crossplat
invoke-ifconfig -Interface en0

# Get Whats new
Install-PSResource -Name Microsoft.PowerShell.WhatsNew
Get-WhatsNew # default is current version
Get-WhatsNew -Version '7.0' #just this version
Get-WhatsNew -Daily # For a MOTD
Get-WhatsNew -Version '7.2' -Daily 
Get-WhatsNew -Version '7.2' -Online

# $PSStyle

$PSStyle
"$($PSStyle.Background.Yellow)Test"
"$($PSStyle.Foreground.Red)Test"
$PSStype.Formatting.TableHeader = $PSStyle.Background.Blue
Get-Date | ft
$PSStyle.Formatting.TableHeader = $PSStyle.Blink
“{0} Hello world {1} “ -f $PSStyle.Foreground.Red,””
$PSStyle.Reset
for ($i = 1; $i -le 100; $i++ ) {
    Write-Progress -Activity "Search in Progress" -Status "$i% Complete:" -PercentComplete $i
    Start-Sleep -Milliseconds 250
}
$PSStyle.Progress.Style = $PSStyle.Background.Blue
$PSStyle.Progress.View = "Classic"
for ($i = 1; $i -le 100; $i++ ) {
    Write-Progress -Activity "Search in Progress" -Status "$i% Complete:" -PercentComplete $i
    Start-Sleep -Milliseconds 250
}

# Native Pipelining
# Will be available in the next preview 4 of PowerShell 7.5

$uri = 'https://github.com/PowerShell/PowerShell/releases/download/v7.3.4/powershell-7.3.4-linux-x64-fxdependent.tar.gz'
# Piping to native commands previously didnt work and now it does!
curl -s -L $uri | tar -xzvf - -C .

# works for Byte Array Streams
(iwr $uri).Content | tar -xzvf - -C .

# Redirection works as well
curl -s -L $uri > powershell.tar.gz

# Az CLI completers in PowerShell
## Docs: https://learn.microsoft.com/en-us/cli/azure/install-azure-cli-windows?tabs=azure-cli#enable-tab-completion-on-powershell
## Add this code to your profile to get tab completion for Az CLI in PowerShell
Register-ArgumentCompleter -Native -CommandName az -ScriptBlock {
    param($commandName, $wordToComplete, $cursorPosition)
    $completion_file = New-TemporaryFile
    $env:ARGCOMPLETE_USE_TEMPFILES = 1
    $env:_ARGCOMPLETE_STDOUT_FILENAME = $completion_file
    $env:COMP_LINE = $wordToComplete
    $env:COMP_POINT = $cursorPosition
    $env:_ARGCOMPLETE = 1
    $env:_ARGCOMPLETE_SUPPRESS_SPACE = 0
    $env:_ARGCOMPLETE_IFS = "`n"
    az 2>&1 | Out-Null
    Get-Content $completion_file | Sort-Object | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, "ParameterValue", $_)
    }
    Remove-Item $completion_file, Env:\_ARGCOMPLETE_STDOUT_FILENAME, Env:\ARGCOMPLETE_USE_TEMPFILES, Env:\COMP_LINE, Env:\COMP_POINT, Env:\_ARGCOMPLETE, Env:\_ARGCOMPLETE_SUPPRESS_SPACE, Env:\_ARGCOMPLETE_IFS
}

