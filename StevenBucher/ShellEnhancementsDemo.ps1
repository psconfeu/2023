# This is needed for some of the smart braces code 
using namespace System.Management.Automation
using namespace System.Management.Automation.Language

# Shell enhancements


#--------------------------------------------------
# Predictors
#--------------------------------------------------

# Enablding only history predictor
Set-PSReadLineOption -PredictionSource History

### History and Plugins
Set-PSReadLineOption -PredictionSource HistoryAndPlugin

### Coloring Changes
Set-PSReadLineOption -Colors @{ InLinePrediction = 'Green'} 
Set-PSReadLineOption -Colors @{ InLinePrediction = "$([char]0x1b)[36;7;238m"}  
Set-PSReadLineOption -Colors @{ InLinePrediction = 'Magenta'}

### List View of Predictors (also binded to F2)
Set-PSREadLineOption -PredictionViewStyle ListView

### Completion Predictor 
Import-Module CompletionPredictor

### Az Predictor Enablement
Import-Module Az.Tools.Predictor     # A.I trained model             
Enable-AzPredictor
Enable-AzPredictor -AllSession       # Keeping it presistent across sessions

# Creating a predictor
### See aka.ms/PSPredictorDoc



#--------------------------------------------------
# PSReadLine Shell Enhancements
#--------------------------------------------------

# Other ways to enhance your shell experience with PSReadLine
## Key Handlers
## https://learn.microsoft.com/en-us/powershell/scripting/learn/shell/using-keyhandlers?view=powershell-7.3
Get-PSReadLineKeyHandler

## PSReadLineOptions

Get-PSReadLineOptions

# you can set differnet PSReadLine options via Set-PSReadLineOption

# SampleProfile.ps1 example located in the PSReadLine module folder 
# You can find location by using
Get-Module PSReadLine -ListAvailable

# Command Validation Handler
Set-PSReadLineOption -CommandValidationHandler {
    param([CommandAst]$CommandAst)

    switch ($CommandAst.GetCommandName())
    {
        'git' {
            #Write-Host "git command found"
            
            $gitCmd = $CommandAst.CommandElements[1].Extent
            switch ($gitCmd.Text)
            {
                'cmt' {
                    [Microsoft.PowerShell.PSConsoleReadLine]::Replace(
                        $gitCmd.StartOffset, $gitCmd.EndOffset - $gitCmd.StartOffset, 'commit')
                }
            }
        }
    }
}

# This function validates and accepts after the enter key is pressed which runs the code in CommandValidationHandler
Set-PSReadLineKeyHandler -Chord Enter -Function ValidateAndAcceptLine


### Smart braces
Set-PSReadLineKeyHandler -Key '(','{','[' `
                         -BriefDescription InsertPairedBraces `
                         -LongDescription "Insert matching braces" `
                         -ScriptBlock {
    param($key, $arg)

    $closeChar = switch ($key.KeyChar)
    {
        <#case#> '(' { [char]')'; break }
        <#case#> '{' { [char]'}'; break }
        <#case#> '[' { [char]']'; break }
    }

    $selectionStart = $null
    $selectionLength = $null
    [Microsoft.PowerShell.PSConsoleReadLine]::GetSelectionState([ref]$selectionStart, [ref]$selectionLength)

    $line = $null
    $cursor = $null
    [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$line, [ref]$cursor)
    
    if ($selectionStart -ne -1)
    {
      # Text is selected, wrap it in brackets
      [Microsoft.PowerShell.PSConsoleReadLine]::Replace($selectionStart, $selectionLength, $key.KeyChar + $line.SubString($selectionStart, $selectionLength) + $closeChar)
      [Microsoft.PowerShell.PSConsoleReadLine]::SetCursorPosition($selectionStart + $selectionLength + 2)
    } else {
      # No text is selected, insert a pair
      [Microsoft.PowerShell.PSConsoleReadLine]::Insert("$($key.KeyChar)$closeChar")
      [Microsoft.PowerShell.PSConsoleReadLine]::SetCursorPosition($cursor + 1)
    }
}

Set-PSReadLineKeyHandler -Key ')',']','}' `
                         -BriefDescription SmartCloseBraces `
                         -LongDescription "Insert closing brace or skip" `
                         -ScriptBlock {
    param($key, $arg)

    $line = $null
    $cursor = $null
    [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$line, [ref]$cursor)

    if ($line[$cursor] -eq $key.KeyChar)
    {
        [Microsoft.PowerShell.PSConsoleReadLine]::SetCursorPosition($cursor + 1)
    }
    else
    {
        [Microsoft.PowerShell.PSConsoleReadLine]::Insert("$($key.KeyChar)")
    }
}

#--------------------------------------------------
# Feedback Providers
#--------------------------------------------------

## Available from 7.4-preview.2 and up
pwsh-preview -NoProfile
Enable-ExperimentalFeature -Name PSCommandNotFoundSuggestion
Enable-ExperimentalFeature -Name PSFeedbackProvider

# JSON Adapter stuff
# Download coming soon!
# JSON Adapter looks for <name>-json scripts/functions in your path and appends that to the command after its execution

# for example if I have my navtive executable "dosomething" and I have a PowerShell script that can parse the text output and convert it to JSON titled "dosomething-json"
# the JSON adapter feedback provider will suggest to run "dosomething | dosomething-json | ConvertFrom-Json" after "dosomething" is executed

# JSON adapters also utilize the tool "JC" that supports a number of native commands and converts them to JSON
# It will suggest the user try using JC to convert the output to JSON and then pipe that to ConvertFrom-Json

uname -a | jc --uname | ConvertFrom-Json

who | who --who | ConvertFrom-Json
# Supported JC commands
# "arp",
# "cksum",
# "crontab",
# "date",
# "df",
# "dig",
# "dir",
# "du",
# "file",
# "finger",
# "free",
# "hash",
# "id",i
# "ifconfig",
# "iostat",
# "jobs",
# "lsof",
# "mount",
# "mpstat",
# "netstat",
# "route",
# "stat",
# "sysctl",
# "traceroute",
# "uname",
# "uptime",
# "w",
# "wc",
# "who",
# "zipinfo"


# Command Not Found Feedback Provider
# Requires a Ubuntu system with the cmd-not-found utility installed
Install-Module -Name command-not-found
pip




