using namespace System.Management.Automation
using namespace System.Management.Automation.Language
using namespace System.Diagnostics.CodeAnalysis
#requires -version 5
[SuppressMessageAttribute('PSAvoidAssignmentToAutomaticVariable', '', Justification = 'PS7 Polyfill')]
[SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Profile Script')]
param()

# Stolen and modified from https://github.com/PowerShell/PSReadLine/blob/master/PSReadLine/SamplePSReadLineProfile.ps1
# F1 for help on the command line - naturally
Set-PSReadLineKeyHandler -Key F1 `
  -BriefDescription CommandHelp `
  -LongDescription 'Open the help window for the current command' `
  -ScriptBlock {
  param([ConsoleKeyInfo]$key, $arg)

  [Ast]$ast = $null
  [Token[]]$tokens = $null
  [ParseError[]]$errors = $null
  [int]$cursor = $null
  [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$ast, [ref]$tokens, [ref]$errors, [ref]$cursor)

  $commandAst = $ast.FindAll( {
      $node = $args[0]
      $node -is [CommandAst] -and
      $node.Extent.StartOffset -le $cursor -and
      $node.Extent.EndOffset -ge $cursor
    }, $true) | Select-Object -Last 1

  if ($commandAst -ne $null) {
    $commandName = $commandAst.GetCommandName()
    if ($commandName -ne $null) {
      $command = $ExecutionContext.InvokeCommand.GetCommand($commandName, 'All')
      if ($command -is [Management.Automation.AliasInfo]) {
        $commandName = $command.ResolvedCommandName
      }

      if ($commandName -ne $null) {
        #First try online
        try {
          Get-Help $commandName -Online -ErrorAction Stop
        } catch [InvalidOperationException] {
          if ($PSItem -notmatch 'The online version of this Help topic cannot be displayed') { throw }
          Get-Help $CommandName -ShowWindow
        }
      }
    }
  }
}

# # Insert text from the clipboard as a here string
Set-PSReadLineKeyHandler -Key Ctrl+Alt+V `
  -BriefDescription PasteAsHereString `
  -LongDescription 'Paste the clipboard text as a here string' `
  -ScriptBlock {
  param($key, $arg)

  Add-Type -Assembly PresentationCore
  if ([System.Windows.Clipboard]::ContainsText()) {
    # Get clipboard text - remove trailing spaces, convert \r\n to \n, and remove the final \n.
    $text = ([System.Windows.Clipboard]::GetText() -replace "\p{Zs}*`r?`n", "`n").TrimEnd()
    [Microsoft.PowerShell.PSConsoleReadLine]::Insert("@'`n$text`n'@")
  } else {
    [Microsoft.PowerShell.PSConsoleReadLine]::Ding()
  }
}

# Sometimes you want to get a property of invoke a member on what you've entered so far
# but you need parens to do that.  This binding will help by putting parens around the current selection,
# or if nothing is selected, the whole line.
Set-PSReadLineKeyHandler -Key 'Alt+(' `
  -BriefDescription ParenthesizeSelection `
  -LongDescription 'Put parenthesis around the selection or entire line and move the cursor to after the closing parenthesis' `
  -ScriptBlock {
  param($key, $arg)

  $selectionStart = $null
  $selectionLength = $null
  [Microsoft.PowerShell.PSConsoleReadLine]::GetSelectionState([ref]$selectionStart, [ref]$selectionLength)

  $line = $null
  $cursor = $null
  [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$line, [ref]$cursor)
  if ($selectionStart -ne -1) {
    [Microsoft.PowerShell.PSConsoleReadLine]::Replace($selectionStart, $selectionLength, '(' + $line.SubString($selectionStart, $selectionLength) + ')')
    [Microsoft.PowerShell.PSConsoleReadLine]::SetCursorPosition($selectionStart + $selectionLength + 2)
  } else {
    [Microsoft.PowerShell.PSConsoleReadLine]::Replace(0, $line.Length, '(' + $line + ')')
    [Microsoft.PowerShell.PSConsoleReadLine]::EndOfLine()
  }
}

# Each time you press Alt+', this key handler will change the token
# under or before the cursor.  It will cycle through single quotes, double quotes, or
# no quotes each time it is invoked.
Set-PSReadLineKeyHandler -Key "Alt+'" `
  -BriefDescription ToggleQuoteArgument `
  -LongDescription 'Toggle quotes on the argument under the cursor' `
  -ScriptBlock {
  param($key, $arg)

  $ast = $null
  $tokens = $null
  $errors = $null
  $cursor = $null
  [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$ast, [ref]$tokens, [ref]$errors, [ref]$cursor)

  $tokenToChange = $null
  foreach ($token in $tokens) {
    $extent = $token.Extent
    if ($extent.StartOffset -le $cursor -and $extent.EndOffset -ge $cursor) {
      $tokenToChange = $token

      # If the cursor is at the end (it's really 1 past the end) of the previous token,
      # we only want to change the previous token if there is no token under the cursor
      if ($extent.EndOffset -eq $cursor -and $foreach.MoveNext()) {
        $nextToken = $foreach.Current
        if ($nextToken.Extent.StartOffset -eq $cursor) {
          $tokenToChange = $nextToken
        }
      }
      break
    }
  }

  if ($tokenToChange -ne $null) {
    $extent = $tokenToChange.Extent
    $tokenText = $extent.Text
    if ($tokenText[0] -eq '"' -and $tokenText[-1] -eq '"') {
      # Switch to no quotes
      $replacement = $tokenText.Substring(1, $tokenText.Length - 2)
    } elseif ($tokenText[0] -eq "'" -and $tokenText[-1] -eq "'") {
      # Switch to double quotes
      $replacement = '"' + $tokenText.Substring(1, $tokenText.Length - 2) + '"'
    } else {
      # Add single quotes
      $replacement = "'" + $tokenText + "'"
    }

    [Microsoft.PowerShell.PSConsoleReadLine]::Replace(
      $extent.StartOffset,
      $tokenText.Length,
      $replacement)
  }
}

Set-PSReadLineKeyHandler -Description 'Edit current directory with Visual Studio Code' -Chord Ctrl+Shift+e -ScriptBlock {
  if (Get-Command code-insiders -ErrorAction SilentlyContinue) { code-insiders . } else {
    code .
  }
}
#endregion EditorStuff
