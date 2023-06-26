function MyArgumentCompleter {
  param (
    [string]$commandName,
    [string]$parameterName,
    [string]$wordToComplete,
    [Ast]$commandAst,
    [hashtable]$fakeBoundParameters
  )

  $possibleValues = @{
    Fruits     = @('Apple', 'Orange', 'Banana')
    Vegetables = @('Onion', 'Carrot', 'Lettuce')
  }

  if ($fakeBoundParameters.ContainsKey('Type')) {
    $possibleValues[$fakeBoundParameters.Type] | Where-Object {
      $_ -like "$wordToComplete*"
    }
  } else {
    $possibleValues.Values | ForEach-Object { $_ }
  }
}

function Test-ArgumentCompleter {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [ValidateSet('Fruits', 'Vegetables')]
    $Type,

    [Parameter(Mandatory = $true)]
    [ArgumentCompleter({ MyArgumentCompleter @args })]
    $Value
  )
}
