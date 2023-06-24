Unregister-PSSessionConfiguration -Name 'VerySimpleJEA' -Force -EA SilentlyContinue
Register-PSSessionConfiguration -Path "$PSScriptRoot\VerySimpleJEA.pssc" -Name 'VerySimpleJEA' -Force