Unregister-PSSessionConfiguration -Name 'CLJEA' -Force -EA SilentlyContinue
Register-PSSessionConfiguration -Path "$PSScriptRoot\CLJEA.pssc" -Name 'CLJEA' -Force