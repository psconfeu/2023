Unregister-PSSessionConfiguration -Name 'Microsoft.Sme.PowerShell' -Force -EA SilentlyContinue
Register-PSSessionConfiguration -Name 'Microsoft.Sme.PowerShell' -Path "$PSScriptRoot\WACJEA.pssc" -Force