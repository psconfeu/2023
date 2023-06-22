Unregister-PSSessionConfiguration -Name "MetaBPA.HyperVRBAC" -Force -EA SilentlyContinue
Register-PSSessionConfiguration -Name "MetaBPA.HyperVRBAC" -Path "$PSScriptRoot\HyperVRBAC.pssc" -Force
