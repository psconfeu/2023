$invocationArgs = @{
  PackageName  = '<pkg-id / url / script-path>'
  ComputerName = 'mybox42'
  Credential   = Get-Credential
}
Install-BoxstarterPackage @invocationArgs
