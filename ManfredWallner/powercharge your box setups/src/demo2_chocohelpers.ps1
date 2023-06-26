New-PackageFromScript MyScript.ps1 MyPackage

New-BoxstarterPackage -Name MyPackage `
                      -Description "hello psconf.eu"

Set-BoxstarterConfig -LocalRepo "c:\packages"
